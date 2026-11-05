"""Command-line front end: ``python -m dfirt <command>``.

Commands:
  manifest  <case>                 build an evidence manifest (SHA-256 + custody)
  verify    <case> [--manifest f]  verify a case against its manifest
  triage    <case> --out report.md run every detector, write a triage report
  proctree  <case/HOST>            print the process tree for one host
  timeline  <case> [--csv f] [--md f] [--key-events]
  execution <case> <target> [--host H]  execution-evidence assessment for a binary
  sigma     <case>                 evaluate the bundled Sigma rules over the case
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from . import execution as execmod
from . import integrity, report, sigma, timeline, triage
from .ingest import load_case
from .model import iso


def _load(case_arg: str):
    return load_case(case_arg)


def cmd_manifest(args) -> int:
    out = integrity.write_manifest(args.case, args.out)
    manifest = integrity.Manifest.from_json(Path(out).read_text(encoding="utf-8"))
    print(f"Manifest written: {out}")
    print(f"  {len(manifest.files)} files hashed (SHA-256)")
    for f in manifest.files[:10]:
        print(f"  {f.sha256[:16]}...  {f.path}")
    if len(manifest.files) > 10:
        print(f"  ... {len(manifest.files) - 10} more")
    return 0


def cmd_verify(args) -> int:
    mpath = args.manifest or str(Path(args.case) / integrity.MANIFEST_NAME)
    if not Path(mpath).exists():
        print(f"error: manifest not found: {mpath}", file=sys.stderr)
        return 2
    result = integrity.verify(args.case, mpath)
    print(result.summary)
    for p in result.modified:
        print(f"  MODIFIED {p}")
    for p in result.missing:
        print(f"  MISSING  {p}")
    for p in result.added:
        print(f"  ADDED    {p}")
    return 0 if result.ok else 1


def cmd_triage(args) -> int:
    case = _load(args.case)
    result = triage.run(case)
    manifest = None
    mpath = Path(args.manifest) if args.manifest else None
    if mpath is not None:
        manifest = integrity.Manifest.from_json(mpath.read_text(encoding="utf-8"))
        check = integrity.verify(args.case, manifest)
        if not check.ok:
            print(f"error: {check.summary}; refusing to report on unverified evidence",
                  file=sys.stderr)
            return 1
    md = report.build_report(result, manifest=manifest)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(md, encoding="utf-8")
        print(f"Triage report written: {args.out} ({md.count(chr(10))} lines)")
    else:
        print(md)
    if args.json:
        payload = {
            "patient_zero": result.patient_zero,
            "findings": [f.to_dict() for f in result.findings],
            "edges": [{"src": e.src, "dst": e.dst, "method": e.method, "account": e.account,
                       "technique": e.technique, "allowlisted": e.allowlisted}
                      for e in result.edges],
            "execution_matrix": result.exec_matrix,
            "iocs": result.iocs,
        }
        Path(args.json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        print(f"Findings JSON written: {args.json}")
    attack = [e for e in result.edges if not e.allowlisted]
    print(f"  {len(result.findings)} findings | patient zero {result.patient_zero} | "
          f"movement: " + ", ".join(f"{e.src} -> {e.dst} ({e.method})" for e in attack))
    if args.score:
        from . import scoring
        gt = scoring.load_ground_truth(args.score)
        sc = scoring.score(result.findings, gt, result.edges)
        table = scoring.to_markdown(sc, gt)
        print(f"  score vs {args.score}: precision {sc.precision:.2f}, recall {sc.recall:.2f}, "
              f"benign cited {len(sc.benign_cited)}/{len(gt.get('benign', []))}, "
              f"edges exact: {'yes' if sc.edges_exact else 'no'}")
        if args.score_out:
            Path(args.score_out).write_text("# Triage score vs ground truth\n\n" + table,
                                            encoding="utf-8")
            print(f"Score table written: {args.score_out}")
    return 0


def cmd_proctree(args) -> int:
    from . import proctree
    target = Path(args.target)
    if args.host:
        case, host = load_case(target), args.host
    else:
        case, host = load_case(target.parent), target.name
    if host not in case.hosts:
        print(f"error: host {host!r} not in case (have {', '.join(case.hosts)})",
              file=sys.stderr)
        return 2
    lsass = [e for e in case.events if e.action == "process_access"]
    tree = proctree.build_tree(case.processes, host)
    flags = proctree.anomaly_flags(case.processes, host, lsass)
    print(f"Process tree for {host} ({len(tree.by_guid)} processes, Sysmon EventID 1):")
    print(tree.render(flags=flags, width=args.width))
    findings = proctree.detect(case.processes, host, lsass)
    if findings:
        print("\nAnomalous lineage:")
        for f in findings:
            print(f"  [{f.severity}] {f.technique} {f.title}")
    return 0


def cmd_timeline(args) -> int:
    case = _load(args.case)
    rows = timeline.build(case)
    if args.key_events:
        rows = timeline.key_events(rows, findings=triage.run(case).findings)
    if args.csv:
        Path(args.csv).parent.mkdir(parents=True, exist_ok=True)
        Path(args.csv).write_text(timeline.to_csv(rows), encoding="utf-8")
        print(f"Timeline CSV written: {args.csv} ({len(rows)} rows)")
    if args.md:
        Path(args.md).parent.mkdir(parents=True, exist_ok=True)
        title = "Key events (rows cited by triage findings)" if args.key_events else "Super-timeline"
        Path(args.md).write_text(timeline.to_markdown(rows, title), encoding="utf-8")
        print(f"Timeline Markdown written: {args.md}")
    if not args.csv and not args.md:
        print(timeline.to_markdown(rows, "Key events" if args.key_events else "Super-timeline"))
    return 0


def cmd_execution(args) -> int:
    case = _load(args.case)
    hosts = [args.host] if args.host else case.hosts
    shown = 0
    for host in hosts:
        for a in execmod.assess_all(args.target, host, case.exec_artifacts,
                                    case.processes, case.events):
            if a.confidence == "none" and args.host is None:
                continue
            shown += 1
            print(f"[{host}] {a.path}")
            print(f"  verdict : {a.confidence.upper()} (proves execution: {a.proves_execution})")
            print(f"  sources : {', '.join(a.sources) or 'none'}")
            if a.run_count is not None:
                print(f"  prefetch: run count {a.run_count}; last runs "
                      + ", ".join(iso(t) for t in a.run_times))
            for art in a.artifacts:
                print(f"    - {art.kind:9s} {art.source}:{art.row}")
            print(f"  why     : {a.rationale}")
    if not shown:
        print(f"No execution or presence artifact for {args.target}")
    return 0


def cmd_sigma(args) -> int:
    case = _load(args.case)
    rules = sigma.load_rules()
    hits = sigma.evaluate(rules, case.events)
    from collections import Counter
    counts = Counter(h["rule"] for h in hits)
    print(f"Evaluated {len(rules)} Sigma rules over {len(case.events)} events "
          f"-> {len(hits)} hits")
    for rule in rules:
        c = counts.get(rule["title"], 0)
        flag = "  " if c else "--"
        print(f"  {flag} {c:2d}  {rule.get('level','?'):8s} {rule['title']}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="dfirt",
        description="Windows endpoint forensic triage for Tier 2 SOC escalations.")
    p.add_argument("--version", action="version", version=f"dfirt {__version__}")
    sub = p.add_subparsers(dest="command", metavar="<command>")
    sub.required = True

    m = sub.add_parser("manifest", help="build an evidence manifest")
    m.add_argument("case")
    m.add_argument("--out", help="output path (default <case>/MANIFEST.json)")
    m.set_defaults(func=cmd_manifest)

    v = sub.add_parser("verify", help="verify a case against a manifest")
    v.add_argument("case")
    v.add_argument("--manifest", help="manifest path (default <case>/MANIFEST.json)")
    v.set_defaults(func=cmd_verify)

    t = sub.add_parser("triage", help="run every detector and write a report")
    t.add_argument("case")
    t.add_argument("--out", help="Markdown report output path")
    t.add_argument("--json", help="also write findings as JSON")
    t.add_argument("--manifest", help="verify evidence against this manifest first")
    t.add_argument("--score", metavar="GROUND_TRUTH",
                   help="score findings against a ground-truth JSON (tests/ground_truth.json)")
    t.add_argument("--score-out", help="write the score table as Markdown")
    t.set_defaults(func=cmd_triage)

    pt = sub.add_parser("proctree", help="print the process tree for one host")
    pt.add_argument("target", help="case/HOST directory (or case dir with --host)")
    pt.add_argument("--host", help="host name when target is the case dir")
    pt.add_argument("--width", type=int, default=110, help="truncate node labels (default 110)")
    pt.set_defaults(func=cmd_proctree)

    tl = sub.add_parser("timeline", help="build the super-timeline")
    tl.add_argument("case")
    tl.add_argument("--csv", help="write CSV")
    tl.add_argument("--md", help="write Markdown")
    tl.add_argument("--key-events", action="store_true",
                    help="filter to key events only")
    tl.set_defaults(func=cmd_timeline)

    ex = sub.add_parser("execution", help="execution-evidence assessment for a binary")
    ex.add_argument("case")
    ex.add_argument("target", help="binary name or full path")
    ex.add_argument("--host", help="limit to one host")
    ex.set_defaults(func=cmd_execution)

    sg = sub.add_parser("sigma", help="evaluate bundled Sigma rules over the case")
    sg.add_argument("case")
    sg.set_defaults(func=cmd_sigma)

    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args) or 0)
    except FileNotFoundError as exc:
        name = getattr(exc, "filename", None) or str(exc)
        print(f"error: file not found: {name}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except BrokenPipeError:          # e.g. `python -m dfirt timeline case | head`
        sys.stderr.close()
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
