"""
Command-line interface:  tracelayer <command>

  migrate                 apply database migrations
  seed [--events N]       generate + ingest the synthetic scenario and run the pipeline
  verify                  verify the evidence ledger and audit chain
  evaluate [--json PATH]  run the adversarial integrity evaluation
  bench [--events N]      run benchmarks on an isolated database
"""

import argparse
import json
import sys

from app.config import get_settings


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="tracelayer")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("migrate")
    seed = sub.add_parser("seed")
    seed.add_argument("--events", type=int, default=3000)
    seed.add_argument("--seed", type=int, default=7)
    sub.add_parser("verify")
    ev = sub.add_parser("evaluate")
    ev.add_argument("--json")
    bench = sub.add_parser("bench")
    bench.add_argument("--events", type=int, default=20_000)
    bench.add_argument("--json")
    args = ap.parse_args(argv)

    settings = get_settings()
    if args.cmd == "migrate":
        from app.migrate import upgrade

        upgrade(settings.database_url)
        print("migrations applied")
    elif args.cmd == "seed":
        from app import jobs
        from app.db import init_engine, session_scope
        from app.ingestion.pipeline import ingest_records
        from app.migrate import upgrade
        from app.synthetic.generator import generate

        upgrade(settings.database_url)
        init_engine(settings.database_url)
        sc = generate(seed=args.seed, background_events=args.events)
        with session_scope() as db:
            for recs, parser in ((sc.native, "native"), (sc.sshd, "sshd"), (sc.winsec, "winsec")):
                r = ingest_records(db, recs, source=f"synthetic-{parser}", parser_name=parser, options={"year": 2026})
                print(f"{parser:7} accepted={r.accepted} duplicates={r.duplicates} rejected={r.rejected}")
        with session_scope() as db:
            stats = jobs.detect_and_correlate(db, "cli")
        print(f"detections={stats['detection']['created']} investigations="
              f"{stats['correlation']['investigations_created']} in {stats['total_ms']:.0f} ms")  # fmt: skip
    elif args.cmd == "verify":
        from app.audit import verify_audit_chain
        from app.db import init_engine, session_scope
        from app.integrity.ledger import verify_ledger

        init_engine(settings.database_url)
        with session_scope() as db:
            ledger, chain = verify_ledger(db), verify_audit_chain(db)
        print(json.dumps({"ledger": ledger, "audit_chain": chain}, indent=2, default=str))
        return 0 if ledger["ok"] and chain["ok"] else 1
    elif args.cmd == "evaluate":
        from app.evaluation import suite

        sys.argv = ["suite"] + (["--json", args.json] if args.json else [])
        suite.main()
    elif args.cmd == "bench":
        from app.benchmarks import runner

        sys.argv = ["runner", "--events", str(args.events)] + (["--json", args.json] if args.json else [])
        runner.main()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
