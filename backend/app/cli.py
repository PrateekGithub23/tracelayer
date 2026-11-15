"""
Command-line interface:  tracelayer <command>

  migrate                 apply database migrations
  seed [--events N]       generate + ingest the synthetic scenario and run the pipeline
  verify                  verify the evidence ledger and audit chain
  evaluate [--json PATH]  run the adversarial integrity evaluation
  bench [--events N]      run benchmarks on an isolated database
  create-user --email E --role R [--password-stdin]
                          create an account (prompts for the password; never pass it as an argument)
  reset-password --email E [--password-stdin]
                          break-glass recovery on the host: set a new password, revoke all sessions
  chain-head              print the ledger + audit chain heads (anchor them somewhere external)
"""

import argparse
import getpass
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
    cu = sub.add_parser("create-user")
    cu.add_argument("--email", required=True)
    cu.add_argument("--role", required=True, choices=["admin", "analyst", "viewer"])
    cu.add_argument("--name")
    cu.add_argument("--password-stdin", action="store_true")
    rp = sub.add_parser("reset-password")
    rp.add_argument("--email", required=True)
    rp.add_argument("--password-stdin", action="store_true")
    sub.add_parser("chain-head")
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
    elif args.cmd in ("create-user", "reset-password"):
        return _account_command(args)
    elif args.cmd == "chain-head":
        from sqlalchemy import select

        from app.db import init_engine, session_scope
        from app.models import AuditEntry, IngestBatch

        init_engine(settings.database_url)
        with session_scope() as db:
            b = db.execute(
                select(IngestBatch.seq, IngestBatch.chain_hash).order_by(IngestBatch.seq.desc()).limit(1)
            ).first()
            a = db.execute(select(AuditEntry.id, AuditEntry.entry_hash).order_by(AuditEntry.id.desc()).limit(1)).first()
        print(json.dumps({"ledger": {"seq": b[0], "chain_hash": b[1]} if b else None,
                          "audit": {"id": a[0], "entry_hash": a[1]} if a else None}, indent=2))  # fmt: skip
    return 0


def _read_password(from_stdin: bool) -> str:
    if from_stdin:
        return sys.stdin.readline().rstrip("\n")
    pw = getpass.getpass("New password: ")
    if pw != getpass.getpass("Repeat password: "):
        raise SystemExit("passwords do not match")
    return pw


def _account_command(args: argparse.Namespace) -> int:
    from sqlalchemy import select

    from app import audit
    from app.auth.passwords import hash_password, policy_errors
    from app.auth.sessions import revoke_all
    from app.auth.users import AccountError, create_user, normalize_email
    from app.db import init_engine, session_scope
    from app.migrate import upgrade
    from app.models import User, utcnow

    settings = get_settings()
    upgrade(settings.database_url)
    init_engine(settings.database_url)
    password = _read_password(args.password_stdin)
    with session_scope() as db:
        if args.cmd == "create-user":
            try:
                u = create_user(db, email=args.email, password=password, role=args.role, display_name=args.name)
            except AccountError as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 2
            audit.record(db, actor="cli", action="user.created", target_type="user", target_id=u.id,
                         details={"email": u.email, "role": u.role})  # fmt: skip
            print(f"created {u.role} {u.email} ({u.id})")
        else:
            user = db.scalar(select(User).where(User.email == normalize_email(args.email)))
            if not user:
                print("error: no such user", file=sys.stderr)
                return 2
            if errs := policy_errors(password, user.email):
                print("error: password " + "; ".join(errs), file=sys.stderr)
                return 2
            user.password_hash, user.password_changed_at, user.status = hash_password(password), utcnow(), "active"
            n = revoke_all(db, user.id, "cli_password_reset")
            audit.record(db, actor="cli", action="auth.password_reset_cli", target_type="user", target_id=user.id,
                         details={"sessions_revoked": n})  # fmt: skip
            print(f"password reset for {user.email}; {n} sessions revoked")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
