"""Operator CLI for the auth service.

Run inside the auth container so it shares the SQLite volume:

    docker compose exec auth python -m app.cli set-password EMAIL --password ...

Use the `tools/rndexp auth` wrappers from the gateway repo rather than
invoking this directly.

Subcommands:
  set-password EMAIL [--password PW] [--no-admin]
      Upsert a user by email, set their password, grant `user` (always) and
      `admin` (unless --no-admin). Reads the password from --password or, if
      that's omitted, from stdin (one line).
"""
from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone

from sqlalchemy import select

from . import db, passwords


def _cmd_set_password(args: argparse.Namespace) -> int:
    email = args.email.strip().lower()
    if not email or "@" not in email:
        print(f"error: not a valid email: {args.email!r}", file=sys.stderr)
        return 2

    password = args.password
    if password is None:
        password = sys.stdin.readline().rstrip("\n")
    if not password:
        print("error: empty password", file=sys.stderr)
        return 2

    try:
        pw_hash = passwords.hash_password(password)
    except passwords.WeakPasswordError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    db.init_engine()
    with db.session() as s:
        user = s.scalar(select(db.User).where(db.User.email == email))
        created = user is None
        if created:
            user = db.User(email=email, name="", picture_url="", password_hash=pw_hash)
            s.add(user)
            s.flush()
        else:
            user.password_hash = pw_hash
        user.last_login_at = datetime.now(tz=timezone.utc)

        role_slugs = ["user"]
        if not args.no_admin:
            role_slugs.append("admin")
        db._grant_roles(s, user, role_slugs)
        s.commit()

        roles = ", ".join(user.role_slugs()) or "(none)"
        verb = "created" if created else "updated"
        print(f"{verb} {email} (id={user.id}, roles=[{roles}])")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="app.cli")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("set-password", help="Upsert a user and set their password.")
    sp.add_argument("email")
    sp.add_argument("--password", help="Password (read from stdin if omitted).")
    sp.add_argument("--no-admin", action="store_true", help="Don't grant the admin role.")
    sp.set_defaults(func=_cmd_set_password)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
