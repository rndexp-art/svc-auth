"""SQLAlchemy 2.x models + session factory + bootstrap.

Schema:
  users(id PK, google_sub, email UNIQUE, name, picture_url, password_hash NULL,
        created_at, last_login_at)
    Partial unique index on google_sub WHERE google_sub != '' so password-only
    users (created via invite, not Google OAuth) can coexist.
  roles(id PK, slug UNIQUE, description, created_at)
  permissions(id PK, slug UNIQUE, description, created_at)
  user_roles(user_id, role_id) — many-to-many
  role_permissions(role_id, permission_id) — many-to-many
  invite_tokens(id PK, email, token_hash UNIQUE, created_by_user_id NULL,
                expires_at, redeemed_at NULL)
  password_reset_tokens(id PK, user_id FK, token_hash UNIQUE, expires_at,
                         used_at NULL)

Seeded on first boot:
  - permission `auth.admin` (the dashboard checks for this)
  - roles `admin` (with auth.admin) and `user` (no perms)
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable

from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    Index,
    String,
    Table,
    UniqueConstraint,
    create_engine,
    inspect,
    select,
    text,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    Session,
    mapped_column,
    relationship,
    sessionmaker,
)

from .config import settings


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


class Base(DeclarativeBase):
    pass


user_roles = Table(
    "user_roles",
    Base.metadata,
    Column("user_id", ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("role_id", ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True),
)

role_permissions = Table(
    "role_permissions",
    Base.metadata,
    Column("role_id", ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True),
    Column("permission_id", ForeignKey("permissions.id", ondelete="CASCADE"), primary_key=True),
)


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    # google_sub is empty for password-only users. The partial unique index
    # below only enforces uniqueness for non-empty values, which lets multiple
    # invite-only users coexist without ever colliding.
    google_sub: Mapped[str] = mapped_column(String(64), default="", index=True)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(255), default="")
    picture_url: Mapped[str] = mapped_column(String(1024), default="")
    password_hash: Mapped[str | None] = mapped_column(String(255), nullable=True, default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    last_login_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    roles: Mapped[list["Role"]] = relationship(secondary=user_roles, back_populates="users", lazy="selectin")

    __table_args__ = (
        Index(
            "ix_users_google_sub_nonempty",
            "google_sub",
            unique=True,
            sqlite_where=text("google_sub != ''"),
        ),
    )

    def permission_slugs(self) -> list[str]:
        seen: set[str] = set()
        for r in self.roles:
            for p in r.permissions:
                seen.add(p.slug)
        return sorted(seen)

    def role_slugs(self) -> list[str]:
        return sorted(r.slug for r in self.roles)

    def has_password(self) -> bool:
        return bool(self.password_hash)

    def has_google(self) -> bool:
        return bool(self.google_sub)


class Role(Base):
    __tablename__ = "roles"
    id: Mapped[int] = mapped_column(primary_key=True)
    slug: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    description: Mapped[str] = mapped_column(String(512), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    users: Mapped[list[User]] = relationship(secondary=user_roles, back_populates="roles", lazy="selectin")
    permissions: Mapped[list["Permission"]] = relationship(
        secondary=role_permissions, back_populates="roles", lazy="selectin"
    )


class Permission(Base):
    __tablename__ = "permissions"
    id: Mapped[int] = mapped_column(primary_key=True)
    slug: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    description: Mapped[str] = mapped_column(String(512), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    roles: Mapped[list[Role]] = relationship(
        secondary=role_permissions, back_populates="permissions", lazy="selectin"
    )

    __table_args__ = (UniqueConstraint("slug"),)


class InviteToken(Base):
    """One-time email invite. The plaintext token only ever lives in the
    emailed URL — we store its sha256 hash so a DB compromise can't be used
    to claim other people's invites.
    """
    __tablename__ = "invite_tokens"
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(320), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    created_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    redeemed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, default=None)
    # If the inviter wanted the new user to land with specific roles, we
    # encode them as a comma-separated slug list. Empty = no extra roles
    # beyond the default `user` role.
    granted_role_slugs: Mapped[str] = mapped_column(String(512), default="")


class PasswordResetToken(Base):
    """One-time password reset token tied to a user. Same hash-before-store
    discipline as invite tokens.
    """
    __tablename__ = "password_reset_tokens"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, default=None)


# --- engine + session factory ----------------------------------------------

_engine = None
_Session: sessionmaker[Session] | None = None


def init_engine(db_path: str | None = None) -> None:
    """Create the SQLite engine + sessionmaker. Idempotent.

    Called from main.py on startup; tests can call with an in-memory URL.
    """
    global _engine, _Session
    if _engine is not None:
        return
    cfg_path = db_path or settings().db_path
    if cfg_path == ":memory:":
        url = "sqlite+pysqlite:///:memory:"
    else:
        Path(cfg_path).parent.mkdir(parents=True, exist_ok=True)
        url = f"sqlite+pysqlite:///{cfg_path}"
    _engine = create_engine(url, echo=False, future=True, connect_args={"check_same_thread": False})
    _Session = sessionmaker(bind=_engine, expire_on_commit=False, future=True)
    Base.metadata.create_all(_engine)
    _migrate_v1_to_v2()
    _seed_defaults()


def session() -> Session:
    if _Session is None:
        raise RuntimeError("init_engine() not called")
    return _Session()


# --- migration --------------------------------------------------------------

def _migrate_v1_to_v2() -> None:
    """v1 schema (Phase 1):
        users(google_sub UNIQUE NOT NULL, email UNIQUE, ...)
       v2 schema (Phase 2):
        users(google_sub default '' + partial unique index, email UNIQUE,
              password_hash NULL, ...)
        + invite_tokens, password_reset_tokens

    `Base.metadata.create_all` already created the new tables and the partial
    index. What it can't do is alter the existing `users` table to add
    `password_hash` or drop the column-level UNIQUE on google_sub. SQLite has
    no `ALTER COLUMN`, so the only safe path for the UNIQUE drop is a
    table-rebuild. We only do that on the first run that finds the v1 shape.
    """
    assert _engine is not None
    insp = inspect(_engine)
    if "users" not in insp.get_table_names():
        return  # fresh DB; create_all already wrote the v2 shape
    cols = {c["name"] for c in insp.get_columns("users")}
    if "password_hash" in cols:
        return  # already v2

    # Detect whether the legacy column-level UNIQUE on google_sub exists. If
    # so, table-rebuild; otherwise just ALTER TABLE ADD COLUMN.
    legacy_unique = any(
        ix.get("unique") and "google_sub" in ix.get("column_names", []) and ix["name"] != "ix_users_google_sub_nonempty"
        for ix in insp.get_indexes("users")
    )

    with _engine.begin() as conn:
        if legacy_unique:
            # Rebuild users with the v2 shape, copy rows, swap.
            conn.execute(text("""
                CREATE TABLE users_v2 (
                    id INTEGER PRIMARY KEY,
                    google_sub VARCHAR(64) NOT NULL DEFAULT '',
                    email VARCHAR(320) NOT NULL,
                    name VARCHAR(255) NOT NULL DEFAULT '',
                    picture_url VARCHAR(1024) NOT NULL DEFAULT '',
                    password_hash VARCHAR(255),
                    created_at DATETIME NOT NULL,
                    last_login_at DATETIME NOT NULL,
                    UNIQUE(email)
                )
            """))
            conn.execute(text("""
                INSERT INTO users_v2 (id, google_sub, email, name, picture_url, password_hash, created_at, last_login_at)
                SELECT id, google_sub, email, name, picture_url, NULL, created_at, last_login_at FROM users
            """))
            conn.execute(text("DROP TABLE users"))
            conn.execute(text("ALTER TABLE users_v2 RENAME TO users"))
            conn.execute(text("CREATE INDEX ix_users_google_sub ON users(google_sub)"))
            conn.execute(text("CREATE INDEX ix_users_email ON users(email)"))
            conn.execute(text(
                "CREATE UNIQUE INDEX ix_users_google_sub_nonempty ON users(google_sub) WHERE google_sub != ''"
            ))
        else:
            # No legacy UNIQUE — just need the new column.
            conn.execute(text("ALTER TABLE users ADD COLUMN password_hash VARCHAR(255)"))


# --- seed data --------------------------------------------------------------

DEFAULT_PERMISSIONS: list[tuple[str, str]] = [
    ("auth.admin", "Manage users, roles, and permissions in the auth service."),
]

DEFAULT_ROLES: list[tuple[str, str, list[str]]] = [
    ("admin", "Full administrative access to the auth service.", ["auth.admin"]),
    ("user", "Default role for any authenticated user.", []),
]


def _seed_defaults() -> None:
    with session() as s:
        existing_perm_slugs = {p.slug for p in s.scalars(select(Permission)).all()}
        for slug, desc in DEFAULT_PERMISSIONS:
            if slug not in existing_perm_slugs:
                s.add(Permission(slug=slug, description=desc))
        s.flush()

        perms_by_slug = {p.slug: p for p in s.scalars(select(Permission)).all()}
        existing_role_slugs = {r.slug for r in s.scalars(select(Role)).all()}
        for slug, desc, perm_slugs in DEFAULT_ROLES:
            if slug in existing_role_slugs:
                continue
            r = Role(slug=slug, description=desc)
            r.permissions = [perms_by_slug[ps] for ps in perm_slugs if ps in perms_by_slug]
            s.add(r)
        s.commit()


# --- helpers ----------------------------------------------------------------

def upsert_google_user(
    s: Session,
    *,
    google_sub: str,
    email: str,
    name: str,
    picture_url: str,
    bootstrap_admin_email: str | None = None,
) -> User:
    """Insert or update a user identified by their Google `sub` claim.

    On first-ever insert, if the email matches `bootstrap_admin_email`, grant
    them the `admin` role. Always grant the `user` role to new users. If the
    user was previously created via invite (password-only) and now signs in
    with Google for the first time, link the Google account by stamping the
    google_sub onto the existing row.
    """
    user: User | None = None
    if google_sub:
        user = s.scalar(select(User).where(User.google_sub == google_sub))
    if user is None:
        user = s.scalar(select(User).where(User.email == email))
    is_new = user is None
    if is_new:
        user = User(google_sub=google_sub, email=email, name=name, picture_url=picture_url)
        s.add(user)
        s.flush()
    else:
        user.email = email
        user.name = name or user.name
        user.picture_url = picture_url or user.picture_url
        user.google_sub = google_sub  # link or refresh
    user.last_login_at = _utcnow()

    if is_new:
        roles_to_grant: list[str] = ["user"]
        if bootstrap_admin_email and email.lower() == bootstrap_admin_email.lower():
            roles_to_grant.append("admin")
        _grant_roles(s, user, roles_to_grant)
    s.commit()
    return user


def _grant_roles(s: Session, user: User, role_slugs: Iterable[str]) -> None:
    role_slugs = list(role_slugs)
    if not role_slugs:
        return
    rs = s.scalars(select(Role).where(Role.slug.in_(role_slugs))).all()
    have = {r.slug for r in user.roles}
    for r in rs:
        if r.slug not in have:
            user.roles.append(r)


# --- last-admin guard -------------------------------------------------------

ADMIN_ROLE_SLUG = "admin"


def admin_user_count(s: Session) -> int:
    """Number of users currently holding the `admin` role."""
    role = s.scalar(select(Role).where(Role.slug == ADMIN_ROLE_SLUG))
    if role is None:
        return 0
    return len(role.users)


def is_last_admin(s: Session, user: User) -> bool:
    """True iff `user` is the only one with the `admin` role.

    Used to gate destructive admin actions (delete user, revoke admin role)
    so we never end up with zero admins.
    """
    if ADMIN_ROLE_SLUG not in user.role_slugs():
        return False
    return admin_user_count(s) <= 1


# --- token TTLs (overrideable via Settings later) ---------------------------

INVITE_TOKEN_TTL = timedelta(days=7)
PASSWORD_RESET_TTL = timedelta(minutes=30)
