"""SQLAlchemy 2.x models + session factory + bootstrap.

Schema:
  users(id PK, google_sub UNIQUE, email UNIQUE, name, picture_url, created_at, last_login_at)
  roles(id PK, slug UNIQUE, description, created_at)
  permissions(id PK, slug UNIQUE, description, created_at)
  user_roles(user_id, role_id) — many-to-many
  role_permissions(role_id, permission_id) — many-to-many

We seed two roles on first boot:
  - `admin` with permission `auth.admin` (manages this service)
  - `user` (no permissions; default for everyone)
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    String,
    Table,
    UniqueConstraint,
    create_engine,
    select,
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
    google_sub: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(255), default="")
    picture_url: Mapped[str] = mapped_column(String(1024), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    last_login_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    roles: Mapped[list["Role"]] = relationship(secondary=user_roles, back_populates="users", lazy="selectin")

    def permission_slugs(self) -> list[str]:
        seen: set[str] = set()
        for r in self.roles:
            for p in r.permissions:
                seen.add(p.slug)
        return sorted(seen)

    def role_slugs(self) -> list[str]:
        return sorted(r.slug for r in self.roles)


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
    _seed_defaults()


def session() -> Session:
    if _Session is None:
        raise RuntimeError("init_engine() not called")
    return _Session()


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
    them the `admin` role. Always grant the `user` role to new users.
    """
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
        user.google_sub = google_sub  # in case we matched by email
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
