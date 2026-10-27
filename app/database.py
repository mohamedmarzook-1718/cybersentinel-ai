"""SQLAlchemy database setup and session management."""
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.core.config import get_settings

settings = get_settings()

engine = create_engine(
    settings.database_url,
    connect_args={"check_same_thread": False},  # SQLite only
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Create all tables and perform safe schema migrations for SQLite."""
    # Import models so they register with Base
    from app.models import user, event, alert, audit, scan  # noqa: F401
    Base.metadata.create_all(bind=engine)

    # Safe migration for web_scans table in existing SQLite databases
    with engine.connect() as conn:
        try:
            from sqlalchemy import text
            res = conn.execute(text("PRAGMA table_info(web_scans)"))
            existing_cols = {row[1] for row in res.fetchall()}
            if existing_cols:
                new_cols = {
                    "profile": "VARCHAR(32) DEFAULT 'standard'",
                    "scope_config_json": "TEXT DEFAULT '{}'",
                    "attack_surface_json": "TEXT DEFAULT '{}'",
                    "remediation_json": "TEXT DEFAULT '[]'",
                    "limitations_json": "TEXT DEFAULT '[]'",
                    "pages_crawled": "INTEGER DEFAULT 1",
                    "pages_discovered": "INTEGER DEFAULT 1",
                }
                for col_name, col_type in new_cols.items():
                    if col_name not in existing_cols:
                        conn.execute(text(f"ALTER TABLE web_scans ADD COLUMN {col_name} {col_type}"))
                conn.commit()
        except Exception:
            pass
