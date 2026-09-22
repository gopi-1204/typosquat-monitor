"""
db.py
PostgreSQL storage for detected typosquat candidates, via SQLAlchemy.
Every function keeps the exact same name/signature as the original
SQLite version, so no other module needs to change.
"""

import os
from datetime import datetime, timezone
from sqlalchemy import create_engine, Column, Integer, String, Float, Text
from sqlalchemy.orm import sessionmaker, declarative_base

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://typosquat_user:typosquat_pass@localhost:5432/typosquat"
)

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()


class Candidate(Base):
    __tablename__ = "candidates"

    id = Column(Integer, primary_key=True, autoincrement=True)
    domain = Column(String, nullable=False)
    decoded_domain = Column(String, nullable=True)
    matched_brand = Column(String, nullable=False)
    detected_at = Column(String, nullable=False)
    is_live = Column(Integer, nullable=True)
    visual_similarity = Column(Float, nullable=True)
    has_login_form = Column(Integer, nullable=True)
    risk_score = Column(Float, nullable=True)
    risk_level = Column(String, nullable=True)
    screenshot_path = Column(Text, nullable=True)
    status = Column(String, default="new")


def init_db():
    Base.metadata.create_all(engine)


def insert_candidate(domain, matched_brand, decoded_domain=None):
    session = SessionLocal()
    try:
        candidate = Candidate(
            domain=domain,
            decoded_domain=decoded_domain,
            matched_brand=matched_brand,
            detected_at=datetime.now(timezone.utc).isoformat(),
        )
        session.add(candidate)
        session.commit()
        session.refresh(candidate)
        return candidate.id
    finally:
        session.close()


def update_liveness(candidate_id, is_live):
    session = SessionLocal()
    try:
        candidate = session.get(Candidate, candidate_id)
        candidate.is_live = 1 if is_live else 0
        session.commit()
    finally:
        session.close()


def update_screenshot_path(candidate_id, path):
    session = SessionLocal()
    try:
        candidate = session.get(Candidate, candidate_id)
        candidate.screenshot_path = path
        session.commit()
    finally:
        session.close()


def update_visual_similarity(candidate_id, score):
    session = SessionLocal()
    try:
        candidate = session.get(Candidate, candidate_id)
        candidate.visual_similarity = float(score) if score is not None else None
        session.commit()
    finally:
        session.close()


def update_content_signals(candidate_id, has_login_form):
    session = SessionLocal()
    try:
        candidate = session.get(Candidate, candidate_id)
        candidate.has_login_form = 1 if has_login_form else 0
        session.commit()
    finally:
        session.close()


def update_risk_score(candidate_id, score, level):
    session = SessionLocal()
    try:
        candidate = session.get(Candidate, candidate_id)
        candidate.risk_score = score
        candidate.risk_level = level
        session.commit()
    finally:
        session.close()


def get_all_candidates():
    session = SessionLocal()
    try:
        candidates = (
            session.query(Candidate)
            .order_by(Candidate.risk_score.desc().nullslast(), Candidate.detected_at.desc())
            .all()
        )
        return [
            {
                "id": c.id,
                "domain": c.domain,
                "decoded_domain": c.decoded_domain,
                "matched_brand": c.matched_brand,
                "detected_at": c.detected_at,
                "is_live": c.is_live,
                "visual_similarity": c.visual_similarity,
                "has_login_form": c.has_login_form,
                "risk_score": c.risk_score,
                "risk_level": c.risk_level,
                "screenshot_path": c.screenshot_path,
                "status": c.status,
            }
            for c in candidates
        ]
    finally:
        session.close()


if __name__ == "__main__":
    init_db()
    print(f"Database initialized (PostgreSQL) at {DATABASE_URL}")
