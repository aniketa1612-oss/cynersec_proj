from __future__ import annotations

import os

from celery import Celery

celery_app = Celery(
    "adaptive_pentest",
    broker=os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/0"),
    backend=os.getenv("CELERY_RESULT_BACKEND", "redis://localhost:6379/1"),
)
celery_app.conf.update(
    task_track_started=True,
    task_time_limit=900,
    task_soft_time_limit=840,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
)


@celery_app.task(name="scans.run", bind=True, max_retries=1)
def run_scan_task(self, scan_id: int, mode: str) -> None:
    """Execute only a previously authorized and persisted assessment."""
    from app.main import run_live, run_mock

    try:
        (run_live if mode == "live" else run_mock)(scan_id)
    except Exception as exc:
        raise self.retry(exc=exc, countdown=5) from exc
