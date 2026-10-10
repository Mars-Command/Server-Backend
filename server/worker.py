"""Run with python -m server.worker. No test scanner can be selected through config."""

import argparse
import json
import logging
import signal
import threading

from .community import Settings, Store
from .ingestion import CapsuleWorkflow


class DiagnosticFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        event = {"level": record.levelname, "logger": record.name, "event": record.getMessage()}
        for key in ("job_id", "attempts", "state", "target"):
            if hasattr(record, key):
                event[key] = getattr(record, key)
        return json.dumps(event)


def main() -> int:
    parser = argparse.ArgumentParser(description="Private capsule scanner worker")
    parser.add_argument("--once", action="store_true", help="Clean up and process at most one job")
    parser.add_argument("--poll-seconds", type=int, default=5)
    parser.add_argument("--worker-id", default="capsule-worker")
    args = parser.parse_args()
    if args.poll_seconds <= 0 or not 1 <= len(args.worker_id) <= 120:
        parser.error("Worker ID and poll interval must be bounded and positive")
    handler = logging.StreamHandler()
    handler.setFormatter(DiagnosticFormatter())
    logging.basicConfig(level=logging.INFO, handlers=[handler])
    settings = Settings.from_env()
    if not settings.enabled or settings.capsules is None:
        parser.error("Community authentication/storage must be configured")
    workflow = CapsuleWorkflow(Store(settings.database), settings.capsules)
    stopped = threading.Event()
    for event in (signal.SIGINT, signal.SIGTERM):
        signal.signal(event, lambda *_: stopped.set())
    while not stopped.is_set():
        try:
            workflow.cleanup()
            processed = workflow.process_one(args.worker_id)
        except Exception:
            # A crashed/failed storage attempt remains leased for fenced recovery.
            logging.getLogger("mars-capsules").error("capsule_worker_operation_failed")
            if args.once:
                return 1
            processed = False
        if args.once:
            return 0
        if not processed:
            stopped.wait(args.poll_seconds)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
