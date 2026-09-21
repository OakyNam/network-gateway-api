"""Persisted, failure-isolated jobs with one bounded sequential worker."""

import csv
import io
import json
import logging
import re
import threading
from concurrent.futures import ThreadPoolExecutor

from app.bl.services.management import ManagementError, store_call

logger = logging.getLogger(__name__)

EXPORT_FIELDS = (
    "connection_id", "name", "protocol", "host", "port", "connector_type",
    "success", "simulated", "stage", "detail", "duration_ms",
)


def _spreadsheet_cell(value):
    text = str(value) if value is not None else ""
    if text.lstrip().startswith(("=", "+", "-", "@")) or text.startswith(("\t", "\r", "\n")):
        return "'" + text
    return text


class BatchService:
    def __init__(self, management):
        self.management = management
        self.store = management.store
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="gateway-batch")
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._future = None
        self._closed = False

    def start(self, connection_ids):
        if not connection_ids or len(connection_ids) > 1000 or len(set(connection_ids)) != len(connection_ids):
            raise ManagementError("Select unique device identifiers.", 422)
        with self._lock:
            if self._closed:
                raise ManagementError("The batch worker is shutting down.", 503)
            if self._future is not None and not self._future.done():
                raise ManagementError("A batch is already active.", 409)
            for connection_id in connection_ids:
                profile = store_call(self.store, "get", "connections", connection_id)
                self.management.check_test_provider(profile)
            job = store_call(self.store, "create_job", connection_ids)
            try:
                self._future = self._executor.submit(self._run, job["id"])
            except Exception:
                logger.error("The batch worker could not schedule a job.")
                self._fail(job["id"], "The batch could not be scheduled.")
                raise ManagementError("The batch could not be scheduled.", 503) from None
            return job

    def get(self, job_id):
        return store_call(self.store, "get_job", job_id)

    def _fail(self, job_id, message):
        try:
            self.store.set_job_status(job_id, "failed", error=message)
        except Exception:
            logger.error("Failed batch status could not be persisted; restart recovery is required.")

    def _run(self, job_id):
        try:
            store_call(self.store, "set_job_status", job_id, "running")
            profiles = store_call(self.store, "get_job_connections", job_id)
            for connection_id, profile in profiles:
                if self._stop.is_set():
                    self._fail(job_id, "Batch interrupted by application shutdown.")
                    return
                result = self.management.test_profile(profile)
                result.update({
                    "connection_id": connection_id,
                    "name": profile.get("name", ""),
                    "protocol": profile["protocol"],
                    "host": profile["host"],
                    "port": profile["port"],
                    "connector_type": (profile.get("connector") or {}).get("type", "direct"),
                })
                store_call(self.store, "record_job_result", job_id, result)
            store_call(self.store, "set_job_status", job_id, "completed")
        except Exception:
            logger.error("Unexpected batch processing failure.")
            self._fail(job_id, "Batch processing failed.")

    def export(self, job_id, format):
        if format not in {"csv", "json"}:
            raise ManagementError("Choose CSV or JSON export.", 422)
        job = self.get(job_id)
        if job["status"] not in {"completed", "failed"}:
            raise ManagementError("The batch has not finished.", 409)
        # Allow-list exports independently of the API's response-model filtering.
        public = {key: job[key] for key in ("id", "status", "total", "completed")}
        public["results"] = [
            {
                key: result.get("simulated", False) if key == "simulated" else result[key]
                for key in EXPORT_FIELDS
            }
            for result in job["results"]
        ]
        if job.get("error"):
            public["error"] = "Batch processing failed or was interrupted."
        safe_id = re.sub(r"[^a-zA-Z0-9_-]", "_", str(public["id"]))[:80] or "results"
        filename = f"connection-tests-{safe_id}.{format}"
        if format == "json":
            return json.dumps(public, ensure_ascii=False, allow_nan=False), "application/json", filename
        output = io.StringIO(newline="")
        writer = csv.DictWriter(output, fieldnames=EXPORT_FIELDS, lineterminator="\r\n")
        writer.writeheader()
        for result in public["results"]:
            writer.writerow({field: _spreadsheet_cell(result[field]) for field in EXPORT_FIELDS})
        return output.getvalue(), "text/csv", filename

    def shutdown(self):
        with self._lock:
            self._closed = True
            self._stop.set()
        self._executor.shutdown(wait=True, cancel_futures=False)
