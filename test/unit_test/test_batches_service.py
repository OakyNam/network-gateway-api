import asyncio
import copy
import csv
import io
import json
import threading
import unittest
from unittest.mock import Mock

from fastapi import FastAPI

from app.api.routes.management import shutdown_management
from app.bl.services.batches import BatchService
from app.bl.services.management import ManagementError, ManagementService
from test.unit_test.test_management_api import DEVICE, OK, FakeStore


class BatchServiceTests(unittest.TestCase):
    def setUp(self):
        self.store = FakeStore()
        self.store.save("connections", DEVICE)
        self.store.save("connections", {**DEVICE, "name": "second", "password": "SECRET"})

    def worker(self, tester):
        worker = BatchService(ManagementService(self.store, tester=tester))
        self.addCleanup(worker.shutdown)
        return worker

    def test_failures_isolated_and_progress_persisted(self):
        tester = Mock(side_effect=[RuntimeError("SECRET"), OK])
        worker = self.worker(tester)
        job = worker.start(["1", "2"])
        worker._future.result(timeout=3)
        finished = worker.get(job["id"])
        self.assertEqual(finished["status"], "completed")
        self.assertEqual(finished["completed"], 2)
        self.assertFalse(finished["results"][0]["success"])
        self.assertTrue(finished["results"][1]["success"])
        self.assertNotIn("SECRET", str(finished))

    def test_bounded_concurrency_snapshot_and_unfinished_export(self):
        started, release = threading.Event(), threading.Event()
        seen = []

        def tester(profile, **kwargs):
            seen.append(copy.deepcopy(profile))
            started.set()
            self.assertTrue(release.wait(3))
            return OK

        worker = self.worker(tester)
        self.addCleanup(release.set)
        job = worker.start(["1", "2"])
        self.assertTrue(started.wait(3))
        self.store.rows["connections"]["2"]["password"] = "CHANGED"
        with self.assertRaises(ManagementError) as raised:
            worker.start(["1"])
        self.assertEqual(raised.exception.status_code, 409)
        with self.assertRaises(ManagementError) as raised:
            worker.export(job["id"], "json")
        self.assertEqual(raised.exception.status_code, 409)
        self.assertEqual(len(seen), 1)
        release.set()
        worker._future.result(timeout=3)
        self.assertEqual(seen[1]["password"], "SECRET")

    def test_persistence_failure_marks_failed(self):
        worker = self.worker(Mock(return_value=OK))
        self.store.record_job_result = Mock(side_effect=RuntimeError("SECRET"))
        with self.assertLogs("app.bl.services.batches", level="ERROR") as logs:
            job = worker.start(["1", "2"])
            worker._future.result(timeout=3)
        self.assertIn("Unexpected batch processing failure.", logs.output[0])
        self.assertNotIn("SECRET", str(logs.output))
        finished = worker.get(job["id"])
        self.assertEqual(finished["status"], "failed")
        self.assertNotIn("SECRET", str(finished))
        self.assertEqual(finished["completed"], 0)

    def test_executor_submission_failure_persisted(self):
        worker = self.worker(Mock(return_value=OK))
        worker._executor.submit = Mock(side_effect=RuntimeError("SECRET"))
        with self.assertLogs("app.bl.services.batches", level="ERROR") as logs:
            with self.assertRaises(ManagementError) as raised:
                worker.start(["1"])
        self.assertNotIn("SECRET", str(logs.output))
        self.assertEqual(raised.exception.status_code, 503)
        self.assertEqual(self.store.jobs["1"]["status"], "failed")
        self.assertNotIn("SECRET", self.store.jobs["1"]["error"])

    def test_failed_status_storage_error_is_logged_without_exception_or_profile(self):
        worker = self.worker(Mock(return_value=OK))
        self.store.set_job_status = Mock(side_effect=RuntimeError("password=SECRET"))
        with self.assertLogs("app.bl.services.batches", level="ERROR") as logs:
            worker._fail("SECRET-JOB-ID", "SECRET-PROFILE")
        self.assertEqual(len(logs.records), 1)
        self.assertIn("Failed batch status could not be persisted", logs.output[0])
        self.assertNotIn("SECRET", str(logs.output))
        self.assertIsNone(logs.records[0].exc_info)

    def test_shutdown_interrupts_remaining_devices_and_rejects_new_jobs(self):
        started, release = threading.Event(), threading.Event()

        def tester(profile, **kwargs):
            started.set()
            self.assertTrue(release.wait(3))
            return OK

        worker = self.worker(tester)
        self.addCleanup(release.set)
        job = worker.start(["1", "2"])
        self.assertTrue(started.wait(3))
        stopped = threading.Thread(target=worker.shutdown)
        stopped.start()
        self.assertTrue(worker._stop.wait(3))
        release.set()
        stopped.join(timeout=3)
        self.assertFalse(stopped.is_alive())
        self.assertEqual(worker.get(job["id"])["status"], "failed")
        self.assertEqual(worker.get(job["id"])["completed"], 1)
        with self.assertRaises(ManagementError) as raised:
            worker.start(["1"])
        self.assertEqual(raised.exception.status_code, 503)

    def test_exports_whitelist_fields_and_escape_formulas(self):
        self.store.rows["connections"]["1"]["name"] = " \t=HYPERLINK(\"bad\")"
        worker = self.worker(Mock(return_value={**OK, "detail": "+FORMULA"}))
        job = worker.start(["1"])
        worker._future.result(timeout=3)
        self.store.jobs[job["id"]]["password"] = "SECRET"
        self.store.jobs[job["id"]]["results"][0]["private_key"] = "SECRET"
        text, media, filename = worker.export(job["id"], "csv")
        rows = list(csv.DictReader(io.StringIO(text)))
        self.assertTrue(rows[0]["name"].startswith("'"))
        self.assertTrue(rows[0]["detail"].startswith("'"))
        self.assertNotIn("SECRET", text)
        text, media, filename = worker.export(job["id"], "json")
        self.assertEqual(json.loads(text)["completed"], 1)
        self.assertNotIn("SECRET", text)
        self.store.jobs[job["id"]]["id"] = 'evil"\r\n/../header'
        _, _, filename = worker.export(job["id"], "json")
        self.assertNotIn("\r", filename)
        self.assertNotIn('"', filename)
        self.assertNotIn("/", filename)

    def test_async_shutdown_helper_joins_worker(self):
        worker = self.worker(Mock(return_value=OK))
        app = FastAPI()
        app.state.management_batches = worker
        asyncio.run(shutdown_management(app))
        self.assertTrue(worker._closed)

    def test_legacy_network_exports_default_simulated_to_false(self):
        worker = self.worker(Mock(return_value=OK))
        job = worker.start(["1"])
        worker._future.result(timeout=3)
        del self.store.jobs[job["id"]]["results"][0]["simulated"]
        content, _, _ = worker.export(job["id"], "json")
        self.assertIs(json.loads(content)["results"][0]["simulated"], False)
        content, _, _ = worker.export(job["id"], "csv")
        self.assertEqual(list(csv.DictReader(io.StringIO(content)))[0]["simulated"], "False")


if __name__ == "__main__":
    unittest.main()
