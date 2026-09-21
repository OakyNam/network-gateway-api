import io
import logging
import unittest
from contextlib import redirect_stdout

from loguru import logger

from config.logger import setup_logging


class LoggingConfigTests(unittest.TestCase):
    def tearDown(self):
        setup_logging()

    def test_standard_and_loguru_messages_are_visible_once(self):
        output = io.StringIO()
        with redirect_stdout(output):
            setup_logging()
            logging.getLogger("gateway.logging-test").warning("standard-marker")
            logger.warning("loguru-marker")
        self.assertEqual(output.getvalue().count("standard-marker"), 1)
        self.assertEqual(output.getvalue().count("loguru-marker"), 1)

    def test_reinitializing_does_not_duplicate_output(self):
        output = io.StringIO()
        with redirect_stdout(output):
            setup_logging()
            setup_logging()
            logging.getLogger("gateway.logging-test").error("one-error-marker")
        self.assertEqual(output.getvalue().count("one-error-marker"), 1)

    def test_traceback_does_not_dump_local_variables(self):
        output = io.StringIO()
        with redirect_stdout(output):
            setup_logging()
            sensitive_local = "fake-secret-not-for-diagnostic-output"
            try:
                raise ValueError("expected-test-error")
            except ValueError:
                logging.getLogger("gateway.logging-test").exception("Operation failed")
        self.assertIn("expected-test-error", output.getvalue())
        self.assertNotIn(sensitive_local, output.getvalue())


if __name__ == "__main__":
    unittest.main()
