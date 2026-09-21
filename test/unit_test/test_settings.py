"""Fail-closed simulated device provider configuration."""

import os
import unittest
from unittest.mock import patch

from config.settings import device_data_provider


class DeviceDataProviderSettingsTests(unittest.TestCase):
    def test_default_is_disabled(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(device_data_provider(), "disabled")

    def test_explicit_provider_is_read_on_each_call(self):
        with patch.dict(os.environ, {}, clear=True):
            for provider in ("fake", "disabled", "fake"):
                os.environ["GATEWAY_DEVICE_DATA_PROVIDER"] = provider
                self.assertEqual(device_data_provider(), provider)

    def test_invalid_settings_raise_sanitized_value_error(self):
        for value in ("", "FAKE", " fake ", "network", "secret-token\ninjected"):
            with self.subTest(value=value):
                with patch.dict(os.environ, {"GATEWAY_DEVICE_DATA_PROVIDER": value}, clear=True):
                    with self.assertRaises(ValueError) as raised:
                        device_data_provider()
                self.assertEqual(
                    str(raised.exception),
                    "GATEWAY_DEVICE_DATA_PROVIDER must be 'fake' or 'disabled'.",
                )


if __name__ == "__main__":
    unittest.main()
