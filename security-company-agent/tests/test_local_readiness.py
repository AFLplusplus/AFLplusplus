"""Offline unit tests for the read-only local model readiness check."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from brain_core import model_api
from brain_core.model_policy import selected_local_model


class LocalReadinessTests(unittest.TestCase):
    def test_available_when_ollama_model_and_memory_are_ready(self):
        model = selected_local_model()
        with patch.object(model_api, 'local_inventory', return_value=[model]):
            with patch.object(model_api, 'available_memory_gib', return_value=8.0):
                self.assertEqual(model_api.check_local_readiness(),
                                 {'status': 'AVAILABLE', 'reason': None})

    def test_offline_when_ollama_is_unreachable(self):
        with patch.object(model_api, 'local_inventory', return_value=[]):
            with patch.object(model_api, 'available_memory_gib') as memory:
                self.assertEqual(model_api.check_local_readiness(),
                                 {'status': 'UNAVAILABLE', 'reason': 'service_offline'})
                memory.assert_not_called()

    def test_missing_when_configured_model_is_not_installed(self):
        with patch('brain_core.model_policy.selected_local_model', return_value='qwen-test:0.6b'):
            with patch.object(model_api, 'local_inventory', return_value=['other-model:latest']):
                with patch.object(model_api, 'available_memory_gib') as memory:
                    self.assertEqual(model_api.check_local_readiness(),
                                     {'status': 'UNAVAILABLE', 'reason': 'model_missing'})
                    memory.assert_not_called()

    def test_low_memory_reported_only_from_verified_local_measurement(self):
        model = selected_local_model()
        with patch.object(model_api, 'local_inventory', return_value=[model]):
            with patch.object(model_api, 'available_memory_gib', return_value=0.5):
                self.assertEqual(model_api.check_local_readiness(),
                                 {'status': 'UNAVAILABLE', 'reason': 'insufficient_memory'})

    def test_unavailable_memory_measurement_is_unknown_not_low_memory(self):
        model = selected_local_model()
        with patch.object(model_api, 'local_inventory', return_value=[model]):
            with patch.object(model_api, 'available_memory_gib', return_value=None):
                self.assertEqual(model_api.check_local_readiness(),
                                 {'status': 'AVAILABLE', 'reason': 'unknown'})


if __name__ == '__main__':
    unittest.main()
