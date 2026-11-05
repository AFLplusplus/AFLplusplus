"""Offline tests for provider-independent intelligence records."""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from brain_core.intelligence_records import (
    IntelligenceRecord, ValidationStatus, from_inference_result, from_web_evidence,
)
from brain_core.providers import InferenceResult, ProviderID
from brain_core.research_evidence import validate_search_results


class IntelligenceRecordTests(unittest.TestCase):
    def result(self, provider, *, status='success', structured=None, text='{}', category=None,
               request_id='request-1', input_tokens=None, output_tokens=None):
        return InferenceResult(
            provider, 'synthetic-model', text, structured, status, category, 0.1,
            input_tokens, output_tokens, request_id, None, True, provider != ProviderID.LOCAL_OLLAMA)

    def test_local_and_openai_results_are_provider_independent_immutable_records(self):
        output = {'answer': 'synthetic', 'items': ['one', 'two']}
        for provider in (ProviderID.LOCAL_OLLAMA, ProviderID.OPENAI_CLOUD):
            with self.subTest(provider=provider):
                result_output = {'answer': 'synthetic', 'items': ['one', 'two']}
                result = self.result(provider, structured=result_output)
                record = from_inference_result(result)
                self.assertIsInstance(record, IntelligenceRecord)
                self.assertEqual(record.source_type, 'inference')
                self.assertEqual(record.source_id, 'request-1')
                self.assertEqual(record.validation_status, ValidationStatus.VALID)
                self.assertEqual(record.citations, ())
                self.assertIn('not independently verified', record.uncertainty)
                self.assertEqual(dict(record.provenance)['provider'], provider.value)
                result_output['items'].append('changed-after-adaptation')
                self.assertEqual(dict(record.content)['items'], ('one', 'two'))
                with self.assertRaises((AttributeError, TypeError)):
                    record.source_type = 'web_evidence'

    def test_failed_inference_is_failed_not_trusted_evidence(self):
        result = self.result(ProviderID.OPENAI_CLOUD, status='failed', structured=None,
                             text='', category='authentication')
        record = from_inference_result(result)
        self.assertEqual(record.validation_status, ValidationStatus.FAILED)
        self.assertEqual(record.content, '')
        self.assertEqual(record.citations, ())
        self.assertIn('Inference failed', record.uncertainty)
        self.assertEqual(dict(record.provenance)['error_category'], 'authentication')

    def test_success_with_missing_structured_output_is_invalid(self):
        record = from_inference_result(self.result(ProviderID.ALIBABA_QWEN_CLOUD,
                                                   structured=None, text='not structured'))
        self.assertEqual(record.validation_status, ValidationStatus.INVALID)
        self.assertEqual(record.content, 'not structured')
        self.assertIn('invalid and untrusted', record.uncertainty)
        self.assertEqual(record.citations, ())

    def test_web_evidence_retains_citation_uncertainty_and_untrusted_provenance(self):
        evidence, = validate_search_results(
            [{'url': 'https://example.test/article', 'title': 'Synthetic title',
              'snippet': 'A claim from an unverified snippet.'}],
            retrieved_at='2026-01-02T03:04:05+00:00')
        first = from_web_evidence(evidence)
        second = from_web_evidence(evidence)
        self.assertEqual(first, second)
        self.assertEqual(first.source_type, 'web_evidence')
        self.assertEqual(first.source_id, 'https://example.test/article')
        self.assertEqual(first.citations, ('https://example.test/article',))
        self.assertEqual(first.validation_status, ValidationStatus.UNVERIFIED)
        self.assertEqual(first.uncertainty, evidence.uncertainty)
        provenance = dict(first.provenance)
        self.assertFalse(provenance['content_trusted'])
        self.assertEqual(provenance['retrieved_at'], '2026-01-02T03:04:05+00:00')
        self.assertEqual(dict(first.content)['claim'], evidence.claim)

    def test_missing_metadata_is_preserved_as_absent_without_inference(self):
        record = from_inference_result(self.result(ProviderID.LOCAL_OLLAMA, structured={'x': 1},
                                                   request_id=None, input_tokens=None, output_tokens=None))
        self.assertIsNone(record.source_id)
        provenance = dict(record.provenance)
        self.assertNotIn('input_tokens', provenance)
        self.assertNotIn('output_tokens', provenance)
        self.assertEqual(record.citations, ())

    def test_invalid_source_objects_are_rejected_and_provenance_is_deterministic(self):
        with self.assertRaises(TypeError):
            from_inference_result({'status': 'success'})
        with self.assertRaises(TypeError):
            from_web_evidence({'url': 'https://example.test'})
        result = self.result(ProviderID.OPENAI_CLOUD, structured={'b': 2, 'a': 1})
        self.assertEqual(from_inference_result(result), from_inference_result(result))
        serialized = json.dumps(from_inference_result(result).provenance)
        self.assertIn('openai_cloud', serialized)


if __name__ == '__main__':
    unittest.main()
