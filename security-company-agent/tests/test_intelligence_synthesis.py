"""Offline tests for deterministic consolidated intelligence synthesis."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from brain_core.intelligence_comparison import compare_intelligence
from brain_core.intelligence_records import from_inference_result, from_web_evidence
from brain_core.intelligence_synthesis import synthesize_intelligence
from brain_core.providers import InferenceResult, ProviderID
from brain_core.research_evidence import validate_search_results


def model_record(provider, claims, *, status='success', request_id=None):
    result = InferenceResult(provider, 'synthetic-model', '', {'claims': claims}, status,
                             'provider_error' if status == 'failed' else None,
                             0.1, None, None, request_id, None, True, provider != ProviderID.LOCAL_OLLAMA)
    return from_inference_result(result)


def web_record(url, snippet):
    evidence, = validate_search_results(
        [{'url': url, 'title': 'Synthetic source', 'snippet': snippet}],
        retrieved_at='2026-02-03T00:00:00+00:00')
    return from_web_evidence(evidence)


class IntelligenceSynthesisTests(unittest.TestCase):
    def test_matching_claims_are_literal_qualified_and_retain_source_refs(self):
        model = model_record(ProviderID.LOCAL_OLLAMA, ['The site is closed today.'], request_id='model-1')
        web = web_record('https://example.test/site', 'The site is closed today.')
        synthesis = synthesize_intelligence(compare_intelligence((model, web)))
        self.assertEqual(synthesis.status, 'qualified')
        self.assertIn('Qualified summary', synthesis.answer)
        self.assertEqual({ref.source_id for ref in synthesis.supporting_sources},
                         {'model-1', 'https://example.test/site'})
        self.assertTrue(any(ref.evidence_label == 'unverified_web_evidence'
                            for ref in synthesis.supporting_sources))
        self.assertIn('not verified', synthesis.answer)
        self.assertTrue(any('not independent factual verification' in item
                            for item in synthesis.uncertainty))

    def test_conflicting_or_unresolved_claims_are_not_reconciled(self):
        model = model_record(ProviderID.LOCAL_OLLAMA, ['The site is open today.'], request_id='model-1')
        web = web_record('https://example.test/site', 'The site is closed today.')
        synthesis = synthesize_intelligence(compare_intelligence((model, web)))
        self.assertEqual(synthesis.status, 'qualified')
        self.assertEqual(synthesis.unresolved_differences, tuple(sorted(
            synthesis.unresolved_differences, key=lambda item: (item.source_type, item.source_id or '', item.claim,
                                                                 item.citations, repr(item.provenance)))))
        self.assertEqual(len(synthesis.unresolved_differences), 2)
        self.assertTrue(any('unresolved' in item.lower() for item in synthesis.uncertainty))
        self.assertNotIn('therefore', synthesis.answer.lower())

    def test_failed_provider_is_not_used_in_answer_or_support(self):
        failed = model_record(ProviderID.OPENAI_CLOUD, ['Claim from a failed result.'],
                              status='failed', request_id='failed-1')
        web = web_record('https://example.test/source', 'A separate published statement.')
        synthesis = synthesize_intelligence(compare_intelligence((failed, web)))
        self.assertEqual(synthesis.status, 'qualified')
        self.assertNotIn('failed-1', {item.source_id for item in synthesis.supporting_sources})
        self.assertNotIn('Claim from a failed result.', synthesis.answer)
        self.assertTrue(any('Inference failed' in item for item in synthesis.uncertainty))

    def test_web_only_content_is_labeled_unverified_and_not_fact(self):
        web = web_record('https://example.test/report', 'A source snippet reports a delay.')
        synthesis = synthesize_intelligence(compare_intelligence((web,)))
        self.assertEqual(synthesis.status, 'qualified')
        self.assertIn('unverified source reports', synthesis.answer)
        self.assertIn('not established as fact', synthesis.answer)
        self.assertEqual(synthesis.supporting_sources[0].citations, ('https://example.test/report',))
        self.assertEqual(synthesis.supporting_sources[0].evidence_label, 'unverified_web_evidence')

    def test_empty_input_has_explicit_unresolved_status(self):
        synthesis = synthesize_intelligence(compare_intelligence(()))
        self.assertEqual(synthesis.status, 'unresolved')
        self.assertEqual(synthesis.supporting_sources, ())
        self.assertEqual(synthesis.unresolved_differences, ())
        self.assertIn('no valid sources', synthesis.answer)

    def test_model_only_agreement_is_not_used_as_a_consolidated_answer(self):
        local = model_record(ProviderID.LOCAL_OLLAMA, ['Same model assertion.'], request_id='local')
        cloud = model_record(ProviderID.OPENAI_CLOUD, ['Same model assertion.'], request_id='cloud')
        synthesis = synthesize_intelligence(compare_intelligence((local, cloud)))
        self.assertEqual(synthesis.status, 'unresolved')
        self.assertEqual(synthesis.supporting_sources, ())

    def test_rejects_non_comparison_input(self):
        with self.assertRaises(TypeError):
            synthesize_intelligence(None)


if __name__ == '__main__':
    unittest.main()
