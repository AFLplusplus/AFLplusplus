"""Offline tests for deterministic multi-source intelligence comparisons."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from brain_core.intelligence_comparison import compare_intelligence
from brain_core.intelligence_records import (
    IntelligenceRecord, ValidationStatus, from_inference_result, from_web_evidence,
)
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


class IntelligenceComparisonTests(unittest.TestCase):
    def test_exact_shared_claim_retains_sources_and_warns_not_independent_verification(self):
        local = model_record(ProviderID.LOCAL_OLLAMA, ['A meeting was cancelled.'], request_id='local-1')
        cloud = model_record(ProviderID.OPENAI_CLOUD, [' a meeting was cancelled. '], request_id='cloud-1')
        web = web_record('https://example.test/corroboration', 'A meeting was cancelled.')
        comparison = compare_intelligence((cloud, local, web))
        self.assertEqual(len(comparison.valid_sources), 3)
        self.assertEqual(len(comparison.shared_claims), 1)
        refs = comparison.shared_claims[0]
        self.assertEqual({ref.source_id for ref in refs}, {
            'local-1', 'cloud-1', 'https://example.test/corroboration'})
        self.assertEqual(next(ref for ref in refs if ref.source_type == 'web_evidence').citations,
                         ('https://example.test/corroboration',))
        self.assertIn('Exact claim repetition is not independent factual verification or proof of truth.',
                      comparison.uncertainty)
        self.assertEqual(compare_intelligence((cloud, local, web)), comparison)

    def test_nonidentical_possible_contradiction_is_unresolved_not_guessed(self):
        first = model_record(ProviderID.LOCAL_OLLAMA, ['The meeting was cancelled.'], request_id='one')
        second = model_record(ProviderID.OPENAI_CLOUD, ['The meeting was not cancelled.'], request_id='two')
        web = web_record('https://example.test/unrelated', 'An unrelated source statement.')
        comparison = compare_intelligence((first, second, web))
        self.assertEqual(comparison.contradictions, ())
        self.assertEqual(len(comparison.unresolved_claims), 3)
        self.assertTrue(any('semantic agreement or contradiction was not inferred' in item
                            for item in comparison.uncertainty))

    def test_keyword_overlap_does_not_create_shared_claim(self):
        first = model_record(ProviderID.LOCAL_OLLAMA, ['A meeting was cancelled.'], request_id='one')
        second = model_record(ProviderID.OPENAI_CLOUD, ['The meeting cancellation caused stress.'], request_id='two')
        web = web_record('https://example.test/keyword', 'An unrelated source statement.')
        comparison = compare_intelligence((first, second, web))
        self.assertEqual(comparison.shared_claims, ())
        self.assertEqual(len(comparison.unsupported_claims), 3)

    def test_failed_model_result_never_counts_as_a_source_or_claim(self):
        good = model_record(ProviderID.LOCAL_OLLAMA, ['A specific claim.'], request_id='good')
        failed = model_record(ProviderID.OPENAI_CLOUD, ['A specific claim.'], status='failed', request_id='bad')
        web = web_record('https://example.test/good', 'An unrelated source statement.')
        comparison = compare_intelligence((good, failed, web))
        self.assertEqual(len(comparison.valid_sources), 2)
        self.assertEqual(len(comparison.unsupported_claims), 2)
        self.assertNotIn('bad', {record.source_id for record in comparison.valid_sources})
        self.assertNotIn('bad', {ref.source_id for ref in comparison.unsupported_claims})
        self.assertTrue(any('Inference failed' in item for item in comparison.uncertainty))

    def test_web_evidence_remains_unverified_and_keeps_citation_and_provenance(self):
        web = web_record('https://example.test/report', 'A reported claim from a search snippet.')
        comparison = compare_intelligence((web,))
        self.assertEqual(len(comparison.shared_claims), 0)
        web_ref, = comparison.unsupported_claims
        self.assertEqual(web_ref.citations, ('https://example.test/report',))
        self.assertEqual(dict(web_ref.provenance)['content_trusted'], False)
        self.assertEqual(len(comparison.contradictions), 0)
        self.assertTrue(any('unverified' in item for item in comparison.uncertainty))

    def test_missing_sources_and_nonrecords_are_handled_deterministically(self):
        empty = compare_intelligence(())
        self.assertEqual(empty.valid_sources, ())
        self.assertEqual(empty.shared_claims, ())
        self.assertEqual(empty.unsupported_claims, ())
        self.assertEqual(empty.unresolved_claims, ())
        self.assertEqual(compare_intelligence(None), empty)
        self.assertEqual(compare_intelligence((object(),)), empty)

    def test_invalid_records_are_excluded_and_provenance_is_retained(self):
        invalid = IntelligenceRecord('inference', 'invalid-1', (('claims', ('Claim',)),),
                                     ValidationStatus.INVALID, (), 'invalid output',
                                     (('provider', 'openai_cloud'),))
        valid = model_record(ProviderID.LOCAL_OLLAMA, ['A separate claim.'], request_id='valid-1')
        web = web_record('https://example.test/valid', 'External source statement.')
        comparison = compare_intelligence((invalid, valid, web))
        self.assertEqual(len(comparison.valid_sources), 2)
        refs = {ref.source_id: ref for ref in comparison.unsupported_claims}
        self.assertEqual(dict(refs['valid-1'].provenance)['provider'], 'local_ollama')
        self.assertNotIn('invalid-1', refs)

    def test_model_agreement_without_web_source_is_not_counted_as_shared(self):
        local = model_record(ProviderID.LOCAL_OLLAMA, ['Same assertion.'], request_id='local')
        cloud = model_record(ProviderID.OPENAI_CLOUD, ['Same assertion.'], request_id='cloud')
        comparison = compare_intelligence((local, cloud))
        self.assertEqual(comparison.shared_claims, ())
        self.assertEqual(comparison.unsupported_claims, ())
        self.assertEqual(comparison.unresolved_claims, ())
        self.assertTrue(any('Model-only claims' in item for item in comparison.uncertainty))


if __name__ == '__main__':
    unittest.main()
