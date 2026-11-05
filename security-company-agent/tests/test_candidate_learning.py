"""Offline tests for pending-review candidate lesson generation."""
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from brain_core.intelligence_comparison import compare_intelligence
from brain_core.intelligence_records import from_inference_result, from_web_evidence
from brain_core.intelligence_synthesis import synthesize_intelligence
from brain_core.candidate_learning import CandidateLesson, generate_candidate
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


def synthesis(model_claims=None, web_claim=None, *, failed=False):
    records = []
    if model_claims is not None:
        records.append(model_record(ProviderID.LOCAL_OLLAMA, model_claims,
                                    status='failed' if failed else 'success', request_id='model-1'))
    if web_claim is not None:
        records.append(web_record('https://example.test/lesson', web_claim))
    return synthesize_intelligence(compare_intelligence(records))


class CandidateLearningTests(unittest.TestCase):
    def test_clear_reusable_principle_yields_pending_review_candidate(self):
        principle = 'When facts are uncertain, ask for clarification before acting.'
        result = synthesis([principle], principle)
        candidate = generate_candidate(result)
        self.assertIsInstance(candidate, CandidateLesson)
        self.assertEqual(candidate.proposed_principle, principle.rstrip('.'))
        self.assertEqual(candidate.review_status, 'pending_review')
        self.assertEqual({reference[1] for reference in candidate.source_references},
                         {'model-1', 'https://example.test/lesson'})
        self.assertTrue(any('not approved memory' in item for item in candidate.uncertainty))

    def test_conflicting_or_unresolved_evidence_suppresses_candidate(self):
        model = model_record(ProviderID.LOCAL_OLLAMA,
                             ['When facts are uncertain, ask for clarification before acting.'],
                             request_id='model-1')
        web = web_record('https://example.test/conflict',
                         'When facts are uncertain, act immediately rather than ask for clarification.')
        self.assertIsNone(generate_candidate(synthesize_intelligence(compare_intelligence((model, web)))))

    def test_insufficient_or_non_principle_claim_suppresses_candidate(self):
        self.assertIsNone(generate_candidate(synthesis(['The office is closed today.'],
                                                       'The office is closed today.')))
        self.assertIsNone(generate_candidate(synthesize_intelligence(compare_intelligence(()))))

    def test_web_only_evidence_never_generates_learning_candidate(self):
        result = synthesis(web_claim='When facts are uncertain, ask for clarification before acting.')
        self.assertIsNone(generate_candidate(result))

    def test_model_only_agreement_does_not_generate_candidate(self):
        records = (
            model_record(ProviderID.LOCAL_OLLAMA,
                         ['When facts are uncertain, ask for clarification before acting.'], request_id='one'),
            model_record(ProviderID.OPENAI_CLOUD,
                         ['When facts are uncertain, ask for clarification before acting.'], request_id='two'),
        )
        self.assertIsNone(generate_candidate(synthesize_intelligence(compare_intelligence(records))))

    def test_failed_provider_is_not_candidate_evidence(self):
        result = synthesis(['When facts are uncertain, ask for clarification before acting.'],
                           'When facts are uncertain, ask for clarification before acting.', failed=True)
        self.assertIsNone(generate_candidate(result))

    def test_emotional_truth_is_not_inferred_as_a_lesson(self):
        claim = 'You should listen when someone feels afraid and anxious.'
        self.assertIsNone(generate_candidate(synthesis([claim], claim)))

    def test_provenance_is_preserved_and_generation_performs_no_persistent_writes(self):
        principle = 'When facts are uncertain, ask for clarification before acting.'
        result = synthesis([principle], principle)
        with patch('brain_core.lessons.approve', side_effect=AssertionError('must not approve')) as approve:
            with patch('brain_core.studio.connect', side_effect=AssertionError('must not write')) as connect:
                candidate = generate_candidate(result)
        approve.assert_not_called()
        connect.assert_not_called()
        self.assertEqual(len(candidate.source_references), 2)
        self.assertTrue(all(reference[3] for reference in candidate.source_references))
        self.assertEqual(candidate.provenance,
                         tuple(reference[3] for reference in candidate.source_references))

    def test_rejects_non_synthesis_input(self):
        with self.assertRaises(TypeError):
            generate_candidate(None)


if __name__ == '__main__':
    unittest.main()
