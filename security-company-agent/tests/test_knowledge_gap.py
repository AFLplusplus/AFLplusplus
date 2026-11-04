"""Offline tests for deterministic knowledge-gap detection."""
import unittest

from brain_core.knowledge_gap import (
    KnowledgeGapClassification as Classification,
    assess_knowledge_gap,
    classify_knowledge_gap,
)


class KnowledgeGapTests(unittest.TestCase):
    def test_greeting_does_not_need_research(self):
        result = assess_knowledge_gap('Hello!')
        self.assertEqual(result.classification, Classification.NOT_NEEDED)
        self.assertTrue(result.reason)

    def test_emotional_discussion_does_not_trigger_research(self):
        result = assess_knowledge_gap('I feel hurt because my friend stopped responding.')
        self.assertEqual(result.classification, Classification.NOT_NEEDED)

    def test_general_knowledge_is_optional(self):
        result = assess_knowledge_gap('How do rainbows form?')
        self.assertEqual(result.classification, Classification.OPTIONAL)

    def test_current_law_recommends_research(self):
        result = assess_knowledge_gap('What are the current laws on data privacy?')
        self.assertEqual(result.classification, Classification.RECOMMENDED)

    def test_recent_developments_recommend_research(self):
        result = assess_knowledge_gap('What are the latest developments in battery technology?')
        self.assertEqual(result.classification, Classification.RECOMMENDED)

    def test_explicit_research_request_recommends_research(self):
        result = assess_knowledge_gap('Please research the evidence on sleep and memory.')
        self.assertEqual(result.classification, Classification.RECOMMENDED)

    def test_explicit_sources_request_recommends_research(self):
        result = classify_knowledge_gap('Explain photosynthesis with citations.')
        self.assertEqual(result.classification, Classification.RECOMMENDED)

    def test_uncertain_fact_recommends_verification(self):
        result = assess_knowledge_gap('Can you verify whether this statistic is accurate?')
        self.assertEqual(result.classification, Classification.RECOMMENDED)

    def test_reasons_are_short_and_never_echo_user_content(self):
        secret_like_text = 'Research this unusual phrase: private-user-content-12345'
        result = assess_knowledge_gap(secret_like_text)
        self.assertLessEqual(len(result.reason), 100)
        self.assertNotIn('private-user-content-12345', result.reason)

    def test_empty_or_non_string_input_is_safe(self):
        self.assertEqual(assess_knowledge_gap('').classification, Classification.NOT_NEEDED)
        self.assertEqual(assess_knowledge_gap(None).classification, Classification.NOT_NEEDED)


if __name__ == '__main__':
    unittest.main()
