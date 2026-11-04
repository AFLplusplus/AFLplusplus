"""Future automatic-routing acceptance tests.

Default unittest discovery skips these tests with an explicit future-feature reason.
To deliberately run them (and observe remaining gaps), use:
    SOVEREIGN_RUN_FUTURE_ROUTING=1 python -m unittest discover -s tests -p test_step8m_sequential_routing_future.py
"""
import os
import unittest
import test_provider_routing
from test_studio_ui import StudioUITests


FUTURE_ROUTING_REASON = 'Future feature: automatic sequential provider routing not implemented.'
RUN_FUTURE_ROUTING = os.environ.get('SOVEREIGN_RUN_FUTURE_ROUTING') == '1'


class SequentialRoutingProviderTests(test_provider_routing.ProviderRoutingTests):
    """Expose original provider assertions; never change their test bodies."""
    __unittest_skip__ = not RUN_FUTURE_ROUTING
    __unittest_skip_why__ = FUTURE_ROUTING_REASON


class SequentialRoutingUITests(StudioUITests):
    """Expose the four original UI journey assertions without changing their bodies."""
    __unittest_skip__ = not RUN_FUTURE_ROUTING
    __unittest_skip_why__ = FUTURE_ROUTING_REASON

    test_local_failure_prepares_openai_preview_but_sends_nothing_until_approval = (
        StudioUITests.test_local_failure_prepares_openai_preview_but_sends_nothing_until_approval)
    test_local_openai_alibaba_journey_requires_separate_action_then_consent = (
        StudioUITests.test_local_openai_alibaba_journey_requires_separate_action_then_consent)
    test_cloud_decline_requires_explicit_continue_before_next_preview = (
        StudioUITests.test_cloud_decline_requires_explicit_continue_before_next_preview)
    test_blocked_alibaba_is_not_prepared_and_only_explicit_revalidation_unblocks = (
        StudioUITests.test_blocked_alibaba_is_not_prepared_and_only_explicit_revalidation_unblocks)


if __name__ == '__main__':
    unittest.main()
