"""Future sequential-routing acceptance suite, separate from Step 8M current features."""
import unittest
from test_studio_ui import StudioUITests
import test_provider_routing


def _skip_future(method):
    def skipped(self):
        self.skipTest('Sequential routing is future work outside Step 8M.')
    skipped.__name__ = method.__name__
    skipped.__doc__ = method.__doc__
    return skipped


class SequentialRoutingProviderTests(test_provider_routing.ProviderRoutingTests):
    """Original provider routing expectations, run independently from current features."""
    __test__ = True


class SequentialRoutingUITests(StudioUITests):
    __test__ = False
    """Run separately with `python -m unittest discover -s tests -p test_step8m_sequential_routing_future.py`."""
    test_local_failure_prepares_openai_preview_but_sends_nothing_until_approval = _skip_future(
        StudioUITests.test_local_failure_prepares_openai_preview_but_sends_nothing_until_approval)
    test_local_openai_alibaba_journey_requires_separate_action_then_consent = _skip_future(
        StudioUITests.test_local_openai_alibaba_journey_requires_separate_action_then_consent)
    test_cloud_decline_requires_explicit_continue_before_next_preview = _skip_future(
        StudioUITests.test_cloud_decline_requires_explicit_continue_before_next_preview)
    test_blocked_alibaba_is_not_prepared_and_only_explicit_revalidation_unblocks = _skip_future(
        StudioUITests.test_blocked_alibaba_is_not_prepared_and_only_explicit_revalidation_unblocks)


if __name__ == '__main__':
    unittest.main()
