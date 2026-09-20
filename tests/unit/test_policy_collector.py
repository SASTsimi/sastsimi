"""Policy collection must not turn an LLM-only label into trusted identity."""

from sastsimi.policy.collector import PolicyCollector


def test_missing_information_keeps_only_existing_policy_item_links() -> None:
    item_ids = {"local-only": "policy-item-1"}

    resolved = PolicyCollector._known_item_ids(
        item_ids,
        ("local-only", "official-policy-unavailable"),
    )

    assert resolved == ("policy-item-1",)


def test_missing_information_may_have_no_policy_item_link() -> None:
    resolved = PolicyCollector._known_item_ids(
        {},
        ("official-policy-unavailable",),
    )

    assert resolved == ()
