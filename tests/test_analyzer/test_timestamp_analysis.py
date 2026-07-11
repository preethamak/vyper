from guardian.analyzer.timestamp_analysis import classify_timestamp_use


def test_curve_checkpoint_is_accounting() -> None:
    assert (
        classify_timestamp_use(
            "_checkpoint", "if block.timestamp > last_point.ts:", "block_slope = 1"
        )
        == "accounting"
    )


def test_vote_delay_is_protocol_scheduling() -> None:
    assert (
        classify_timestamp_use(
            "vote_for_gauge_weights",
            "assert block.timestamp >= self.last_user_vote[user] + WEIGHT_VOTE_DELAY",
        )
        == "protocol_scheduling"
    )


def test_short_unexplained_assert_is_authorization_window() -> None:
    assert (
        classify_timestamp_use("enter", "assert block.timestamp > 1000") == "authorization_window"
    )
