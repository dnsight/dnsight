"""Tests for MergeableConfig."""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from dnsight.core.config.blocks import Config, DmarcConfig, ThrottleConfig


class TestMerge:
    def test_merge_only_set_fields(self) -> None:
        base = DmarcConfig(policy="none", rua_required=False)
        partial = DmarcConfig.model_construct(policy="reject")
        # Manually mark only 'policy' as set
        partial.__pydantic_fields_set__ = {"policy"}

        merged = base.merge(partial)
        assert merged.policy == "reject"
        assert merged.rua_required is False

    def test_merge_preserves_unset_fields(self) -> None:
        base = ThrottleConfig(global_max_rps=50.0, global_max_concurrency=10)
        partial = ThrottleConfig.model_construct(global_max_rps=100.0)
        partial.__pydantic_fields_set__ = {"global_max_rps"}

        merged = base.merge(partial)
        assert merged.global_max_rps == 100.0
        assert merged.global_max_concurrency == 10

    def test_merge_recursive_nested_config(self) -> None:
        base = Config()
        partial_dmarc = DmarcConfig(policy="reject")
        partial = Config(dmarc=partial_dmarc)

        merged = base.merge(partial)
        assert merged.dmarc.policy == "reject"
        assert merged.dmarc.rua_required is True  # from base default

    def test_merge_returns_new_instance(self) -> None:
        base = DmarcConfig(policy="quarantine")
        partial = DmarcConfig(policy="reject")

        merged = base.merge(partial)
        assert merged is not base
        assert base.policy == "quarantine"
        assert merged.policy == "reject"


class TestResolve:
    def test_resolve_defaults_only(self) -> None:
        resolved = DmarcConfig.resolve()
        assert resolved.policy == "reject"
        assert resolved.rua_required is True

    def test_resolve_with_config(self) -> None:
        cfg = DmarcConfig(policy="quarantine")
        resolved = DmarcConfig.resolve(config=cfg)
        assert resolved.policy == "quarantine"

    def test_resolve_with_partial(self) -> None:
        base = DmarcConfig(policy="none")
        partial = DmarcConfig(policy="reject")
        resolved = DmarcConfig.resolve(config=base, partial=partial)
        assert resolved.policy == "reject"

    def test_resolve_with_kwargs(self) -> None:
        resolved = DmarcConfig.resolve(policy="quarantine", rua_required=True)
        assert resolved.policy == "quarantine"
        assert resolved.rua_required is True

    def test_resolve_precedence_kwargs_over_partial(self) -> None:
        base = DmarcConfig(policy="none")
        partial = DmarcConfig(policy="quarantine")
        resolved = DmarcConfig.resolve(config=base, partial=partial, policy="reject")
        assert resolved.policy == "reject"


@given(
    base_policy=st.sampled_from(["none", "quarantine", "reject"]),
    overlay_policy=st.sampled_from(["none", "quarantine", "reject"]),
)
def test_dmarc_merge_partial_only_overrides_listed_fields(
    base_policy: str, overlay_policy: str
) -> None:
    """Explicit ``model_fields_set`` on partial controls merge; other fields stay."""
    base = DmarcConfig(policy=base_policy, rua_required=True)  # type: ignore[arg-type]
    partial = DmarcConfig.model_construct(policy=overlay_policy)
    partial.__pydantic_fields_set__ = {"policy"}
    merged = base.merge(partial)
    assert merged.policy == overlay_policy
    assert merged.rua_required is True
