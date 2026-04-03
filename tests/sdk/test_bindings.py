"""Unit tests for :mod:`dnsight.sdk._bindings` merge helpers and generate binders."""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st
import pytest

from dnsight.core.config.blocks import Config, DmarcConfig
from dnsight.sdk._bindings import GenerateBinder, merge_check_programmatic_config


class TestMergeCheckProgrammaticConfig:
    def test_both_none_returns_none(self) -> None:
        assert merge_check_programmatic_config(None, None, config_field="dmarc") is None

    def test_config_only_returns_same_root(self) -> None:
        cfg = Config(dmarc=DmarcConfig(policy="none"))
        out = merge_check_programmatic_config(cfg, None, config_field="dmarc")
        assert out is cfg

    def test_slice_only_builds_fresh_config_with_field(self) -> None:
        slice_ = DmarcConfig(policy="reject", rua_required=False)
        out = merge_check_programmatic_config(None, slice_, config_field="dmarc")
        assert out is not None
        assert out.dmarc.policy == "reject"
        assert out.dmarc.rua_required is False

    def test_config_plus_slice_overrides_field(self) -> None:
        base = Config(dmarc=DmarcConfig(policy="none", rua_required=True))
        slice_ = DmarcConfig(policy="reject")
        out = merge_check_programmatic_config(base, slice_, config_field="dmarc")
        assert out is not None
        assert out.dmarc.policy == "reject"
        assert out.dmarc.rua_required is True


@given(policy=st.sampled_from(["none", "quarantine", "reject"]), rua=st.booleans())
def test_merge_check_programmatic_config_slice_only_preserves_invariants(
    policy: str, rua: bool
) -> None:
    """Fresh Config from slice-only merge keeps non-dmarc defaults."""
    slice_ = DmarcConfig(policy=policy, rua_required=rua)  # type: ignore[arg-type]
    out = merge_check_programmatic_config(None, slice_, config_field="dmarc")
    assert out is not None
    assert out.dmarc.policy == policy
    assert out.dmarc.rua_required is rua


class TestGenerateBinder:
    def test_build_without_default_factory_requires_params(self) -> None:
        gen = GenerateBinder("dmarc").build()
        with pytest.raises(
            TypeError, match="missing required keyword argument 'params'"
        ):
            gen()
