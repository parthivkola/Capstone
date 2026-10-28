"""Smoke tests for Stage 1 configuration contracts."""

from pytest import MonkeyPatch

from src.sdn_defense.settings import load_settings


def test_default_settings_disable_live_network_and_mitigation(
    monkeypatch: MonkeyPatch,
) -> None:
    """Safety-sensitive runtime features are opt-in."""

    monkeypatch.delenv("SDN_DEFENSE_ENABLE_LIVE_NETWORK", raising=False)
    monkeypatch.delenv("SDN_DEFENSE_ENABLE_MITIGATION", raising=False)

    settings = load_settings()

    assert settings.enable_live_network is False
    assert settings.enable_mitigation is False


def test_seed_is_configurable(monkeypatch: MonkeyPatch) -> None:
    """A deterministic seed can be supplied through configuration."""

    monkeypatch.setenv("SDN_DEFENSE_SEED", "7")

    assert load_settings().seed == 7
