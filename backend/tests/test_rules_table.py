"""The shipped rules table: it loads, it is consistent, and it holds the weights we publish."""

import re

import pytest
from pydantic import ValidationError

from app.rules.engine import INPUT_KINDS, RulesTable, load_table

T = load_table()


def minimal(**check) -> dict:
    return {
        "version": 1,
        "thresholds": {"red": 50, "yellow": 20, "min_coverage": 0.6},
        "max_negative_points": 20,
        "messages": {"red": "r", "yellow": "y", "green": "g"},
        "checks": {"A1_x": {"layer": "static", "title": "t", "needs": ["repo"], **check}},
    }


def test_loads_with_sane_thresholds():
    assert T.version == 1
    assert 0 < T.thresholds.yellow < T.thresholds.red
    assert 0 < T.thresholds.min_coverage <= 1


def test_published_numbers():
    th = T.thresholds
    assert (th.red, th.yellow, th.min_coverage, T.max_negative_points) == (50, 20, 0.6, 20)
    points = {cid: c.points for cid, c in T.checks.items()}
    assert points["C1_claimed_age_contradiction"] == 25
    assert points["C4_off_official_domain"] == 25
    assert points["P8_new_domains_in_repo_config"] == 20
    assert points["T3_work_computer_or_admin"] == 20
    assert points["C5_job_not_on_official_board"] == 15


def test_hard_triggers():
    hard = {cid.split("_")[0] for cid, c in T.checks.items() if c.hard}
    assert hard == {"H1", "H2", "H3", "H4", "H5", "H6", "S3", "S7", "S8", "D1", "D2", "D3", "D4", "D5"}


def test_ids_and_layers():
    layer_of = {"S": "static", "D": "decoy"}
    for cid, c in T.checks.items():
        assert re.fullmatch(r"[A-Z]\d+_[a-z0-9_]+", cid), cid
        assert c.layer == layer_of.get(cid[0], "sender"), cid
        assert c.title.strip(), cid


def test_needs_are_known_inputs():
    for cid, c in T.checks.items():
        for need in c.needs:
            for kind in [need] if isinstance(need, str) else need:
                assert kind in INPUT_KINDS, (cid, kind)


def test_messages_for_every_color():
    assert set(T.messages) == {"red", "yellow", "green"}


def test_duplicate_keys_are_rejected(tmp_path):
    path = tmp_path / "rules.yaml"
    path.write_text(
        "version: 1\n"
        "thresholds: {red: 50, yellow: 20, min_coverage: 0.6}\n"
        "max_negative_points: 20\n"
        "messages: {red: r, yellow: y, green: g}\n"
        "checks:\n"
        "  A1_x: {layer: static, title: t, needs: [repo], points: 5}\n"
        "  A1_x: {layer: static, title: t, needs: [repo], points: 50}\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="A1_x"):
        load_table(path)


@pytest.mark.parametrize("spec", [
    {"hard": True, "points": 10},
    {"points": 10, "bands": [[30, 5]]},
    {},
    {"points": 0},
    {"bands": [[180, 12], [30, 20]]},
    {"bands": []},
    {"points": 10, "pionts": 10},
    {"points": 10, "needs": ["telepathy"]},
    {"points": 10, "only_if_unknown": "Z9_missing"},
])
def test_bad_checks_are_rejected(spec):
    with pytest.raises(ValidationError):
        RulesTable.model_validate(minimal(**spec))


def test_bad_thresholds_are_rejected():
    bad = minimal(points=10)
    bad["thresholds"] = {"red": 20, "yellow": 50, "min_coverage": 0.6}
    with pytest.raises(ValidationError):
        RulesTable.model_validate(bad)


def test_missing_message_is_rejected():
    bad = minimal(points=10)
    del bad["messages"]["green"]
    with pytest.raises(ValidationError):
        RulesTable.model_validate(bad)
