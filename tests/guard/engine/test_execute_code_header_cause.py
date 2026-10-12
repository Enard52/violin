"""A valid two-field execute_code header must explain why target resolution failed."""

from __future__ import annotations

import json
from pathlib import Path

from plugins.violin_guard.core.engagement import bootstrap
from plugins.violin_guard.engine import code_execution_audit
from tests.guard.receipt_fixture import bind_active_task


def _engagement_with_scope(tmp_path: Path, scope_text: str) -> Path:
    eng = tmp_path / "engagement"
    assert bootstrap.init_engagement(eng, host="10.0.2.2") == 0
    (eng / "scope" / "scope.yaml").write_text(scope_text, encoding="utf-8")
    (eng / "state" / ".skill-loaded-test").write_text("skill-loaded: test\n", encoding="utf-8")
    ptt = eng / "state" / "ptt.md"
    ptt.write_text(
        ptt.read_text(encoding="utf-8").replace("| PT-010 | [ ] |", "| PT-010 | [~] |"),
        encoding="utf-8",
    )
    bind_active_task(eng, "test")
    return eng


def _header(eng: Path) -> str:
    return '# violin: {"eng_dir":"' + str(eng).replace("\\", "\\\\") + '","phase":"RECON"}\n'


def test_unresolvable_scope_reports_the_real_cause(tmp_path: Path) -> None:
    eng = _engagement_with_scope(
        tmp_path,
        "targets:\n  cidrs: []\n  ip_addresses: []\nexclusions: {}\n",
    )

    metadata, error = code_execution_audit.parse_metadata(_header(eng) + "print(1)\n")

    assert metadata is None
    assert "no single declared target" in error
    assert "first-line metadata" in error


def test_valid_cidr_scope_parses_the_documented_header(tmp_path: Path) -> None:
    eng = _engagement_with_scope(
        tmp_path,
        "targets:\n  cidrs: [10.0.2.0/24]\nexclusions: {}\n",
    )

    metadata, error = code_execution_audit.parse_metadata(_header(eng) + "print(1)\n")

    assert error is None, error
    assert metadata is not None
    assert metadata["eng_dir"] == str(eng)
    assert metadata["phase"] == "RECON"
    assert metadata["target"] == "10.0.2.0/24"
    assert json.dumps(metadata)


def _bootstrap_engagement(tmp_path: Path) -> Path:
    """Create an engagement with the bootstrap's complete scope and an active task."""
    eng = tmp_path / "engagement"
    assert bootstrap.init_engagement(eng, host="10.0.2.2") == 0
    (eng / "state" / ".skill-loaded-test").write_text("skill-loaded: test\n", encoding="utf-8")
    ptt = eng / "state" / "ptt.md"
    ptt.write_text(
        ptt.read_text(encoding="utf-8").replace("| PT-010 | [ ] |", "| PT-010 | [~] |"),
        encoding="utf-8",
    )
    bind_active_task(eng, "test")
    return eng


def _scope_with_targets(eng: Path, targets_block: dict, exclusions: dict | None = None) -> None:
    """Overlay targets on the bootstrap scope so every gate-required section is present."""
    import yaml

    scope_path = eng / "scope" / "scope.yaml"
    data = yaml.safe_load(scope_path.read_text(encoding="utf-8"))
    data["targets"] = targets_block
    data["exclusions"] = exclusions or {}
    data["authorisation"] = {
        "confirmed": True,
        "confirmed_by": "test",
        "confirmed_at": "2026-10-12",
    }
    data.setdefault("rules_of_engagement", {})["allowed_actions"] = ["RECON"]
    scope_path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def _code_probing(eng: Path, host: str) -> str:
    return _header(eng) + f"import requests\nprint(requests.get('http://{host}/').status_code)\n"


def test_execute_code_allows_a_host_inside_a_declared_cidr(tmp_path: Path) -> None:
    eng = _bootstrap_engagement(tmp_path)
    _scope_with_targets(eng, {"cidrs": ["10.0.2.0/24"]})

    metadata, error = code_execution_audit.validate_source(_code_probing(eng, "10.0.2.2"))

    assert error is None, error
    assert metadata is not None


def test_execute_code_rejects_a_host_outside_the_cidr(tmp_path: Path) -> None:
    eng = _bootstrap_engagement(tmp_path)
    _scope_with_targets(eng, {"cidrs": ["10.0.2.0/24"]})

    metadata, error = code_execution_audit.validate_source(_code_probing(eng, "10.0.3.2"))

    assert metadata is None
    assert "10.0.3.2" in (error or "")


def test_execute_code_rejects_an_excluded_host_inside_the_cidr(tmp_path: Path) -> None:
    eng = _bootstrap_engagement(tmp_path)
    _scope_with_targets(eng, {"cidrs": ["10.0.2.0/24"]}, {"cidrs": ["10.0.2.128/25"]})

    metadata, error = code_execution_audit.validate_source(_code_probing(eng, "10.0.2.200"))

    assert metadata is None
    assert "10.0.2.200" in (error or "")
