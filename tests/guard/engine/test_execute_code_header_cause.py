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
