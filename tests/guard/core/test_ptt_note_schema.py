"""The violin_record_ptt schema must agree with the handler's note requirement."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from plugins.violin_guard.core import schemas


def test_schema_marks_lifecycle_note_required() -> None:
    schema = schemas.RECORD_PTT_SCHEMA
    properties = (
        schema["parameters"]["properties"] if "parameters" in schema else schema["properties"]
    )
    required = schema["parameters"]["required"] if "parameters" in schema else schema["required"]

    assert "note" in required
    assert properties["note"].get("description")


def test_model_rejects_a_blank_lifecycle_note() -> None:
    base = {"eng_dir": "eng", "id": "PT-001", "skill": "pentest", "technique": "recon"}

    with pytest.raises(ValidationError):
        schemas.RecordPttArgsModel.model_validate({**base})
    with pytest.raises(ValidationError):
        schemas.RecordPttArgsModel.model_validate({**base, "note": "   "})
