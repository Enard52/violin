"""Hypothesis tracking handlers."""

from __future__ import annotations

from ..core.commands.targets import _host_in_scope_data, normalize_target, scope_hosts
from ..core.engagement import hypotheses, state
from ..gates.scope_gate import load_scope
from .base import _eng_path, _json, _serialize_errors


def _scope_hosts(eng_dir: str, target: str) -> set[str] | None:
    """Return canonical scope hosts, requiring a valid scope for targeted records.

    A targeted hypothesis may name a host that is covered only by a CIDR or
    range; that host is added to the set so the membership check accepts it.
    """
    scope_path = _eng_path(eng_dir) / "scope" / "scope.yaml"
    if not scope_path.exists():
        if target.strip():
            raise ValueError("targeted hypotheses require a valid scope/scope.yaml")
        return None
    scope = load_scope(scope_path)
    hosts = scope_hosts(scope)
    normalized = normalize_target(target) if target.strip() else ""
    if normalized and _host_in_scope_data(scope, normalized):
        hosts.add(normalized)
    return hosts


@_serialize_errors
def handle_record_hypothesis(args, **kwargs):
    eng_dir = args["eng_dir"]
    fields = {k: v for k, v in args.items() if k != "eng_dir"}
    in_scope = _scope_hosts(eng_dir, str(fields.get("target") or ""))
    with state.workflow_lock(eng_dir):
        requested_id = str(fields.get("id") or "").strip()
        existing = {
            hypothesis.id
            for hypothesis in hypotheses.parse_hypotheses(_eng_path(eng_dir) / "hypotheses.md")
        }
        hypothesis_record = hypotheses.update_hypothesis(
            _eng_path(eng_dir) / "hypotheses.md", in_scope_hosts=in_scope, **fields
        )
        if (
            fields.get("cve_research")
            or fields.get("exploit_research")
            or fields.get("research_attempted")
        ):
            state.record_research_attempt(eng_dir, "hypothesis_research", True)
    operation = "updated" if requested_id and hypothesis_record.id in existing else "created"
    return _json("ok", operation=operation, hypothesis=hypothesis_record.to_dict())
