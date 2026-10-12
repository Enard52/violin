"""Host-level target resolution must honour CIDR scope members."""

from __future__ import annotations

import pytest

from plugins.violin_guard.core.commands import targets


def test_cidr_member_host_resolves_for_host_query() -> None:
    scope = {"targets": {"cidrs": ["10.0.2.0/24"]}}

    assert targets.resolve_target(scope, None, "10.0.2.2", field="ip") == "10.0.2.2"


def test_cidr_member_host_resolves_when_scope_lists_it_as_ip_address() -> None:
    scope = {"targets": {"ip_addresses": ["10.0.2.2"]}}

    assert targets.resolve_target(scope, None, "10.0.2.2", field="ip") == "10.0.2.2"


def test_address_outside_cidr_is_still_rejected() -> None:
    scope = {"targets": {"cidrs": ["10.0.2.0/24"]}}

    with pytest.raises(ValueError, match="not present in scope.yaml"):
        targets.resolve_target(scope, None, "10.0.3.2", field="ip")


def test_excluded_cidr_member_is_rejected_by_command_scope(tmp_path) -> None:
    scope_file = tmp_path / "scope.yaml"
    scope_file.write_text(
        "targets:\n  cidrs: [10.0.2.0/24]\nexclusions:\n  cidrs: [10.0.2.128/25]\n",
        encoding="utf-8",
    )

    allowed = targets.check_scope_targets(scope_file, "curl http://10.0.2.2")
    excluded = targets.check_scope_targets(scope_file, "curl http://10.0.2.200")

    assert not allowed.errors
    assert any("excluded target" in error for error in excluded.errors)


def test_hostname_and_wildcard_scope_resolution_is_unchanged() -> None:
    scope = {"targets": {"domains": ["*.example.test", "app.example.test"]}}

    assert targets.resolve_target(scope, None, "app.example.test", field="host") == (
        "app.example.test"
    )
    assert targets.resolve_target(scope, None, "api.example.test", field="host") == (
        "api.example.test"
    )


def test_plain_ip_covered_by_listed_cidr_is_still_the_single_target() -> None:
    scope = {"targets": {"ip_addresses": ["10.0.2.2"], "cidrs": ["10.0.2.0/24"]}}

    assert targets.resolve_target(scope, None, None) == "10.0.2.2"


def test_disjoint_cidr_with_plain_ip_is_ambiguous_not_silently_chosen() -> None:
    scope = {"targets": {"ip_addresses": ["10.0.2.2"], "cidrs": ["10.0.3.0/24"]}}

    with pytest.raises(ValueError, match="multiple targets"):
        targets.resolve_target(scope, None, None)
