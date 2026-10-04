"""Regression: request fields must not be able to inject commands into staged configuration."""

import pytest
from conftest import make_cr

from rulegate.pipeline import build_context, read_request_file
from rulegate.render import render


@pytest.mark.parametrize("field,value", [
    ("source_zone", "web-dmz ]\ndelete rulebase"),
    ("destination_zone", "db-trust; commit"),
    ("application", 'postgres" force'),
    ("source", "10.0.0.1 ] action allow"),
    ("destination", "any\nset deviceconfig"),
    ("service", "tcp/22 ]"),
    ("service", "tcp/99999"),
    ("users", "corp\\a b"),
    ("security_profile_group", "Strict ] action allow"),
    ("intrusion_policy", 'IPS"}, "action": "TRUST'),
    ("placement", "before:Rule One"),
    ("placement", "before:x\nmove"),
])
def test_command_injection_rejected(field, value):
    with pytest.raises(ValueError):
        make_cr("panos" if field != "intrusion_policy" else "ftd", **{field: value})


@pytest.mark.parametrize("field,value", [
    ("ticket_ref", 'CHG1" ; delete'),
    ("requester", "app-team\nset rulebase security rules evil action allow"),
    ("requester", 'team"quote'),
])
def test_metadata_injection_rejected(field, value):
    with pytest.raises(ValueError):
        make_cr("panos", **{field: value})


def test_justification_is_flattened_to_one_line():
    cr = make_cr("panos", business_justification="line one\nset rulebase evil | x")
    assert "\n" not in cr.business_justification and "|" not in cr.business_justification


def test_application_default_cannot_be_mixed():
    with pytest.raises(ValueError):
        make_cr("panos", service=["application-default", "tcp/22"])


def test_valid_inputs_still_accepted():
    cr = make_cr("panos", source=["10.0.0.1-10.0.0.9", "web-servers", "2001:db8::/64"], users=["corp\\jdoe"],
                 placement="before:Allow-Web-to-App", service=["tcp/80,8080", "udp/1000-2000", "icmp"])
    assert cr.request.placement == "before:Allow-Web-to-App"


@pytest.mark.parametrize("sample", ["cr-1001-panos-web-to-db.yaml", "cr-1003-panos-any-any.yaml",
                                    "cr-1005-panos-telnet-untrust.yaml"])
def test_staged_panos_config_only_contains_expected_statements(sample):
    staged = render(build_context(read_request_file(f"samples/change_requests/{sample}")))
    for line in staged.config.splitlines():
        assert line == "" or line.startswith(("#", "set ", "move ")), line


def test_unknown_fields_are_rejected():
    from rulegate.models.change_request import NormalizedChangeRequest

    data = make_cr("panos").model_dump(mode="json")
    data["request"]["securty_profile_group"] = "Strict-Inspection"  # typo must not be silently ignored
    with pytest.raises(ValueError):
        NormalizedChangeRequest.model_validate(data)
