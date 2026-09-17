import pytest
from app.core.models import Service, Vendor
from app.core.parsing import parse_config

@pytest.mark.parametrize("vendor",list(Vendor)[:3])
def test_empty_is_error(vendor):
    cfg=parse_config("",vendor)
    assert cfg.metadata["parser_metrics"]["errors"] == 1

def test_asa_invalid_cidr_recovers_and_preserves():
    cfg=parse_config("object network BAD\n subnet 10.0.0.0 bad-mask\nobject network GOOD\n host 10.0.0.1",Vendor.ASA)
    assert cfg.addresses[-1].value == "10.0.0.1" and cfg.unparsed_constructs

def test_forti_truncated_nested_and_bad_quote_recover():
    text='config firewall address\n edit "A"\n set subnet 10.0.0.1 255.255.255.255\n config unexpected nested\n set broken "quote\n'
    cfg=parse_config(text,Vendor.FORTIGATE)
    assert cfg.unparsed_constructs and cfg.metadata["parser_metrics"]["errors"] >= 1

def test_pan_malformed_xml_recovers():
    cfg=parse_config("<config><devices>",Vendor.PALO_ALTO)
    assert cfg.warnings[0].severity == "ERROR"

def test_duplicate_ids_warn():
    cfg=parse_config("object network A\n host 10.0.0.1\nobject network A\n host 10.0.0.2",Vendor.ASA)
    assert any(x.message == "Duplicate entity ID" for x in cfg.warnings)

def test_broken_reference_warns():
    cfg=parse_config("access-list x extended permit tcp object MISSING any eq 443",Vendor.ASA)
    assert any("Unresolved" in x.message for x in cfg.warnings)

def test_unknown_protocol_normalizes_conservatively():
    assert Service(id="x",name="x",protocol="vendor-x").protocol == "ip"

@pytest.mark.parametrize("payload",["x"*100_000,"object network café\n host 10.0.0.1","object network A\x00B\n host 10.0.0.1"],ids=["very-long-line","unicode","null-byte"])
def test_long_unicode_and_null_do_not_crash(payload):
    cfg=parse_config(payload,Vendor.ASA)
    assert cfg.metadata["parser_metrics"]