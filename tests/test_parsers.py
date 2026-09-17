from pathlib import Path
import pytest
from app.core.models import Vendor
from app.core.parsing import detect_vendor, parse_config

@pytest.mark.parametrize("vendor,path", [(Vendor.ASA,"examples/asa/basic.cfg"),(Vendor.FORTIGATE,"examples/fortigate/basic.conf"),(Vendor.PALO_ALTO,"examples/paloalto/basic.xml")])
def test_examples(vendor, path):
    text = Path(path).read_text()
    assert detect_vendor(text).vendor == vendor
    cfg = parse_config(text, vendor)
    assert cfg.addresses and cfg.address_groups and cfg.services and cfg.security_policies

def test_pan_rejects_doctype():
    cfg = parse_config('<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><config>&e;</config>', Vendor.PALO_ALTO)
    assert cfg.warnings and cfg.warnings[0].severity == "ERROR"
