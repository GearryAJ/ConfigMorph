import json
from pathlib import Path
import pytest
from app.core.models import Vendor
from app.core.parsing import parse_config

CASES = [(Vendor.ASA,"asa","basic.cfg"),(Vendor.FORTIGATE,"fortigate","basic.conf"),(Vendor.PALO_ALTO,"paloalto","basic.xml")]

def semantics(cfg):
    return {
        "counts":{"addresses":len(cfg.addresses),"groups":len(cfg.address_groups)+len(cfg.service_groups),"services":len(cfg.services),"interfaces":len(cfg.interfaces),"zones":len(cfg.zones),"policies":len(cfg.security_policies),"nat":len(cfg.nat_policies),"routes":len(cfg.static_routes)},
        "interface_names":sorted(x.name for x in cfg.interfaces), "zone_names":sorted(x.name for x in cfg.zones),
        "address_names":sorted(x.name for x in cfg.addresses), "group_names":sorted(x.name for x in cfg.address_groups+cfg.service_groups),
        "service_names":sorted(x.name for x in cfg.services), "policy_actions":sorted(x.action for x in cfg.security_policies),
        "nat_types":sorted(x.type for x in cfg.nat_policies), "route_destinations":sorted(x.destination for x in cfg.static_routes),
    }

@pytest.mark.parametrize("vendor,directory,filename",CASES)
def test_golden_semantics(vendor,directory,filename):
    cfg=parse_config(Path(f"examples/{directory}/{filename}").read_text(),vendor)
    expected=json.loads(Path(f"tests/golden/{directory}/basic.normalized.json").read_text())
    assert semantics(cfg)==expected
    assert cfg.metadata["parser_metrics"]["parsed_entities"] == sum(expected["counts"].values())