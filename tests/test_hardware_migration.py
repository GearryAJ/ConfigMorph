from pathlib import Path

from fastapi.testclient import TestClient

from app.core.hardware_migration import HardwareMigrationAnalyzer, load_hardware_catalog
from app.core.models import Interface
from app.main import app


def interfaces(*names: str) -> list[Interface]:
    return [Interface(id=name, name=name) for name in names]


def test_catalog_loads_local_reference_and_official_series_refs():
    catalog = load_hardware_catalog()

    assert len(catalog.models) == 56
    assert catalog.find("pa-3440").model == "PA-3440"
    assert catalog.find("PA-5540").documentation_refs == [
        "PAN-HW-PA5500-COMPONENTS",
        "PAN-HW-PA5500-SUPPORTED-PANOS",
    ]


def test_preserves_valid_ports_and_counts_subinterfaces_once():
    plan = HardwareMigrationAnalyzer().analyze(
        interfaces("ethernet1/1", "ethernet1/28", "ethernet1/28.100"),
        "PA-3440",
        "PA-5540",
        "11.1",
        "12.1",
    )

    assert plan.status == "REVIEW_REQUIRED"
    assert plan.source_capacity.configured_physical_ports == 2
    assert plan.target_capacity.assigned_physical_ports == 2
    assert [(item.source_interface, item.target_interface) for item in plan.mappings] == [
        ("ethernet1/1", "ethernet1/1"),
        ("ethernet1/28", "ethernet1/28"),
        ("ethernet1/28.100", "ethernet1/28.100"),
    ]
    assert plan.version_status == "VERSION_NOT_VERIFIED"


def test_remaps_out_of_range_port_to_first_available_target_port():
    plan = HardwareMigrationAnalyzer().analyze(
        interfaces("ethernet1/1", "ethernet1/28"),
        "PA-3440",
        "PA-3410",
        "11.1",
        "11.1",
    )

    mapping = next(item for item in plan.mappings if item.source_interface == "ethernet1/28")
    assert mapping.target_interface == "ethernet1/2"
    assert mapping.status == "REMAPPED"
    assert "INTERFACE_RENUMBERING_REQUIRED" in {alert.code for alert in plan.alerts}


def test_target_shortfall_and_modular_capacity_are_blocking():
    fixed = HardwareMigrationAnalyzer().analyze(
        interfaces(*(f"ethernet1/{number}" for number in range(1, 24))),
        "PA-3440",
        "PA-3410",
        "11.1",
        "11.1",
    )
    modular = HardwareMigrationAnalyzer().analyze(
        interfaces("ethernet1/1"),
        "PA-3410",
        "PA-5450",
        "11.1",
        "11.1",
    )

    assert fixed.status == "BLOCKING"
    assert sum(item.target_interface is None for item in fixed.mappings) == 1
    assert "TARGET_CAPACITY_SHORTFALL" in {alert.code for alert in fixed.alerts}
    assert modular.status == "BLOCKING"
    assert "TARGET_CAPACITY_NOT_FIXED" in {alert.code for alert in modular.alerts}


def test_hardware_migration_api_builds_suggestions_and_rejects_unknown_port():
    client = TestClient(app)
    source = Path("examples/paloalto/basic.xml").read_text(encoding="utf-8")
    response = client.post(
        "/api/analyze",
        data={
            "source": source,
            "source_vendor": "paloalto",
            "source_version": "11.1",
            "source_hardware": "PA-3410",
            "target_vendor": "paloalto",
            "target_version": "12.1",
            "target_hardware": "PA-5540",
        },
    )

    assert response.status_code == 200
    project = response.text.split("Project: <code>")[1].split("<")[0]
    base = f"/api/projects/{project}/migration"
    plan = client.get(f"{base}/hardware-plan")
    assert plan.status_code == 200
    assert plan.json()["target_capacity"]["catalog_capacity"] == 36
    mappings = client.get(f"{base}/mappings").json()
    assert [item["target_interface"] for item in mappings["interfaces"]] == [
        "ethernet1/1",
        "ethernet1/2",
    ]

    mappings["interfaces"][0]["target_interface"] = "ethernet1/99"
    assert client.put(f"{base}/mappings", json=mappings).status_code == 422


def test_palo_alto_source_requires_both_hardware_models():
    client = TestClient(app)
    source = Path("examples/paloalto/basic.xml").read_text(encoding="utf-8")

    response = client.post(
        "/api/analyze",
        data={
            "source": source,
            "source_vendor": "paloalto",
            "source_version": "11.1",
            "target_vendor": "paloalto",
            "target_version": "12.1",
        },
    )

    assert response.status_code == 422


def test_hardware_controls_and_review_panel_are_rendered():
    response = TestClient(app).get("/")

    assert response.status_code == 200
    assert 'name="source_hardware"' in response.text
    assert 'name="target_hardware"' in response.text
    assert 'id="hardware-migration-panel"' in response.text
