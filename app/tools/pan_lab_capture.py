import argparse
import json
import os
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from urllib.parse import urlsplit


class Capture(StrEnum):
    ADDRESS = "address"
    ADDRESS_GROUP = "address-group"
    SERVICE = "service"
    SERVICE_GROUP = "service-group"
    SECURITY_RULE = "security-rule"
    STATIC_ROUTE = "static-route"
    LIST_SEMANTICS = "list-semantics"


def _enabled(name: str) -> bool:
    return os.getenv(name, "").lower() == "true"


def prepare(capture: Capture, host: str, ca_bundle: Path, output: Path) -> Path:
    required = (
        "FCS_PAN_LAB_VALIDATION_ENABLED",
        "FCS_PAN_LAB_ISOLATED",
        "FCS_PAN_LAB_EVIDENCE_CAPTURE",
    )
    if not all(_enabled(name) for name in required):
        raise ValueError("all three PAN lab opt-ins must be true")
    parsed = urlsplit(host)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("host must be an HTTPS origin")
    if not ca_bundle.is_file():
        raise ValueError("CA bundle must be an existing file")
    destination = output / "normalized" / f"{capture.value}.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "panos_version": None,
        "device_model": None,
        "management_mode": "LOCAL_FIREWALL",
        "vsys": None,
        "capability": capture.value,
        "capture_method": None,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "xpath": None,
        "element_xml": None,
        "action": "set",
        "result": "UNVERIFIED",
        "confidence": "UNVERIFIED",
        "notes": "Complete from sanitized API Browser or debug CLI output; retain raw capture separately.",
        "sanitized": False,
    }
    destination.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    (output / "raw").mkdir(exist_ok=True)
    return destination


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare one local PAN-OS 11.1 evidence record; performs no network requests.")
    parser.add_argument("--capture", required=True, choices=Capture)
    parser.add_argument("--host", required=True)
    parser.add_argument("--ca-bundle", required=True, type=Path)
    args = parser.parse_args()
    print(prepare(args.capture, args.host, args.ca_bundle, Path("evidence/pan11_1_lab")))


if __name__ == "__main__":
    main()