import json
from functools import lru_cache
from pathlib import Path

from pydantic import BaseModel, Field

from .models import HardwareModel, ReferenceStatus


CATALOG_PATH = Path(__file__).resolve().parents[3] / "references" / "palo_alto_ngfw_hardware_database.json"

SERIES_DOCUMENTATION = {
    "PA-3400": ["PAN-HW-PA3400-FRONT-PANEL"],
    "PA-5500": ["PAN-HW-PA5500-COMPONENTS", "PAN-HW-PA5500-SUPPORTED-PANOS"],
}


class HardwareCatalog(BaseModel):
    vendor: str
    product_family: str
    interface_count_definition: str
    models: list[HardwareModel] = Field(default_factory=list)

    def find(self, model: str) -> HardwareModel:
        match = next((item for item in self.models if item.model.casefold() == model.casefold()), None)
        if match is None:
            raise ValueError(f"Unknown Palo Alto hardware model: {model}")
        return match


@lru_cache(maxsize=1)
def load_hardware_catalog() -> HardwareCatalog:
    data = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
    models = []
    for item in data.get("models", []):
        refs = SERIES_DOCUMENTATION.get(item.get("series", ""), [])
        models.append(
            HardwareModel(
                **item,
                documentation_refs=refs,
                reference_status=(
                    ReferenceStatus.OFFICIAL if refs else ReferenceStatus.LOCAL_REFERENCE_ONLY
                ),
            )
        )
    if not models:
        raise ValueError("Palo Alto hardware catalog contains no models")
    return HardwareCatalog(
        vendor=data["vendor"],
        product_family=data["product_family"],
        interface_count_definition=data["interface_count_definition"],
        models=sorted(models, key=lambda item: (item.series.casefold(), item.model.casefold())),
    )
