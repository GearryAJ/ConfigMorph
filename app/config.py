from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="FCS_")
    data_dir: Path = Path("data")
    workspace_dir: Path = Path("workspace")
    max_input_bytes: int = 5 * 1024 * 1024
    pan_lab_validation_enabled: bool = False
    pan_lab_host: str|None = None
    pan_lab_host_allowlist: str = ""
    pan_lab_ca_bundle: Path|None = None

    @property
    def database_url(self) -> str:
        return f"sqlite:///{self.data_dir / 'studio.db'}"


settings = Settings()