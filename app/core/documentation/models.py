from datetime import date
from enum import StrEnum
from pydantic import BaseModel, HttpUrl
from app.core.models import Vendor

class DocumentType(StrEnum):
    CLI_REFERENCE="CLI_REFERENCE"; API_REFERENCE="API_REFERENCE"; CONFIGURATION_GUIDE="CONFIGURATION_GUIDE"; ADMIN_GUIDE="ADMIN_GUIDE"; RELEASE_NOTES="RELEASE_NOTES"; COMPATIBILITY_GUIDE="COMPATIBILITY_GUIDE"

class DocumentationReference(BaseModel):
    id:str; vendor:Vendor; product:str; version_family:str; document_type:DocumentType
    title:str; topic:str; official_url:HttpUrl; verified_at:date; notes:str=""