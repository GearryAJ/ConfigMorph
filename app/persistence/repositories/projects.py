from app.persistence.database import SessionLocal
from app.persistence.models import Project
from sqlalchemy import select

def create_project(project_key: str, source_vendor: str, target_vendor: str, source_path: str, issue_count: int) -> None:
    with SessionLocal.begin() as session:
        session.add(Project(project_key=project_key, source_vendor=source_vendor, target_vendor=target_vendor, source_path=source_path, issue_count=issue_count))

def get_project(project_key:str):
    with SessionLocal() as session:
        return session.scalar(select(Project).where(Project.project_key==project_key))