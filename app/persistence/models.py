from datetime import datetime
from sqlalchemy import DateTime, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column
from .database import Base

class Project(Base):
    __tablename__ = "projects"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_key: Mapped[str] = mapped_column(String(36), unique=True)
    source_vendor: Mapped[str] = mapped_column(String(32))
    target_vendor: Mapped[str] = mapped_column(String(32))
    source_path: Mapped[str] = mapped_column(String(255))
    issue_count: Mapped[int] = mapped_column(default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
