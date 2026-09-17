"""projects metadata"""
from alembic import op
import sqlalchemy as sa
revision = "0001"
down_revision = None
def upgrade():
    op.create_table("projects", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("project_key", sa.String(36), nullable=False, unique=True), sa.Column("source_vendor", sa.String(32), nullable=False), sa.Column("target_vendor", sa.String(32), nullable=False), sa.Column("source_path", sa.String(255), nullable=False), sa.Column("issue_count", sa.Integer(), nullable=False), sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=False))
def downgrade(): op.drop_table("projects")
