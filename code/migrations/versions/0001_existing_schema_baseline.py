"""Baseline the schema originally created by SQLAlchemy.

Revision ID: 0001_baseline
Revises:
"""

revision = "0001_baseline"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Existing installations already have these tables through Base.metadata.create_all.
    pass


def downgrade() -> None:
    # A baseline must never drop an existing user's assessment database.
    pass
