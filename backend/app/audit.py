from sqlalchemy import Column, DateTime, Integer, String, Table

from app.database import metadata

asset_events = Table(
    "asset_events",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("kind", String(24), nullable=False),
    Column("occurred_at", DateTime, nullable=False, index=True),
    Column("asset_id", Integer, nullable=False),
    Column("asset_name", String(100), nullable=False),
)
