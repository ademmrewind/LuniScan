from sqlalchemy import Column, MetaData, String, Table, select
from sqlalchemy.engine import Engine

metadata = MetaData()
app_metadata = Table(
    "app_metadata",
    metadata,
    Column("key", String, primary_key=True),
    Column("value", String, nullable=False),
)


def initialize_database(engine: Engine) -> None:
    metadata.create_all(engine)


def check_database(engine: Engine) -> None:
    with engine.connect() as connection:
        connection.execute(select(app_metadata.c.key).limit(1))
