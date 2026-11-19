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
    additions = {
        "assets": {
            "group_name": "VARCHAR(60)",
            "tags": "JSON NOT NULL DEFAULT '[]'",
            "notes": "TEXT NOT NULL DEFAULT ''",
            "last_seen": "DATETIME",
        },
        "scan_results": {"duration_ms": "FLOAT"},
        "security_assessments": {"path": "VARCHAR(128) NOT NULL DEFAULT '/'"},
    }
    with engine.begin() as connection:
        connection.exec_driver_sql("BEGIN IMMEDIATE")
        for table, columns in additions.items():
            existing = {
                row[1]
                for row in connection.exec_driver_sql(f"PRAGMA table_info({table})")
            }
            if not existing:
                continue
            for name, definition in columns.items():
                if name not in existing:
                    connection.exec_driver_sql(
                        f"ALTER TABLE {table} ADD COLUMN {name} {definition}"
                    )
        connection.exec_driver_sql(
            "CREATE INDEX IF NOT EXISTS phase6_asset_group ON assets (group_name, id)"
        )


def check_database(engine: Engine) -> None:
    with engine.connect() as connection:
        connection.execute(select(app_metadata.c.key).limit(1))
