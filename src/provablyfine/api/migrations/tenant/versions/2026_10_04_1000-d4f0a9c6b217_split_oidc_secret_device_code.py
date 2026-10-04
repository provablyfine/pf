"""split_oidc_secret_device_code

`oidc-device-code` now means a device code flow with no client_secret. Providers that
require client authentication in the device flow get the new `oidc-secret-device-code`
type instead.

The auth `config` column is encrypted with the KEK, so SQL alone cannot say which rows
carry a secret. `migrate.upgrade_tenant` hands the key to alembic as the `pf.kek` option.

Only rows that really carry a secret are renamed. Renaming is all this does. The config
blob is left exactly as it was, encrypted.

Revision ID: d4f0a9c6b217
Revises: 736d98eea63f
Create Date: 2026-10-04 10:00:00.000000

"""

import json

import alembic.context as context
import alembic.op as op
import cryptography.fernet
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "d4f0a9c6b217"
down_revision: str | None = "736d98eea63f"
branch_labels: str | None = None
depends_on: str | None = None

_OLD_TYPE = "oidc-device-code"
_NEW_TYPE = "oidc-secret-device-code"

_auth = sa.table(
    "auth",
    sa.column("id", sa.Integer),
    sa.column("type", sa.String),
    sa.column("config", sa.LargeBinary),
)


def _kek() -> cryptography.fernet.Fernet:
    """The key that decrypts auth configs. Fails loudly when the caller supplied none."""
    alembic_config = context.get_context().config
    key = alembic_config.get_main_option("pf.kek") if alembic_config is not None else None
    if key is None:
        raise RuntimeError("pf.kek is not set, so encrypted auth configs cannot be read")
    return cryptography.fernet.Fernet(key)


def _has_client_secret(kek: cryptography.fernet.Fernet, stored: bytes) -> bool:
    """Whether an encrypted auth config carries a non-empty client_secret."""
    config = json.loads(kek.decrypt(stored))
    return bool(config.get("client_secret"))


def upgrade() -> None:
    """Upgrade schema."""
    connection = op.get_bind()
    kek = _kek()
    rows = connection.execute(sa.select(_auth.c.id, _auth.c.config).where(_auth.c.type == _OLD_TYPE)).all()
    for row_id, stored in rows:
        if _has_client_secret(kek, bytes(stored)):
            connection.execute(sa.update(_auth).where(_auth.c.id == row_id).values(type=_NEW_TYPE))
