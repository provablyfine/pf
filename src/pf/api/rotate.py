import argparse
import datetime
import logging

import cryptography.fernet
import sqlalchemy

from .. import base64url, jwk
from .. import log
from . import config, dao_factory, db, model, tenant_db
from .context import ctx

logger = logging.getLogger(__name__)


def rotate(key_type: db.SigningKeyType, crypto_key_type: jwk.KeyType, rotation_period: int, staging_period: int):
    one = ctx.db.identity.read_one()
    if one is None:
        return
    logger.info(f"rotate {key_type.name}")
    now = int(datetime.datetime.now().timestamp())
    keys = model.signing_key.read_all(
        ctx.db.signing_key.columns.valid_after >= now - rotation_period,
        type=key_type,
    )
    current = [k for k in keys if k.valid_after <= (now - staging_period) and k.valid_before > now]
    staged = [k for k in keys if k.valid_after > (now - staging_period)]
    if len(current) == 0:
        logger.error(f"create current key {crypto_key_type.name} rotation={rotation_period} staging={staging_period}")
        # This case should really never happen if rotation has happened ok
        current_start = now - staging_period - 10
        current_end = current_start + rotation_period
        model.signing_key.create(key_type, crypto_key_type, valid_after=current_start, valid_before=current_end)
    else:
        current_end = current[0].valid_before
    if len(staged) == 0:
        logger.info(f"create staged key {crypto_key_type.name} rotation={rotation_period} staging={staging_period}")
        staged_start = current_end - staging_period
        staged_end = staged_start + rotation_period
        model.signing_key.create(key_type, crypto_key_type, staged_start, staged_end)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--config", help="Configuration file", required=True)
    parser.add_argument("--log-filename", default=None)
    args = parser.parse_args()

    conf = config.Config.load(args.config)

    match conf.log_level:
        case "DEBUG":
            level = logging.DEBUG
        case "INFO":
            level = logging.INFO
        case "WARNING":
            level = logging.WARN
        case "ERROR":
            level = logging.ERROR
        case _:
            assert False
    log.setup_server("rotate", level, args.log_filename)

    with open(conf.kek_filename, "rb") as f:
        kek_string = base64url.encode(f.read()) + "======"
        kek = cryptography.fernet.Fernet(kek_string)

    def _rotate_one(database_url: str):
        engine = sqlalchemy.create_engine(database_url)
        with engine.begin() as connection:
            dao = dao_factory.create(connection, db.metadata)
            with ctx.set_db(dao), ctx.set_kek(kek):
                rotate(
                    db.SigningKeyType.HOST,
                    jwk.KeyType.from_string(conf.host_key_type),
                    conf.host_key_rotation_period,
                    conf.host_key_staging_period,
                )
                rotate(
                    db.SigningKeyType.USER,
                    jwk.KeyType.from_string(conf.user_key_type),
                    conf.user_key_rotation_period,
                    conf.user_key_staging_period,
                )

    registry_engine = sqlalchemy.create_engine(conf.tenant_registry_url)
    with registry_engine.connect() as registry_conn:
        registry_dao = dao_factory.create(registry_conn, tenant_db.tenant_metadata)
        for tenant_row in registry_dao.tenant.read_all():
            if tenant_row.is_enabled and tenant_row.is_initialized:
                _rotate_one(tenant_row.database_url)
