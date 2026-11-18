import collections.abc
import time
import typing

import jwt
import pytest

from .. import jwk
from . import app_db, config, model
from .context import ctx

TENANT_UUID = "11111111-2222-3333-4444-555555555555"


@pytest.fixture
def identity_id(tenant_app_db: app_db.AppDb) -> collections.abc.Iterator[int]:
    now = int(time.time())
    created = model.identity.create(name="root", boundary_id_list=[], tag_id_list=[])
    model.oidc_key.create(now - 10, now + 3600)
    with ctx.set_config(config.Config()), ctx.set_tenant_uuid(TENANT_UUID), ctx.set_identity_id(created):
        yield created


def _forge(signer: jwk.Private | None = None, **overrides: typing.Any) -> str:
    key = model.oidc_key.get_private_key()
    claims: dict[str, typing.Any] = {
        "sub": "1",
        "iss": f"{ctx.config.base_url}/pf/t/{TENANT_UUID}/public/oidc",
        "aud": f"host-{model.bastion._tenant_label()}",
        "iat": int(time.time()),
        "exp": int(time.time()) + 60,
        "jti": "j",
        "use": "connect",
        "cid": "cid",
    }
    for name, value in overrides.items():
        if value is None:
            del claims[name]
        else:
            claims[name] = value
    signing_key = key if signer is None else signer
    return jwt.encode(
        claims, signing_key.to_crypto(), algorithm="EdDSA", headers={"kid": overrides.get("kid", key.thumbprint())}
    )


def test_a_well_formed_connect_token_is_accepted(identity_id: int) -> None:
    claims = model.bastion.verify_connect_token(_forge(sub=str(identity_id), cid="abc"))

    assert claims is not None
    assert claims.identity_id == identity_id
    assert claims.connection_id == "abc"
    assert claims.audience == f"host-{model.bastion._tenant_label()}"


@pytest.mark.parametrize(
    "overrides",
    [
        {"use": "register"},
        {"use": "terminate"},
        {"use": None},
        {"cid": None},
        {"exp": 1},
        {"exp": None},
        {"iss": "http://127.0.0.1:8000/pf/t/other/public/oidc"},
        {"aud": "host-000000000000"},
        {"aud": None},
        {"sub": "not-a-number"},
        {"sub": None},
    ],
    ids=lambda overrides: ",".join(f"{k}={v}" for k, v in overrides.items()),
)
def test_a_token_with_a_bad_claim_is_refused(identity_id: int, overrides: dict[str, typing.Any]) -> None:
    assert model.bastion.verify_connect_token(_forge(**overrides)) is None


def test_a_token_signed_by_another_key_is_refused(identity_id: int) -> None:
    assert model.bastion.verify_connect_token(_forge(signer=jwk.Private.generate_ed25519())) is None


def test_a_token_with_an_unknown_key_id_is_refused(identity_id: int) -> None:
    assert model.bastion.verify_connect_token(_forge(kid="unknown")) is None


@pytest.mark.parametrize("token", ["", "not-a-jwt", "a.b.c", "x" * 10_000])
def test_garbage_is_refused(identity_id: int, token: str) -> None:
    assert model.bastion.verify_connect_token(token) is None
