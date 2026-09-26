"""`rotate_oidc` keeps a tenant's OIDC signing key topped up, the same way `rotate` does for SSH."""

import datetime

from . import app_db, model, rotate


def _identity() -> None:
    model.identity.create(name="root", boundary_id_list=[], tag_id_list=[])


def test_rotate_oidc_does_nothing_before_any_identity_exists(tenant_app_db: app_db.AppDb) -> None:
    rotate.rotate_oidc(rotation_period=100, staging_period=10)

    assert tenant_app_db.oidc_key.read_all() == []


def test_rotate_oidc_creates_current_and_staged_keys_when_missing(tenant_app_db: app_db.AppDb) -> None:
    _identity()

    rotate.rotate_oidc(rotation_period=100, staging_period=10)

    rows = sorted(tenant_app_db.oidc_key.read_all(), key=lambda r: r.valid_after)
    assert len(rows) == 2
    current, staged = rows
    assert current.valid_before == staged.valid_after + 10
    assert staged.valid_before - staged.valid_after == 100
    assert current.valid_before - current.valid_after == 100


def test_rotate_oidc_is_a_noop_when_current_and_staged_already_exist(tenant_app_db: app_db.AppDb) -> None:
    _identity()
    rotate.rotate_oidc(rotation_period=100, staging_period=10)
    before = sorted(r.id for r in tenant_app_db.oidc_key.read_all())

    rotate.rotate_oidc(rotation_period=100, staging_period=10)

    after = sorted(r.id for r in tenant_app_db.oidc_key.read_all())
    assert after == before


def test_rotate_oidc_creates_only_the_missing_one(tenant_app_db: app_db.AppDb) -> None:
    _identity()
    now = int(datetime.datetime.now().timestamp())
    rotation_period = 100
    staging_period = 10
    # Already past the staging cutoff, not yet expired: a "current" key, no staged one.
    current_valid_after = now - staging_period - 5
    current_valid_before = current_valid_after + rotation_period
    model.oidc_key.create(valid_after=current_valid_after, valid_before=current_valid_before)

    rotate.rotate_oidc(rotation_period=rotation_period, staging_period=staging_period)

    rows = tenant_app_db.oidc_key.read_all()
    assert len(rows) == 2
    assert any(r.valid_after == current_valid_after and r.valid_before == current_valid_before for r in rows)
