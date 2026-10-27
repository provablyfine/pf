# Retention

Audit log records are deleted after a configurable per-tenant retention period.
Deleted records cannot be recovered.

## The deletion policy

There are two periods.

- `audit_retention_days` applies to changes to the configuration.
Examples are the creation, the update, or the deletion of a role.

- `activity_retention_days` applies to logins, rejected requests, certificates and connections.

We record in the audit log metadata (count, start and end date of
the entries that were deleted) about each data purge. These entries
are never deleted.

## Changing the deletion policy

```bash
pfa tenant update -i 1 --audit-retention-days 90 --activity-retention-days 30
```

The server refuses a period outside its limits. The limits are 30 to 365 days by default.
The server administrator sets them with `retention_min_days` and `retention_max_days` in the 
server configuration.

## When data is deleted

Data is deleted by `pf-api-purge`. It is generally scheduled once per hour
via systemd timer services.

Administrators of the server can run it manually:
```bash
pf-api-purge -c /etc/pf/pf-server.yaml
```

## Disable data deletion

Administrators can disable the `pf-api-purge` job to make sure no data is deleted
ever across all tenants.

The members of a tenant who have admin permissions over the tenant can disable
purges temporarily, during an investigation, for example:
```bash
pfa tenant update -i 1 --disable-purge
```

When they enable it again, everything past the cutoff is deleted at the next run.
```bash
pfa tenant update -i 1 --enable-purge
```
