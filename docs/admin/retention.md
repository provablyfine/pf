# Retention

Activity records are deleted after a retention period.
You choose the period for each tenant.
Deleted records cannot be recovered.

## What is deleted

There are two periods.

`audit_retention_days` applies to changes to the configuration.
Examples are the creation of a role or the change of a grant list.
The names that deleted objects had are removed with their entries.

`activity_retention_days` applies to logins, rejected requests, certificates and connections.
Ended live sessions are removed with it.

The configuration itself is not activity.
Identities, roles, boundaries, tags, bastions and authentication settings stay until you delete them.

Entries about retention are never deleted.
They hold the old and new values and who made the change.
They hold no personal data.
Each purge that deleted something also writes one of these entries, with the cutoffs and the counts.

## Change the periods

```bash
pfa tenant update -i 1 --audit-retention-days 90 --activity-retention-days 30
```

The server refuses a period outside its limits.
The limits are 30 to 365 days by default.
The operator sets them with `retention_min_days` and `retention_max_days` in the server configuration.

A new tenant starts with 365 days, or with `retention_max_days` if that is lower.

The change is not applied at once.
Records are deleted the next time the purge job runs.
Making a period longer does not bring back records that were already deleted.

You need the matching update permission on the tenant grant.
There is one for each of `audit_retention_days`, `activity_retention_days` and `retention_purge_enabled`.
Grants written before these existed do not have them.

## Stop deleting during an investigation

```bash
pfa tenant update -i 1 --disable-purge
pfa tenant update -i 1 --enable-purge
```

While purge is disabled, nothing is deleted for this tenant.
When you enable it again, everything past the cutoff is deleted at the next run.

To stop deleting for every tenant, stop running the purge job.

## Run the purge job

Deletion is done by `pf-api-purge`.
It is not part of the API server, so you must schedule it.

```bash
pf-api-purge -c /etc/pf/pf-server.yaml
```

Run it once an hour.
Every tenant is then purged well within 24 hours of the end of its period.
The job works in small transactions, so a large backlog does not block the server.

## Backups

The guarantees apply to the live database.
Backups are not changed.
Records deleted here remain in older backups until those backups expire.
Set the backup expiry to match the longest retention you promise.
