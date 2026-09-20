Initialize root tenant and login
  $ bash $TESTDIR/fixture.sh
  .* (re)

Only one context exists after initialize+login: "root", marked current
  $ pf -c config.json ctx list | grep -c '^\*'
  1
  $ pf -c config.json ctx list | grep '^\*'
  .*root.*root.*directory (re)

Root sees only itself in the tenant list
  $ pfa -c config.json tenant list -q
  1

Create and bootstrap a second tenant "acme" into the SAME registry file --
no --name flag exists, so it lands under its auto-derived name ("acme",
from the tenant name in its directory) and becomes current.
  $ pfa -c config.json tenant create --name acme --display-name "Acme Corp"
  .* (re)
  .* (re)
  .* (re)
  $ ssh-keygen -t ed25519 -f acme-account -N "" > /dev/null
  $ ACME_UUID=$(pfa -c config.json tenant get -i 2 | awk 'NR==3{print $2}')
  $ pfa -c config.json initialize http://127.0.0.1:$API_PORT/pf/t/$ACME_UUID/directory --key acme-account
  $ ssh-keygen -t ed25519 -f acme-session -N "" > /dev/null
  $ pfa -c config.json login --session-key acme-session

Both contexts now exist in the one file; "acme" is current
  $ pf -c config.json ctx list | grep -c '^\*'
  1
  $ pf -c config.json ctx list | grep '^\*'
  .*acme.*acme.*directory (re)
  $ pf -c config.json ctx list | grep -w acme > /dev/null
  $ pf -c config.json ctx list | grep -w root > /dev/null

A second context for a directory URL that already has one is refused before
the server is contacted, so the invitation is not spent
  $ pfa -c config.json initialize http://127.0.0.1:$API_PORT/pf/t/$ACME_UUID/directory --key acme-account
  Context 'acme' already targets http://127.0.0.1:\d+/pf/t/[0-9a-f-]+/directory\. Use it \(ctx use acme\) or delete it first \(ctx delete acme\)\. (re)
  [2]

Commands against config.json now act as acme -- sees only itself, no -c change needed
  $ pfa -c config.json tenant list -q
  2

Switch back to root without touching -c
  $ pf -c config.json ctx use root
  $ pf -c config.json ctx list | grep '^\*'
  .*root.*root.*directory (re)

Commands now act as root again: sees both tenants
  $ pfa -c config.json tenant list -q
  1
  2

"-" switches to the previously-selected context (acme)
  $ pf -c config.json ctx use -
  $ pfa -c config.json tenant list -q
  2

"-" again swaps back to root
  $ pf -c config.json ctx use -
  $ pfa -c config.json tenant list -q
  1
  2

Rename the current context
  $ pf -c config.json ctx rename root --to=root-renamed
  $ pf -c config.json ctx list | grep '^\*'
  .*root-renamed.*root.*directory (re)
  $ pf -c config.json ctx list | grep -w root$
  [1]

Switching by the old, now-gone name fails with a friendly error
  $ pf -c config.json ctx use root
  No such context: 'root'. Available: acme, root-renamed
  [2]

Switching to a context that was never created also fails
  $ pf -c config.json ctx use does-not-exist
  No such context: 'does-not-exist'. Available: acme, root-renamed
  [2]

Deleting the current context is refused outright, not silently reassigned
  $ pf -c config.json ctx delete root-renamed
  Cannot delete the current context 'root-renamed'. Switch away first.
  [2]
  $ pf -c config.json ctx list | grep -w root-renamed > /dev/null

Delete the non-current context
  $ pf -c config.json ctx delete acme
  $ pf -c config.json ctx list | grep -c '^\*'
  1
  $ pf -c config.json ctx list | grep -w acme
  [1]

With only one context left and no valid previous pointer, "-" fails cleanly
  $ pf -c config.json ctx use -
  No previous context to switch to
  [2]
