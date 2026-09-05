"""Message-type constants for the oracle's ssh-agent-compatible protocol.

The wire framing itself is `ssh/wire.py`'s `WireSocket`, shared with
`agent.Client`'s connecting side -- `Connection` is just a name for it on
the accepting/server side.
"""

from __future__ import annotations

from .. import wire

Connection = wire.WireSocket

# https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent
SSH_AGENTC_REQUEST_IDENTITIES = 11
SSH_AGENT_IDENTITIES_ANSWER = 12
SSH_AGENTC_SIGN_REQUEST = 13
SSH_AGENT_SIGN_RESPONSE = 14
SSH_AGENT_FAILURE = 5
