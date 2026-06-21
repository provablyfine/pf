"""Mock OIDC provider for testing OIDC login flow."""

import base64
import dataclasses
import hashlib
import http.server
import json
import secrets
import threading
import time
import typing
import urllib.parse

import cryptography.hazmat.primitives.asymmetric.ec
import cryptography.hazmat.primitives.asymmetric.rsa
import cryptography.hazmat.primitives.asymmetric.utils
import cryptography.hazmat.primitives.hashes
import cryptography.hazmat.primitives.serialization
import pytest


def _b64url_encode(data: bytes) -> str:
    """Encode bytes as base64url without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    """Decode base64url string to bytes."""
    s = s + "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


@dataclasses.dataclass
class _PendingCode:
    """Pending authorization code with PKCE challenge and optional email."""

    code_challenge: str
    email: str


@dataclasses.dataclass
class _PendingDeviceCode:
    """Pending device authorization with completion state."""

    user_code: str
    completed: bool = False
    email: str = "user@example.com"


class _MockOidcHandler(http.server.BaseHTTPRequestHandler):
    """Handler for mock OIDC HTTP server."""

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/.well-known/openid-configuration":
            self._handle_discovery()
        elif path == "/jwks":
            self._handle_jwks()
        elif path == "/authorize":
            self._handle_authorize(parsed.query)
        else:
            self.send_error(404)

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        content_length = int(self.headers.get("content-length", 0))
        body = self.rfile.read(content_length).decode("utf-8")

        if path == "/token":
            self._handle_token(body)
        elif path == "/device_authorization":
            self._handle_device_authorization(body)
        else:
            self.send_error(404)

    def log_message(self, format: str, *args: typing.Any) -> None:
        pass  # suppress logging

    def _handle_discovery(self) -> None:
        provider = self.server.mock_provider  # type: ignore
        discovery = {
            "issuer": provider.issuer,
            "authorization_endpoint": f"{provider.issuer}/authorize",
            "token_endpoint": f"{provider.issuer}/token",
            "device_authorization_endpoint": f"{provider.issuer}/device_authorization",
            "jwks_uri": f"{provider.issuer}/jwks",
        }
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(discovery).encode("utf-8"))

    def _handle_jwks(self) -> None:
        provider = self.server.mock_provider  # type: ignore
        jwks = provider._build_jwks()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(jwks).encode("utf-8"))

    def _handle_authorize(self, query: str) -> None:
        provider = self.server.mock_provider  # type: ignore
        params = urllib.parse.parse_qs(query)
        redirect_uri = params.get("redirect_uri", [""])[0]
        code_challenge = params.get("code_challenge", [""])[0]

        if not redirect_uri or not code_challenge:
            self.send_error(400, "Missing redirect_uri or code_challenge")
            return

        # Check if an error should be returned
        if provider._authorize_error:
            error = provider._authorize_error
            redirect = f"{redirect_uri}?error={urllib.parse.quote(error)}"
            self.send_response(302)
            self.send_header("location", redirect)
            self.end_headers()
            return

        # Generate authorization code
        code = secrets.token_urlsafe(32)
        provider._pending_codes[code] = _PendingCode(code_challenge=code_challenge, email="user@example.com")

        redirect = f"{redirect_uri}?code={urllib.parse.quote(code)}"
        self.send_response(302)
        self.send_header("location", redirect)
        self.end_headers()

    def _handle_device_authorization(self, body: str) -> None:
        provider = self.server.mock_provider  # type: ignore
        device_code = secrets.token_urlsafe(32)
        user_code = secrets.token_hex(4).upper()
        provider._pending_device_codes[device_code] = _PendingDeviceCode(user_code=user_code)
        response = {
            "device_code": device_code,
            "user_code": user_code,
            "verification_uri": f"{provider.issuer}/activate",
            "expires_in": 300,
            "interval": 1,
        }
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(response).encode("utf-8"))

    def _handle_token(self, body: str) -> None:
        provider = self.server.mock_provider  # type: ignore
        params = urllib.parse.parse_qs(body)
        grant_type = params.get("grant_type", [""])[0]

        if grant_type == "urn:ietf:params:oauth:grant-type:device_code":
            device_code = params.get("device_code", [""])[0]
            pending_device = provider._pending_device_codes.get(device_code)
            if not pending_device:
                self.send_error(400, "Invalid device_code")
                return
            if not pending_device.completed:
                self.send_response(400)
                self.send_header("content-type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "authorization_pending"}).encode("utf-8"))
                return
            id_token = provider.issue_token(pending_device.email)
            del provider._pending_device_codes[device_code]
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"id_token": id_token, "token_type": "Bearer"}).encode("utf-8"))
            return

        code = params.get("code", [""])[0]
        code_verifier = params.get("code_verifier", [""])[0]

        if not code or not code_verifier:
            self.send_error(400, "Missing code or code_verifier")
            return

        pending = provider._pending_codes.get(code)
        if not pending:
            self.send_error(400, "Invalid code")
            return

        # Verify PKCE: b64url(sha256(verifier)) == challenge
        computed_challenge = _b64url_encode(hashlib.sha256(code_verifier.encode()).digest())
        if computed_challenge != pending.code_challenge:
            self.send_error(400, "PKCE verification failed")
            return

        # Generate and return id_token
        id_token = provider.issue_token(pending.email)
        response = {"id_token": id_token, "token_type": "Bearer"}

        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(response).encode("utf-8"))

        # Clean up
        del provider._pending_codes[code]


class MockOidcProvider:
    """Lightweight OIDC provider running in a background thread."""

    def __init__(self, client_id: str = "test-client") -> None:
        self.client_id = client_id
        self._authorize_error: str | None = None
        self._pending_codes: dict[str, _PendingCode] = {}
        self._pending_device_codes: dict[str, _PendingDeviceCode] = {}

        # Generate RSA-2048 key
        self._rsa_key = cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )

        # Generate EC P-256 key
        self._ec_key = cryptography.hazmat.primitives.asymmetric.ec.generate_private_key(
            cryptography.hazmat.primitives.asymmetric.ec.SECP256R1()
        )

        # Create HTTP server
        self._server = http.server.HTTPServer(("127.0.0.1", 0), _MockOidcHandler)
        self._server.mock_provider = self  # type: ignore
        self.issuer = f"http://127.0.0.1:{self._server.server_port}"

        # Start server in background thread
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def set_authorize_error(self, error: str | None) -> None:
        """Set/clear the error to return from /authorize endpoint."""
        self._authorize_error = error

    def complete_device_auth(self, device_code: str) -> None:
        """Mark device authorization as completed (simulates user visiting verification_uri)."""
        pending = self._pending_device_codes.get(device_code)
        if pending:
            pending.completed = True

    def issue_token(
        self,
        email: str,
        alg: str = "RS256",
        expired: bool = False,
        issuer: str | None = None,
        audience: str | None = None,
    ) -> str:
        """Generate a signed JWT token."""
        if issuer is None:
            issuer = self.issuer
        if audience is None:
            audience = self.client_id

        now = int(time.time())
        exp = now - 1 if expired else now + 3600

        header = {"alg": alg, "typ": "JWT", "kid": "rsa-1" if alg == "RS256" else "ec-1"}
        payload = {
            "iss": issuer,
            "aud": audience,
            "email": email,
            "exp": exp,
            "iat": now,
        }

        header_b64 = _b64url_encode(json.dumps(header).encode())
        payload_b64 = _b64url_encode(json.dumps(payload).encode())
        signing_input = f"{header_b64}.{payload_b64}".encode()

        if alg == "RS256":
            signature = self._rsa_key.sign(
                signing_input,
                cryptography.hazmat.primitives.asymmetric.padding.PKCS1v15(),
                cryptography.hazmat.primitives.hashes.SHA256(),
            )
        elif alg == "ES256":
            der_sig = self._ec_key.sign(
                signing_input,
                cryptography.hazmat.primitives.asymmetric.ec.ECDSA(cryptography.hazmat.primitives.hashes.SHA256()),
            )
            # Convert DER signature to (r, s) raw format for JWS
            # DER format: 0x30 [len] 0x02 [r-len] [r-bytes] 0x02 [s-len] [s-bytes]
            r, s = cryptography.hazmat.primitives.asymmetric.utils.decode_dss_signature(der_sig)
            signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        else:
            raise ValueError(f"Unsupported algorithm: {alg}")

        signature_b64 = _b64url_encode(signature)
        return f"{header_b64}.{payload_b64}.{signature_b64}"

    def _build_jwks(self) -> dict[str, typing.Any]:
        """Build JWKS response with RSA and EC public keys."""
        keys = []

        # RSA key
        rsa_pub = self._rsa_key.public_key()
        rsa_numbers = rsa_pub.public_numbers()
        keys.append(
            {
                "kty": "RSA",
                "kid": "rsa-1",
                "n": _b64url_encode(rsa_numbers.n.to_bytes(256, "big")),
                "e": _b64url_encode(rsa_numbers.e.to_bytes(3, "big")),
                "use": "sig",
                "alg": "RS256",
            }
        )

        # EC key
        ec_pub = self._ec_key.public_key()
        ec_numbers = ec_pub.public_numbers()
        keys.append(
            {
                "kty": "EC",
                "kid": "ec-1",
                "crv": "P-256",
                "x": _b64url_encode(ec_numbers.x.to_bytes(32, "big")),
                "y": _b64url_encode(ec_numbers.y.to_bytes(32, "big")),
                "use": "sig",
                "alg": "ES256",
            }
        )

        return {"keys": keys}

    def stop(self) -> None:
        """Shutdown the server."""
        self._server.shutdown()
        self._thread.join(timeout=5)


@pytest.fixture
def mock_oidc() -> typing.Iterator[MockOidcProvider]:
    """Pytest fixture for mock OIDC provider."""
    provider = MockOidcProvider()
    yield provider
    provider.stop()
