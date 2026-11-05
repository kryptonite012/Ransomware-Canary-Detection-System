"""Cryptographic helpers shared by the agent and the control plane.

* Ed25519 signatures protect everything the agent accepts as an instruction
  (policy documents, monitored-directory rows, response commands).  The
  backend holds the private key; the agent only needs the public key, so a
  process that can read agent files cannot forge instructions.
* HMAC-SHA256 (agent-local key) protects snapshot manifests and evidence
  manifests written by the agent itself.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import stat
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def canonical_json(payload: Any) -> bytes:
    """Deterministic JSON encoding used as signature input."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode(
        "utf-8"
    )


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write_secret(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


def generate_keypair(private_path: Path, public_path: Path, overwrite: bool = False) -> None:
    if private_path.exists() and not overwrite:
        raise FileExistsError(f"{private_path} already exists")
    key = Ed25519PrivateKey.generate()
    priv = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    pub = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    _write_secret(private_path, priv)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.write_bytes(pub)
    try:
        os.chmod(public_path, 0o644)
    except OSError:
        pass


def ensure_secret_file(path: Path, nbytes: int = 32) -> bytes:
    """Return the content of a random secret file, creating it if necessary."""
    if path.exists():
        return path.read_bytes()
    value = secrets.token_bytes(nbytes)
    _write_secret(path, value)
    return value


class Signer:
    def __init__(self, private_key: Ed25519PrivateKey):
        self._key = private_key

    @classmethod
    def from_file(cls, path: Path) -> "Signer":
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("control-plane key is not an Ed25519 private key")
        return cls(key)

    def sign(self, payload: Any) -> str:
        return base64.b64encode(self._key.sign(canonical_json(payload))).decode("ascii")


class Verifier:
    def __init__(self, public_key: Ed25519PublicKey):
        self._key = public_key

    @classmethod
    def from_file(cls, path: Path) -> "Verifier":
        key = serialization.load_pem_public_key(path.read_bytes())
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError("control-plane key is not an Ed25519 public key")
        return cls(key)

    def verify(self, payload: Any, signature: str | None) -> bool:
        if not signature:
            return False
        try:
            self._key.verify(base64.b64decode(signature, validate=True), canonical_json(payload))
            return True
        except (InvalidSignature, ValueError, TypeError):
            return False


class HmacSigner:
    def __init__(self, key: bytes):
        if len(key) < 16:
            raise ValueError("HMAC key too short")
        self._key = key

    def sign(self, payload: Any) -> str:
        return hmac.new(self._key, canonical_json(payload), hashlib.sha256).hexdigest()

    def verify(self, payload: Any, signature: str | None) -> bool:
        if not signature:
            return False
        return hmac.compare_digest(self.sign(payload), signature)


# --- canonical payload builders -------------------------------------------------
# Signatures cover a stable subset of fields so that the agent and backend agree
# on exactly what was signed.

def directory_payload(endpoint_id: int, directory_path: str, recursive: bool, enabled: bool) -> dict[str, Any]:
    return {
        "kind": "monitored_directory",
        "endpoint_id": int(endpoint_id),
        "path": directory_path,
        "recursive": bool(recursive),
        "enabled": bool(enabled),
    }


def command_payload(command_id: int, endpoint_id: int, command: str, params: dict[str, Any]) -> dict[str, Any]:
    return {
        "kind": "agent_command",
        "id": int(command_id),
        "endpoint_id": int(endpoint_id),
        "command": command,
        "params": params or {},
    }


def policy_payload(version: int, policy: dict[str, Any]) -> dict[str, Any]:
    return {"kind": "policy", "version": int(version), "policy": policy}
