from __future__ import annotations

import hashlib
import os
from dataclasses import asdict
from pathlib import Path
from typing import Any

from arenyxa.domain.network import BodyArtifact
from arenyxa.domain.models import utc_now
from arenyxa.infrastructure.atomic_io import atomic_write_bytes


class NetworkBodyStore:
    







    def __init__(self, root: Path, *, max_body_bytes: int = 2 * 1024 * 1024) -> None:
        self.root = Path(root)
        self.max_body_bytes = max(1, int(max_body_bytes))

    @classmethod
    def for_capture(
        cls, captures_root: Path, session_id: str, *, max_body_bytes: int = 2 * 1024 * 1024
    ) -> "NetworkBodyStore":
        return cls(Path(captures_root) / session_id / "bodies", max_body_bytes=max_body_bytes)

    def put(
        self,
        session_id: str,
        payload: bytes | bytearray | memoryview | str,
        *,
        content_type: str = "",
        encoding: str = "",
        sensitive: bool = False,
    ) -> BodyArtifact:
        if isinstance(payload, str):
            codec = encoding or "utf-8"
            try:
                raw = payload.encode(codec)
            except (LookupError, UnicodeEncodeError):
                codec = "utf-8"
                raw = payload.encode(codec, errors="replace")
            encoding = codec
        else:
            raw = bytes(payload)

        digest = hashlib.sha256(raw).hexdigest()
        body_id = self._body_id(session_id, digest)
        byte_size = len(raw)
        stored = raw[: self.max_body_bytes]
        stored_digest = hashlib.sha256(stored).hexdigest()
        truncated = byte_size > len(stored)
        suffix = ".partial" if truncated else ".bin"
        relative = Path(digest[:2]) / f"{digest}{suffix}"
        destination = self.root / relative
        if not destination.exists() or destination.stat().st_size < len(stored):
            atomic_write_bytes(destination, stored, mode=0o600 if os.name != "nt" else None)
        return BodyArtifact(
            id=body_id,
            session_id=session_id,
            sha256=digest,
            stored_sha256=stored_digest,
            byte_size=byte_size,
            stored_size=len(stored),
            content_type=str(content_type or ""),
            encoding=str(encoding or ""),
            storage_kind="file",
            storage_ref=relative.as_posix(),
            truncated=truncated,
            sensitive=bool(sensitive),
            created_at=utc_now(),
        )

    def read(self, artifact: BodyArtifact | dict[str, Any], *, max_bytes: int | None = None) -> bytes:
        path = self.get_path(artifact)
        expected_size = int(artifact.stored_size if isinstance(artifact, BodyArtifact) else artifact.get("stored_size", 0))
        limit = expected_size if max_bytes is None else min(expected_size, max(0, int(max_bytes)))
        with path.open("rb") as stream:
            payload = stream.read(limit + 1)
        if len(payload) > limit:
            if limit == expected_size:
                raise ValueError("captured body size does not match metadata")
            payload = payload[:limit]
        expected_hash = artifact.stored_sha256 if isinstance(artifact, BodyArtifact) else str(artifact.get("stored_sha256") or "")
        if limit == expected_size and len(payload) != expected_size:
            raise ValueError("captured body size does not match metadata")
        if limit == expected_size and expected_hash and hashlib.sha256(payload).hexdigest() != expected_hash:
            raise ValueError("captured body failed integrity verification")
        return payload

    def get_path(self, artifact: BodyArtifact | dict[str, Any]) -> Path:
        storage_ref = artifact.storage_ref if isinstance(artifact, BodyArtifact) else str(artifact["storage_ref"])
        candidate = (self.root / storage_ref).resolve()
        root = self.root.resolve()
        try:
            candidate.relative_to(root)
        except ValueError as exc:
            raise ValueError("body storage reference escapes capture root") from exc
        return candidate

    @staticmethod
    def metadata(artifact: BodyArtifact) -> dict[str, Any]:
        return asdict(artifact)

    @staticmethod
    def _body_id(session_id: str, digest: str) -> str:
        key = f"{session_id}\x1f{digest}".encode("utf-8", errors="surrogatepass")
        return f"body_{hashlib.sha256(key).hexdigest()[:32]}"
