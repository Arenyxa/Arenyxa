from __future__ import annotations

import json
import os
from pathlib import Path
from typing import BinaryIO


class DataRootLease:
    






    def __init__(self, data_root: Path) -> None:
        self.data_root = data_root.expanduser().resolve()
        self.path = self.data_root / ".arenyxa-runtime.lock"
        self._stream: BinaryIO | None = None

    def acquire(self) -> bool:
        if self._stream is not None:
            return True
        self.data_root.mkdir(parents=True, exist_ok=True)
        stream = self.path.open("a+b")
        try:
            stream.seek(0, os.SEEK_END)
            if stream.tell() == 0:
                stream.write(b"\0")
                stream.flush()
            stream.seek(0)
            if os.name == "nt":
                import msvcrt

                try:
                    msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                except OSError:
                    stream.close()
                    return False
            else:
                import fcntl

                try:
                    fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                except OSError:
                    stream.close()
                    return False
            self._stream = stream
            self._write_owner_metadata()
            return True
        except Exception:
                                                                                          
                                                                                          
                                                                                        
            self._stream = None
            stream.close()
            raise

    def release(self) -> None:
        stream = self._stream
        if stream is None:
            return
        self._stream = None
        try:
            stream.seek(0)
            if os.name == "nt":
                import msvcrt

                try:
                    msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
                except OSError:
                    pass
            else:
                import fcntl

                try:
                    fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
                except OSError:
                    pass
        finally:
            stream.close()

    def _write_owner_metadata(self) -> None:
        stream = self._stream
        if stream is None:
            return
        payload = json.dumps({"pid": os.getpid()}, ensure_ascii=False).encode("utf-8")
                                                                                         
        stream.seek(1)
        stream.truncate(1)
        stream.write(payload)
        stream.flush()
        try:
            os.fsync(stream.fileno())
        except OSError:
            pass

    def __enter__(self) -> DataRootLease:
        if not self.acquire():
            raise RuntimeError(f"Arenyxa data directory is already in use: {self.data_root}")
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.release()

    def __del__(self) -> None:
        try:
            self.release()
        except Exception:
            pass
