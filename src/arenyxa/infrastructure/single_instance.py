from __future__ import annotations

import hashlib
import os
from pathlib import Path

from arenyxa.qt_compat.QtCore import QObject, Signal
from arenyxa.branding import LEGACY_APP_NAME
from arenyxa.qt_compat.QtNetwork import QLocalServer, QLocalSocket


class SingleInstance(QObject):
    messageReceived = Signal(str)

    def __init__(self, data_root: Path, parent: QObject | None = None) -> None:
        super().__init__(parent)
        root_key = str(data_root.resolve())
        if os.name == "nt":
            root_key = root_key.casefold()
        digest = hashlib.sha256(root_key.encode("utf-8")).hexdigest()[:20]
        self.name = f"{LEGACY_APP_NAME}-{digest}"                                                                                                                     
        self.server = QLocalServer(self)
        self.server.newConnection.connect(self._accept)
        self._buffers: dict[QLocalSocket, bytearray] = {}

    def acquire(self) -> bool:
        if self.server.listen(self.name):
            return True
        socket = QLocalSocket()
        socket.connectToServer(self.name)
        if socket.waitForConnected(500):
            socket.disconnectFromServer()
            return False
                                                                        
        QLocalServer.removeServer(self.name)
        return self.server.listen(self.name)

    def notify(self, message: str) -> bool:
        socket = QLocalSocket()
        socket.connectToServer(self.name)
        if not socket.waitForConnected(1000):
            return False
        payload = message.encode("utf-8")[:64 * 1024]
        socket.write(payload)
        socket.flush()
        written = socket.waitForBytesWritten(1000)
        socket.disconnectFromServer()
        return bool(written)

    def _accept(self) -> None:
                                                                                           
                                                                                             
        while self.server.hasPendingConnections():
            socket = self.server.nextPendingConnection()
            if socket is None:
                continue
            self._buffers[socket] = bytearray()
            socket.readyRead.connect(lambda socket=socket: self._read_available(socket))
            socket.disconnected.connect(lambda socket=socket: self._finish_socket(socket))
            self._read_available(socket)

    def _read_available(self, socket: QLocalSocket) -> None:
        buffer = self._buffers.get(socket)
        if buffer is None:
            return
        if socket.bytesAvailable() > 0:
            buffer.extend(bytes(socket.readAll().data()))
        if len(buffer) > 64 * 1024:
            del buffer[64 * 1024 :]
            socket.abort()

    def _finish_socket(self, socket: QLocalSocket) -> None:
        self._read_available(socket)
        payload = bytes(self._buffers.pop(socket, b""))
        if payload:
            self.messageReceived.emit(payload.decode("utf-8", errors="replace"))
        socket.deleteLater()
