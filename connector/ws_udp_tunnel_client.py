#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import os
import secrets
import socket
import ssl
import struct
import sys
import urllib.parse
from dataclasses import dataclass
from typing import Optional, Tuple


WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def _parse_hostport(value: str) -> Tuple[str, int]:
    if value.startswith(":"):
        return "0.0.0.0", int(value[1:])
    host, port_s = value.rsplit(":", 1)
    return host, int(port_s)


def _ws_accept(key: str) -> str:
    raw = (key + WS_GUID).encode("utf-8")
    digest = hashlib.sha1(raw).digest()
    return base64.b64encode(digest).decode("ascii")


def _ws_make_frame_client(opcode: int, payload: bytes) -> bytes:
    fin_opcode = 0x80 | (opcode & 0x0F)
    length = len(payload)
    mask_key = secrets.token_bytes(4)
    masked_payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))

    if length < 126:
        header = struct.pack("!BB", fin_opcode, 0x80 | length)
    elif length <= 0xFFFF:
        header = struct.pack("!BBH", fin_opcode, 0x80 | 126, length)
    else:
        header = struct.pack("!BBQ", fin_opcode, 0x80 | 127, length)
    return header + mask_key + masked_payload


async def _ws_read_frame(reader: asyncio.StreamReader) -> tuple[int, bool, bytes]:
    b1 = await reader.readexactly(1)
    b2 = await reader.readexactly(1)
    fin = bool(b1[0] & 0x80)
    opcode = b1[0] & 0x0F
    masked = bool(b2[0] & 0x80)
    length = b2[0] & 0x7F
    if length == 126:
        length = struct.unpack("!H", await reader.readexactly(2))[0]
    elif length == 127:
        length = struct.unpack("!Q", await reader.readexactly(8))[0]
    mask_key = await reader.readexactly(4) if masked else b""
    payload = await reader.readexactly(length) if length else b""
    if masked and payload:
        payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
    return opcode, fin, payload


async def _read_http_headers(reader: asyncio.StreamReader, max_bytes: int = 64 * 1024) -> bytes:
    buf = bytearray()
    while b"\r\n\r\n" not in buf:
        chunk = await reader.read(1024)
        if not chunk:
            break
        buf.extend(chunk)
        if len(buf) > max_bytes:
            raise ValueError("headers too large")
    return bytes(buf)


def _parse_status_and_headers(raw: bytes) -> tuple[int, dict[str, str]]:
    head, _, _ = raw.partition(b"\r\n\r\n")
    lines = head.decode("iso-8859-1").split("\r\n")
    if not lines or " " not in lines[0]:
        raise ValueError("invalid response")
    _, status_s, _ = lines[0].split(" ", 2)
    status = int(status_s)
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line or ":" not in line:
            continue
        k, v = line.split(":", 1)
        headers[k.strip().lower()] = v.strip()
    return status, headers


@dataclass
class WsTarget:
    host: str
    port: int
    path: str
    use_tls: bool
    host_header: str


def _parse_ws_url(ws_url: str) -> WsTarget:
    u = urllib.parse.urlparse(ws_url)
    if u.scheme not in ("ws", "wss"):
        raise ValueError(f"unsupported scheme: {u.scheme!r}")
    host = u.hostname or ""
    if not host:
        raise ValueError("missing hostname")
    port = u.port or (443 if u.scheme == "wss" else 80)
    path = u.path or "/"
    if u.query:
        path = f"{path}?{u.query}"
    host_header = host
    if u.port and ((u.scheme == "ws" and u.port != 80) or (u.scheme == "wss" and u.port != 443)):
        host_header = f"{host}:{u.port}"
    return WsTarget(host=host, port=port, path=path, use_tls=(u.scheme == "wss"), host_header=host_header)


async def run_tunnel(*, ws_url: str, udp_listen: str, extra_headers: list[str]) -> None:
    target = _parse_ws_url(ws_url)
    udp_host, udp_port = _parse_hostport(udp_listen)

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind((udp_host, udp_port))
    udp.setblocking(False)

    ssl_context: ssl.SSLContext | None = None
    if target.use_tls:
        ssl_context = ssl.create_default_context()

    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    reader, writer = await asyncio.open_connection(
        target.host,
        target.port,
        ssl=ssl_context,
        server_hostname=target.host if ssl_context else None,
    )

    # WebSocket handshake
    ws_key = base64.b64encode(os.urandom(16)).decode("ascii")
    req_lines = [
        f"GET {target.path} HTTP/1.1",
        f"Host: {target.host_header}",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Key: {ws_key}",
        "Sec-WebSocket-Version: 13",
    ]
    for h in extra_headers:
        h = h.strip()
        if not h or ":" not in h:
            continue
        req_lines.append(h)
    req_lines.append("")
    req_lines.append("")
    writer.write("\r\n".join(req_lines).encode("utf-8"))
    await writer.drain()

    resp = await _read_http_headers(reader)
    status, headers = _parse_status_and_headers(resp)
    if status != 101:
        raise RuntimeError(f"websocket upgrade failed: status={status}")
    accept = headers.get("sec-websocket-accept", "")
    if accept != _ws_accept(ws_key):
        raise RuntimeError("websocket upgrade failed: Sec-WebSocket-Accept mismatch")

    loop = asyncio.get_running_loop()
    peer_addr: Optional[tuple[str, int]] = None

    async def udp_to_ws() -> None:
        nonlocal peer_addr
        while True:
            data, addr = await loop.sock_recvfrom(udp, 65535)
            if not data:
                continue
            peer_addr = (addr[0], addr[1])
            writer.write(_ws_make_frame_client(0x2, data))
            await writer.drain()

    async def ws_to_udp() -> None:
        nonlocal peer_addr
        msg_parts: list[bytes] = []
        msg_opcode: Optional[int] = None
        while True:
            opcode, fin, payload = await _ws_read_frame(reader)
            if opcode in (0x0, 0x1, 0x2):
                if opcode != 0x0:
                    msg_opcode = opcode
                    msg_parts = []
                msg_parts.append(payload)
                if not fin:
                    continue
                full = b"".join(msg_parts)
                msg_parts = []
                msg_opcode = None
                if peer_addr is not None:
                    await loop.sock_sendto(udp, full, peer_addr)
            elif opcode == 0x8:
                # close
                writer.write(_ws_make_frame_client(0x8, b""))
                await writer.drain()
                return
            elif opcode == 0x9:
                # ping -> pong
                writer.write(_ws_make_frame_client(0xA, payload))
                await writer.drain()
            elif opcode == 0xA:
                continue
            else:
                writer.write(_ws_make_frame_client(0x8, b""))
                await writer.drain()
                return

    async def keepalive_ping(interval_s: float) -> None:
        if interval_s <= 0:
            return
        while True:
            await asyncio.sleep(interval_s)
            writer.write(_ws_make_frame_client(0x9, b"ping"))
            await writer.drain()

    try:
        interval_s = float(os.environ.get("SIM_AWS_TUNNEL_PING_INTERVAL_S", "20"))
        await asyncio.gather(udp_to_ws(), ws_to_udp(), keepalive_ping(interval_s))
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        udp.close()


async def run_forever(*, ws_url: str, udp_listen: str, extra_headers: list[str]) -> None:
    """
    Keep the UDP<->WS tunnel alive for long-lived connector sessions.

    The Morph instance HTTP gateway (or intermediaries) may close idle WebSockets; this loop
    reconnects with exponential backoff.
    """
    backoff_s = 1.0
    max_backoff_s = 30.0
    while True:
        try:
            await run_tunnel(ws_url=ws_url, udp_listen=udp_listen, extra_headers=extra_headers)
        except Exception as e:
            # Best-effort, single-line log (no secrets).
            print(f"[ws_udp_tunnel_client] WARN: tunnel disconnected: {type(e).__name__}: {e}", file=sys.stderr)
        await asyncio.sleep(backoff_s)
        backoff_s = min(max_backoff_s, backoff_s * 2.0)


def main() -> int:
    p = argparse.ArgumentParser(description="UDP<->WebSocket relay client (no deps; for Sim-AWS ws_udp_tunnel.py)")
    p.add_argument("--ws-url", required=True, help="ws:// or wss:// URL for the tunnel server")
    p.add_argument("--udp-listen", default="127.0.0.1:51820", help="UDP listen host:port (default 127.0.0.1:51820)")
    p.add_argument("--header", action="append", default=[], help="Extra HTTP header to include (repeatable)")
    args = p.parse_args()
    asyncio.run(run_forever(ws_url=args.ws_url, udp_listen=args.udp_listen, extra_headers=args.header))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
