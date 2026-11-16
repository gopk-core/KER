"""Signed and HMAC-authenticated cluster messages, length-prefixed on the wire."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import struct
from typing import Any

from ker.sign import sign_bytes, verify_bytes


class ProtocolError(RuntimeError):
    pass


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode('ascii').rstrip('=')


def b64d(text: str) -> bytes:
    pad = '=' * ((4 - len(text) % 4) % 4)
    return base64.urlsafe_b64decode(text + pad)


def encode_payload(obj: dict) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()


def sign_message(obj: dict, keys: dict) -> dict:
    raw = encode_payload(obj)
    gsig, ksig = sign_bytes(raw, keys)
    return {'payload': b64(raw), 'gsig': b64(gsig), 'ksig': b64(ksig)}


def verify_message(msg: dict, keys: dict) -> dict:
    try:
        raw = b64d(msg['payload'])
        verify_bytes(raw, b64d(msg['gsig']), b64d(msg['ksig']), keys)
    except Exception as e:
        raise ProtocolError('SIGNATURE_REJECTED') from e
    return json.loads(raw.decode('utf-8'))


def hmac_message(obj: dict, secret: bytes) -> dict:
    raw = encode_payload(obj)
    mac = hmac.new(secret, raw, hashlib.sha256).digest()
    return {'payload': b64(raw), 'hmac': b64(mac)}


def verify_hmac(msg: dict, secret: bytes) -> dict:
    raw = b64d(msg.get('payload') or '')
    mac = b64d(msg.get('hmac') or '')
    expect = hmac.new(secret, raw, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expect):
        raise ProtocolError('HMAC_REJECTED')
    return json.loads(raw.decode('utf-8'))


def send_msg(sock, obj: dict) -> None:
    data = json.dumps(obj, ensure_ascii=False, separators=(',', ':')).encode()
    sock.sendall(struct.pack('!I', len(data)) + data)


def recvn(sock, n: int) -> bytes:
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ProtocolError('connection closed')
        buf += chunk
    return buf


def recv_msg(sock, maxlen: int = 16 * 1024 * 1024) -> dict:
    n = struct.unpack('!I', recvn(sock, 4))[0]
    if n > maxlen or n < 1:
        raise ProtocolError('invalid message length')
    return json.loads(recvn(sock, n).decode('utf-8'))
