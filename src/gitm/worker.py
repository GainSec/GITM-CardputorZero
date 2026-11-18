"""Owned foreground metadata and lease workers. Never display packet payloads."""

import argparse
import ctypes
from datetime import datetime, timezone
from ipaddress import ip_address
import json
import os
from pathlib import Path
import re
import shutil
import socket
import struct
import time

MAX_LOG_BYTES = 256 * 1024


def safe_text(value: object, limit: int = 160) -> str:
    return ''.join(c if 32 <= ord(c) < 127 and c not in '<>' else '?' for c in str(value))[:limit]


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')


def packet_metadata(packet: bytes) -> dict | None:
    if len(packet) < 14:
        return None
    kind = struct.unpack('!H', packet[12:14])[0]
    data = packet[14:]
    if kind == 0x0800 and len(data) >= 20 and data[0] >> 4 == 4:
        offset = (data[0] & 15) * 4
        if offset < 20 or len(data) < offset:
            return None
        source, destination = str(ip_address(data[12:16])), str(ip_address(data[16:20]))
        protocol = data[9]
        # Do not interpret fragment payload bytes as transport ports.
        if struct.unpack('!H', data[6:8])[0] & 0x1fff:
            protocol = 0
    elif kind == 0x86dd and len(data) >= 40 and data[0] >> 4 == 6:
        offset = 40
        source, destination = str(ip_address(data[8:24])), str(ip_address(data[24:40]))
        protocol = data[6]
    else:
        return None
    if protocol in (6, 17) and len(data) >= offset + 4:
        sport, dport = struct.unpack('!HH', data[offset:offset + 4])
        source, destination = f'{source}:{sport}', f'{destination}:{dport}'
    return {'timestamp': now(), 'source': source, 'destination': destination,
            'protocol': {6: 'TCP', 17: 'UDP', 1: 'ICMP', 58: 'ICMP6'}.get(protocol, 'IP'),
            'bytes': len(packet)}


def lease_events(text: str, seen: set, *, timestamp: str | None = None) -> list[dict]:
    result = []
    for line in text[:65536].splitlines():
        fields = line.split()
        if len(fields) != 5 or not re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', fields[1]):
            continue
        try:
            address = str(ip_address(fields[2]))
        except ValueError:
            continue
        identity = (fields[1].lower(), address)
        if identity not in seen:
            result.append({'timestamp': timestamp or now(), 'mac': identity[0], 'ip': identity[1]})
            seen.add(identity)
    return result


def append_event(path: Path, event: dict, *, max_bytes: int = MAX_LOG_BYTES) -> None:
    data = (json.dumps(event, sort_keys=True, ensure_ascii=True) + '\n').encode('ascii')
    if len(data) > max_bytes:
        return
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(fd, 0o600)
        size = os.fstat(fd).st_size
        if size + len(data) > max_bytes:
            os.lseek(fd, max(0, size - max_bytes // 2), os.SEEK_SET)
            tail = os.read(fd, max_bytes // 2).split(b'\n', 1)
            retained = tail[1] if len(tail) == 2 else b''
            os.ftruncate(fd, 0)
            os.lseek(fd, 0, os.SEEK_SET)
            os.write(fd, retained)
        os.lseek(fd, 0, os.SEEK_END)
        os.write(fd, data)
    finally:
        os.close(fd)


def read_events(path: Path, *, limit: int = 20) -> list[dict]:
    limit = min(max(int(limit), 1), 100)
    try:
        with path.open('rb') as stream:
            size = os.fstat(stream.fileno()).st_size
            stream.seek(max(0, size - MAX_LOG_BYTES))
            lines = stream.read(MAX_LOG_BYTES).splitlines()
    except FileNotFoundError:
        return []
    result = []
    for line in lines[-limit:]:
        try:
            value = json.loads(line)
        except (ValueError, UnicodeDecodeError):
            continue
        if isinstance(value, dict):
            result.append({safe_text(k, 32): safe_text(v) for k, v in value.items() if k in {'timestamp', 'source', 'destination', 'protocol', 'bytes', 'mac', 'ip'}})
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=('live', 'leases'))
    parser.add_argument('--interface', default='gitm-ap', choices=('gitm-ap',))
    parser.add_argument('--source', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args(argv)
    # Linux process identity lets the helper distinguish the two Python workers.
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(15, ('gitm-' + args.mode).encode(), 0, 0, 0) != 0:
        raise OSError('cannot set worker process identity')
    seen = set()
    receiver = None
    if args.mode == 'live':
        receiver = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        receiver.bind((args.interface, 0))
        receiver.settimeout(0.2)
    try:
        while True:
            if shutil.disk_usage(args.output.parent).free < 16 * 1_000_000:
                raise OSError('evidence disk reserve exhausted')
            if receiver is not None:
                try:
                    packet = receiver.recv(256)
                except socket.timeout:
                    continue
                event = packet_metadata(packet)
                if event:
                    append_event(args.output, event)
            else:
                try:
                    fd = os.open(args.source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                    with os.fdopen(fd) as stream:
                        text = stream.read(65536)
                except FileNotFoundError:
                    text = ''
                current = set()
                events = lease_events(text, current)
                for event in events:
                    if (event['mac'], event['ip']) not in seen:
                        append_event(args.output, event)
                seen = current
                time.sleep(0.2)
    finally:
        if receiver:
            receiver.close()


if __name__ == '__main__':
    raise SystemExit(main())
