#!/usr/bin/env python3

import hashlib
import hmac
import struct
from pathlib import Path


PASSPHRASE = b"12345678"
RSN_IE = bytes.fromhex("dd14000fac040100000fac040100000fac020000")


def prf(key, label, data, length):
    result = b""
    counter = 0
    while len(result) < length:
        result += hmac.new(
            key, label + b"\x00" + data + bytes([counter]), hashlib.sha1
        ).digest()
        counter += 1
    return result[:length]


def pmk_for(essid):
    return hashlib.pbkdf2_hmac("sha1", PASSPHRASE, essid, 4096, 32)


def pmkid_for(pmk, bssid, station):
    return hmac.new(
        pmk, b"PMK Name" + bssid + station, hashlib.sha1
    ).digest()[:16]


def mic_for(pmk, bssid, station, anonce, snonce, eapol):
    data = (
        min(bssid, station)
        + max(bssid, station)
        + min(anonce, snonce)
        + max(anonce, snonce)
    )
    kck = prf(pmk, b"Pairwise key expansion", data, 16)
    return hmac.new(kck, eapol, hashlib.sha1).digest()[:16]


def eapol_key(key_info, replay, nonce, key_data=b"", mic=b"\x00" * 16):
    body = (
        b"\x02"
        + struct.pack(">H", key_info)
        + struct.pack(">H", 16)
        + struct.pack(">Q", replay)
        + nonce
        + b"\x00" * 16
        + b"\x00" * 8
        + b"\x00" * 8
        + mic
        + struct.pack(">H", len(key_data))
        + key_data
    )
    return b"\x02\x03" + struct.pack(">H", len(body)) + body


def sequence(value):
    return struct.pack("<H", (value & 0x0FFF) << 4)


def data_frame(direction, bssid, station, payload, seq):
    if direction == "fromds":
        addr1, addr2, addr3 = station, bssid, bssid
        fc1 = 0x02
    else:
        addr1, addr2, addr3 = bssid, station, bssid
        fc1 = 0x01

    return (
        bytes([0x08, fc1, 0x00, 0x00])
        + addr1
        + addr2
        + addr3
        + sequence(seq)
        + b"\xaa\xaa\x03\x00\x00\x00\x88\x8e"
        + payload
    )


def beacon(bssid, essid, seq):
    ssid_ie = bytes([0x00, len(essid)]) + essid
    rates_ie = bytes.fromhex("010482848b96")
    return (
        b"\x80\x00\x00\x00"
        + b"\xff" * 6
        + bssid
        + bssid
        + sequence(seq)
        + b"\x00" * 8
        + struct.pack("<H", 100)
        + struct.pack("<H", 0x0011)
        + ssid_ie
        + rates_ie
    )


class Capture:
    def __init__(self):
        self.packets = []
        self.seq = 0

    def add(self, timestamp, frame):
        self.packets.append((timestamp, frame))
        self.seq += 1

    def write(self, path):
        with open(path, "wb") as output:
            output.write(
                struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 105)
            )
            for timestamp, frame in self.packets:
                seconds = int(timestamp)
                microseconds = int(round((timestamp - seconds) * 1000000))
                output.write(
                    struct.pack(
                        "<IIII", seconds, microseconds, len(frame), len(frame)
                    )
                )
                output.write(frame)


def add_handshake(
    capture,
    timestamp,
    bssid,
    station,
    essid,
    replay=1,
    anonce=None,
    snonce=None,
    pmkid_only=False,
    m1_only=False,
    corrupt_mic=False,
):
    pmk = pmk_for(essid)
    anonce = anonce or hashlib.sha256(b"anonce" + bssid).digest()
    snonce = snonce or hashlib.sha256(b"snonce" + station).digest()
    pmkid = pmkid_for(pmk, bssid, station)

    if pmkid_only:
        key_data = bytes.fromhex("dd14000fac04") + pmkid
        m1 = eapol_key(0x008A, replay, anonce, key_data)
        capture.add(timestamp, data_frame("fromds", bssid, station, m1, capture.seq))
        return

    m1 = eapol_key(0x008A, replay, anonce)
    capture.add(timestamp, data_frame("fromds", bssid, station, m1, capture.seq))
    if m1_only:
        return

    m2_without_mic = eapol_key(0x010A, replay, snonce, RSN_IE)
    mic = mic_for(pmk, bssid, station, anonce, snonce, m2_without_mic)
    if corrupt_mic:
        mic = bytes([mic[0] ^ 0xFF]) + mic[1:]
    m2 = eapol_key(0x010A, replay, snonce, RSN_IE, mic)

    capture.add(
        timestamp + 0.01,
        data_frame("tods", bssid, station, m2, capture.seq),
    )


def write_fixtures(base):
    aggregate = Capture()
    bssid = bytes.fromhex("020000000001")
    essid = b"AuditAgg"
    aggregate.add(1000.0, beacon(bssid, essid, aggregate.seq))
    add_handshake(
        aggregate,
        1000.1,
        bssid,
        bytes.fromhex("020000001001"),
        essid,
        replay=1,
        m1_only=True,
    )
    # The second client's complete four-way exchange is what the BSSID
    # aggregation must select.
    add_handshake(
        aggregate,
        1000.2,
        bssid,
        bytes.fromhex("020000001002"),
        essid,
        replay=2,
    )
    aggregate.write(base / "handshake-aggregate.pcap")

    dual = Capture()
    pmkid_bssid = bytes.fromhex("020000000002")
    pmkid_essid = b"AuditPmkid"
    dual.add(2000.0, beacon(pmkid_bssid, pmkid_essid, dual.seq))
    add_handshake(
        dual,
        2000.1,
        pmkid_bssid,
        bytes.fromhex("020000002001"),
        pmkid_essid,
        pmkid_only=True,
    )

    fourway_bssid = bytes.fromhex("020000000003")
    fourway_essid = b"AuditFourway"
    dual.add(2000.2, beacon(fourway_bssid, fourway_essid, dual.seq))
    add_handshake(
        dual,
        2000.3,
        fourway_bssid,
        bytes.fromhex("020000002002"),
        fourway_essid,
        replay=7,
    )
    dual.write(base / "handshake-dual-path.pcap")

    retry = Capture()
    bssid = bytes.fromhex("020000000004")
    essid = b"AuditRetry"
    station = bytes.fromhex("020000004001")
    retry.add(3000.0, beacon(bssid, essid, retry.seq))
    add_handshake(
        retry,
        3000.1,
        bssid,
        station,
        essid,
        replay=11,
        anonce=b"A" * 32,
        snonce=b"B" * 32,
        corrupt_mic=True,
    )
    add_handshake(
        retry,
        3000.3,
        bssid,
        station,
        essid,
        replay=12,
        anonce=b"C" * 32,
        snonce=b"D" * 32,
    )
    retry.write(base / "handshake-retry.pcap")


if __name__ == "__main__":
    write_fixtures(Path(__file__).resolve().parent)
