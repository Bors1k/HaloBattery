"""Keychron devices over their receiver, cable, or K2 Pro custom Raw HID firmware.

The K2 Pro ANSI RGB protocol is defined by the target-specific QMK battery module in
``keychrone_k2_pro/BATTERY_PROTOCOL.md`` and ``keychron-k2-pro-battery.patch``.  It uses
the existing VIA Raw HID collection only: 3434:0220, FF60:0061, 32-byte payloads with
command AC/01.  No command is sent to a stock keyboard or to another collection.

Other Keychron devices use their receiver protocol without Keychron's own software.

Protocol from csutcliff/keychron-battery-dkms, which implements it for these ids:

  * 3434:d048  Keychron M5, over the cable
  * 3434:d028  the Ultra-Link 8K receiver

Keychron does not expose a standard HID battery report, so the level comes from the
vendor protocol:

  * the vendor collection on interface 4 - the interface number is the only handle
    that module uses to find it, and a probe logs what is actually present.
  * request: a 64-byte *feature* report `b3 06 00 ...` (report id 0xB3, command
    0x06 status).
  * reply: a 64-byte input report on the interrupt endpoint: `b4 06 ... <level> ...`,
    the battery in byte 20, accepted only when it is 100 or less.
  * up to three attempts, 100 ms apart, with a 500 ms wait for each reply.

The reply carries no charging flag, so none is reported.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from time import monotonic
from typing import List, Optional

import hid

from . import hidlist
from .base import DeviceStatus, Provider, hexdump, log
from .keychron_bt import KeychronBluetoothListener, is_k2_bluetooth_path

KEYCHRON_VID = 0x3434

USAGE_PAGE = 0
USAGE = 0
VENDOR_INTERFACE = 4            # the interface the module binds to

REPORT_ID_CMD = 0xB3
REPORT_ID_RESP = 0xB4
CMD_STATUS = 0x06
BATTERY_OFFSET = 20
REPORT_SIZE = 64

ATTEMPTS = 3
RETRY_DELAY = 0.1               # 100 ms between attempts
READ_TIMEOUT_MS = 500           # the module waits 500 ms for the reply
FLUSH_TIMEOUT_MS = 30

K2_PRO_PID = 0x0220
K2_PRO_NAME = "Keychron K2 Pro"
K2_USAGE_PAGE = 0xFF60
K2_USAGE = 0x0061
K2_REPORT_SIZE = 32
K2_COMMAND = 0xAC
K2_REQUEST = 0x01
K2_RESPONSE = 0x81
K2_VERSION = 0x01
K2_PAYLOAD_SIZE = 13
K2_PERCENT_VALID = 0x0010
K2_VALID = 1
K2_STALE = 2
K2_QUERY_INTERVAL_S = 60.0

PIDS = {
    0xD028: "Keychron Ultra-Link 8K",
    0xD048: "Keychron M5",
    0xD026: "Keychron Nape Pro",      # "Keychron Link-KM" (#270): vendor channel on iface 1
}


def make_request() -> List[int]:
    return [REPORT_ID_CMD, CMD_STATUS] + [0x00] * (REPORT_SIZE - 2)


def _checksum(frame) -> int:
    return sum(frame[:30]) & 0xFFFF


def make_k2_request() -> List[int]:
    """Report-id zero followed by the documented 32-byte AC/01 payload."""
    payload = [0] * K2_REPORT_SIZE
    payload[:3] = [K2_COMMAND, K2_REQUEST, K2_VERSION]
    checksum = _checksum(payload)
    payload[30:32] = [checksum & 0xFF, checksum >> 8]
    return [0] + payload


@dataclass(frozen=True)
class K2Reading:
    level: Optional[int]
    stale: bool
    usb_power: bool
    voltage_mv: Optional[int]
    age_s: Optional[int]


def parse_k2_reply(report) -> Optional[K2Reading]:
    """Validate and parse protocol v1, accepting hidapi with or without report id 0."""
    if not report:
        return None
    frame = list(report)
    if len(frame) == K2_REPORT_SIZE + 1 and frame[0] == 0:
        frame = frame[1:]
    if len(frame) != K2_REPORT_SIZE:
        return None
    if frame[:3] != [K2_COMMAND, K2_RESPONSE, K2_VERSION]:
        return None
    if frame[3] != 0 or frame[4] != K2_PAYLOAD_SIZE:
        return None
    if frame[30] | frame[31] << 8 != _checksum(frame):
        return None

    flags = frame[8] | frame[9] << 8
    validity = frame[12]
    raw_level = frame[5]
    has_level = bool(flags & K2_PERCENT_VALID)
    if validity == 0:
        level = None
    elif validity in (K2_VALID, K2_STALE) and has_level and 0 <= raw_level <= 100:
        level = raw_level
    else:
        level = None
    voltage = frame[6] | frame[7] << 8
    raw_age = int.from_bytes(bytes(frame[14:18]), "little")
    return K2Reading(level, validity == K2_STALE, bool(flags & 0x0001),
                     voltage or None, None if raw_age == 0xFFFFFFFF else raw_age)


def parse_level(r) -> Optional[int]:
    """Percent from a status reply, or None when this is not one."""
    if not r or len(r) <= BATTERY_OFFSET:
        return None
    if r[0] != REPORT_ID_RESP or r[1] != CMD_STATUS:
        return None
    level = r[BATTERY_OFFSET]
    return level if 0 <= level <= 100 else None


class KeychronProvider(Provider):
    name = "keychron"

    def __init__(self, bluetooth_listener=None):
        self._diag: List[str] = []
        self.bluetooth = (bluetooth_listener if bluetooth_listener is not None
                          else KeychronBluetoothListener())
        self._k2_last_query: Optional[float] = None
        self._k2_cached: Optional[K2Reading] = None

    def _pick(self, infos: List[dict]) -> Optional[dict]:
        for d in infos:
            if d.get("interface_number") == VENDOR_INTERFACE:
                return d
        # the Nape Pro's Link-KM receiver puts its vendor collection on interface 1
        # (ffc1:0001), not interface 4: pick the vendor page wherever it is (#270)
        vendor = [d for d in infos if (d.get("usage_page") or 0) >= 0xFF00]
        if vendor:
            self._diag.append(f"  no interface {VENDOR_INTERFACE} collection; using "
                              f"iface={vendor[0].get('interface_number')} "
                              f"{vendor[0].get('usage_page', 0):04x}:"
                              f"{vendor[0].get('usage', 0):04x}")
            return vendor[0]
        self._diag.append(f"  no interface {VENDOR_INTERFACE} collection; "
                          f"falling back to the first of {len(infos)}")
        return infos[0] if infos else None

    def _query_k2(self, path: bytes) -> Optional[K2Reading]:
        now = monotonic()
        if (self._k2_last_query is not None
                and 0 <= now - self._k2_last_query < K2_QUERY_INTERVAL_S):
            self._diag.append(f"  USB query rate-limited; cached reading "
                              f"({K2_QUERY_INTERVAL_S - (now - self._k2_last_query):.0f} s left)")
            return self._k2_cached
        # Set this before I/O: failures and device removal are rate-limited too.
        self._k2_last_query = now
        dev = hid.device()
        try:
            dev.open_path(path)
            for attempt in range(2):
                if attempt:
                    time.sleep(RETRY_DELAY)
                sent = dev.write(bytes(make_k2_request()))
                if sent is not None and sent < 0:
                    self._diag.append(f"  attempt {attempt + 1}: write refused ({sent})")
                    continue
                report = dev.read(K2_REPORT_SIZE + 1, READ_TIMEOUT_MS)
                if not report:
                    self._diag.append(f"  attempt {attempt + 1}: no reply")
                    continue
                self._diag.append(f"  attempt {attempt + 1} reply: {hexdump(report)}")
                parsed = parse_k2_reply(report)
                if parsed is not None:
                    self._k2_cached = parsed
                    return parsed
            self._diag.append("  no valid K2 Pro protocol response")
            return None
        except (OSError, IOError, ValueError) as e:
            self._diag.append(f"  K2 Pro exchange: {e}")
            return None
        finally:
            try:
                dev.close()
            except Exception:
                pass

    def _query(self, path: bytes) -> Optional[List[int]]:
        dev = hid.device()
        try:
            dev.open_path(path)
        except (OSError, IOError) as e:
            self._diag.append(f"  open: {e}")
            return None
        try:
            for attempt in range(ATTEMPTS):
                if attempt:
                    time.sleep(RETRY_DELAY)
                try:
                    dev.send_feature_report(make_request())
                except (OSError, IOError, ValueError) as e:
                    self._diag.append(f"  attempt {attempt + 1} send: {e}")
                    continue
                r = dev.read(REPORT_SIZE, READ_TIMEOUT_MS)
                if not r:
                    self._diag.append(f"  attempt {attempt + 1}: no reply")
                    continue
                self._diag.append(f"  attempt {attempt + 1} reply: {hexdump(r)}")
                if parse_level(r) is not None:
                    return list(r)
            self._diag.append("  no usable level in the replies")
            return None
        finally:
            try:
                dev.close()
            except Exception:
                pass

    def poll(self) -> List[DeviceStatus]:
        self._diag = []
        try:
            infos = hidlist.enumerate(KEYCHRON_VID)
        except Exception as e:  # pragma: no cover
            log.warning("hid.enumerate(keychron): %s", e)
            return []
        out = []
        seen = set()
        bluetooth_ok = self.bluetooth.start()
        bluetooth_reading = self.bluetooth.snapshot()
        k2_over_usb = False

        k2_infos = [d for d in infos if d.get("product_id") == K2_PRO_PID]
        k2_usb_infos = [d for d in k2_infos if not is_k2_bluetooth_path(d.get("path", ""))]
        k2 = next((d for d in k2_usb_infos if d.get("usage_page") == K2_USAGE_PAGE
                   and d.get("usage") == K2_USAGE), None)
        if k2_usb_infos and k2 is None:
            collections = ", ".join(
                f"{d.get('usage_page', 0):04x}:{d.get('usage', 0):04x}"
                for d in k2_usb_infos
            )
            self._diag.append(
                f"[Keychron] pid={K2_PRO_PID:04x} '{K2_PRO_NAME}': no "
                f"{K2_USAGE_PAGE:04x}:{K2_USAGE:04x} Raw HID collection "
                f"(found: {collections})"
            )
        elif k2 is not None:
            self._diag.append(f"[Keychron] pid={K2_PRO_PID:04x} '{K2_PRO_NAME}' "
                              f"iface={k2.get('interface_number')} "
                              f"{K2_USAGE_PAGE:04x}:{K2_USAGE:04x}")
            reading = self._query_k2(k2["path"])
            if reading is not None:
                self._diag.append(f"  battery={reading.level} voltage={reading.voltage_mv} "
                                  f"age={reading.age_s} stale={reading.stale} "
                                  f"usb_power={reading.usb_power}")
                out.append(DeviceStatus(f"keychron:{K2_PRO_PID:04x}", K2_PRO_NAME,
                                        reading.level, False, not reading.stale, "keychron",
                                        kind="keyboard", charging_known=False))
                k2_over_usb = True

        if bluetooth_reading is not None:
            self._diag.append(f"[Keychron Bluetooth] {K2_PRO_NAME}: "
                              f"{bluetooth_reading.level}% "
                              f"usb_power={bluetooth_reading.usb_power}")
            if not k2_over_usb:
                out.append(DeviceStatus(f"keychron:{K2_PRO_PID:04x}", K2_PRO_NAME,
                                        bluetooth_reading.level, False, True, "keychron",
                                        kind="keyboard", via="bluetooth",
                                        charging_known=False))
        elif bluetooth_ok:
            self._diag.append("[Keychron Bluetooth] listener active; awaiting a battery beacon")
        elif self.bluetooth.error:
            self._diag.append(f"[Keychron Bluetooth] listener unavailable: "
                              f"{self.bluetooth.error}")

        for pid in PIDS:
            mine = [d for d in infos if d["product_id"] == pid and d["path"] not in seen]
            if not mine:
                continue
            d = self._pick(mine)
            if d is None:
                continue
            seen.add(d["path"])
            name = PIDS[pid]
            self._diag.append(f"[Keychron] pid={pid:04x} '{name}' "
                              f"iface={d.get('interface_number')} "
                              f"{d.get('usage_page', 0):04x}:{d.get('usage', 0):04x}")
            reply = self._query(d["path"])
            level = parse_level(reply)
            if level is None:
                continue
            out.append(DeviceStatus(f"keychron:{pid:04x}", name, level, False, True,
                                    "keychron"))
        return out

    def diagnostics(self) -> List[str]:
        return list(self._diag)

    def close(self):
        self.bluetooth.close()
