"""Razer Barracuda X Chroma (2.4 GHz receiver 1532:0574).

Protocol decoded from ``file.pcapng``, a USBPcap capture supplied by the device
owner while Razer Synapse refreshed the battery page.  The MediaTek receiver
uses 64-byte report-id 0x02 frames on its ff14:0001 collection.  Synapse sends
command 0x21 for battery and 0x2a for charging; the reply echoes the command and
places the one-byte value at offset 14.
"""
from __future__ import annotations

from typing import List, Optional

import hid

from . import hidlist
from .base import DeviceStatus, Provider, hexdump

VID = 0x1532
PID = 0x0574
NAME = "Razer Barracuda X Chroma"
KEY = "barracuda-chroma:0574"

USAGE_PAGE = 0xFF14
USAGE = 0x0001
REPORT_ID = 0x02
REPORT_LEN = 64
CMD_BATTERY = 0x21
CMD_CHARGING = 0x2A
ATTEMPTS = 3
READ_TIMEOUT_MS = 200


def frame_query(command: int) -> bytes:
    frame = bytearray(REPORT_LEN)
    frame[0] = REPORT_ID
    frame[2] = 0x60
    frame[6] = 0x04
    frame[9] = 0x80
    frame[10] = command
    frame[62] = 0
    for value in frame[:62]:
        frame[62] ^= value
    return bytes(frame)


def parse_reply(data, command: int) -> Optional[int]:
    reply = list(data or [])
    for off in (0, -1):
        cmd = 11 + off
        value = 14 + off
        if (len(reply) > value and reply[cmd] == command and
                reply[cmd + 1] == 0x01 and reply[cmd + 2] == 0x01):
            return reply[value]
    return None


def is_candidate(info: dict) -> bool:
    return info.get("usage_page") == USAGE_PAGE and info.get("usage") == USAGE


class BarracudaChromaProvider(Provider):
    name = "barracuda_chroma"

    def __init__(self):
        self._diag: List[str] = []

    def _query(self, dev, command: int) -> Optional[int]:
        for attempt in range(ATTEMPTS):
            try:
                while dev.read(REPORT_LEN, 10):
                    pass
                sent = dev.write(frame_query(command))
                if sent is not None and sent < 0:
                    self._diag.append(f"    cmd {command:02x}: write refused ({sent})")
                    return None
                for _ in range(4):
                    reply = dev.read(REPORT_LEN, READ_TIMEOUT_MS)
                    if not reply:
                        continue
                    value = parse_reply(reply, command)
                    if value is not None:
                        self._diag.append(
                            f"    cmd {command:02x} attempt {attempt + 1}: {hexdump(reply, 20)}")
                        return value
            except (OSError, IOError, ValueError) as exc:
                self._diag.append(f"    cmd {command:02x}: {exc}")
                return None
            self._diag.append(f"    cmd {command:02x} attempt {attempt + 1}: no reply")
        return None

    def poll(self) -> List[DeviceStatus]:
        self._diag = []
        try:
            infos = hidlist.enumerate(VID)
        except Exception as exc:
            self._diag.append(f"  enumerate: {exc}")
            return []
        mine = [info for info in infos if info.get("product_id") == PID]
        if not mine:
            return []
        candidate = next((info for info in mine if is_candidate(info)), None)
        if candidate is None:
            self._diag.append("  no ff14:0001 collection on the receiver")
            return [DeviceStatus(KEY, NAME, None, False, False, self.name, kind="headset")]

        self._diag.append("  pid=0574 ff14:0001: %s" % hexdump(candidate.get("path")))
        dev = hid.device()
        try:
            dev.open_path(candidate["path"])
            level = self._query(dev, CMD_BATTERY)
            if level is None or not 0 <= level <= 100:
                if level is not None:
                    self._diag.append(f"    battery level out of range: {level}")
                return [DeviceStatus(KEY, NAME, None, False, False, self.name, kind="headset")]
            charging_value = self._query(dev, CMD_CHARGING)
            charging_known = charging_value in (0, 1)
            if charging_value is not None and not charging_known:
                self._diag.append(f"    unknown charging state: {charging_value}")
            return [DeviceStatus(KEY, NAME, level, charging_value == 1, True, self.name,
                                 kind="headset", charging_known=charging_known)]
        except (OSError, IOError, ValueError) as exc:
            self._diag.append(f"    open/read: {exc}")
            return [DeviceStatus(KEY, NAME, None, False, False, self.name, kind="headset")]
        finally:
            try:
                dev.close()
            except Exception:
                pass

    def diagnostics(self) -> List[str]:
        return list(self._diag)
