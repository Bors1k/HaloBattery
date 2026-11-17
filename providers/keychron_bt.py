"""Passive Windows Raw Input listener for the K2 Pro Bluetooth battery beacon.

Hardware-confirmed on Keychron K2 Pro / Windows 11: Bluetooth Classic HID UUID
0x1124, Consumer Control collection Col03, report ``0a <usage-le16> 00 00 00 00``.
The device path contains ``VID&00023434_PID&0220&Col03``. Nothing is opened or
written; the listener only receives WM_INPUT reports for usage 000C:0001.
"""
from __future__ import annotations

import sys
import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional

REPORT_ID = 0x0A
REPORT_SIZE = 7
BATTERY_BASE = 0x0300
USB_POWER_BASE = 0x0380
MAX_PERCENT = 100
MAX_AGE_S = 360.0  # unchanged firmware beacon refresh is five minutes


@dataclass(frozen=True)
class BluetoothReading:
    level: int
    usb_power: bool
    received_at: float


def is_k2_bluetooth_path(path) -> bool:
    value = (path.decode("utf-8", errors="replace")
             if isinstance(path, bytes) else str(path)).lower()
    return ("{00001124-0000-1000-8000-00805f9b34fb}" in value
            and "_vid&00023434_pid&0220&" in value)


def is_k2_consumer_path(path: str) -> bool:
    value = str(path).lower()
    return is_k2_bluetooth_path(value) and "&col03#" in value


def decode_beacon(report) -> Optional[tuple[int, bool]]:
    data = bytes(report)
    if len(data) != REPORT_SIZE or data[0] != REPORT_ID:
        return None
    usage = data[1] | data[2] << 8
    if usage == 0:  # Consumer release: retain the preceding battery value
        return None
    if BATTERY_BASE <= usage <= BATTERY_BASE + MAX_PERCENT:
        return usage - BATTERY_BASE, False
    if USB_POWER_BASE <= usage <= USB_POWER_BASE + MAX_PERCENT:
        return usage - USB_POWER_BASE, True
    return None


class KeychronBluetoothListener:
    def __init__(self):
        self.wake: Optional[Callable[[], None]] = None
        self._reading: Optional[BluetoothReading] = None
        self._lock = threading.Lock()
        self._thread = None
        self._hwnd = None
        self._ready = threading.Event()
        self._ok = False
        self.error: Optional[str] = None

    def observe(self, path: str, report, now: Optional[float] = None) -> bool:
        if not is_k2_consumer_path(path):
            return False
        decoded = decode_beacon(report)
        if decoded is None:
            return False
        level, usb_power = decoded
        with self._lock:
            self._reading = BluetoothReading(
                level, usb_power, time.monotonic() if now is None else now
            )
        if self.wake is not None:
            self.wake()
        return True

    def snapshot(self, now: Optional[float] = None) -> Optional[BluetoothReading]:
        with self._lock:
            reading = self._reading
        current = time.monotonic() if now is None else now
        if reading is None or not 0 <= current - reading.received_at <= MAX_AGE_S:
            return None
        return reading

    def start(self) -> bool:
        if self._thread is None and sys.platform == "win32":
            self._thread = threading.Thread(target=self._run, daemon=True,
                                            name="keychron-bt-battery")
            self._thread.start()
            self._ready.wait(2)
        return self._ok

    def close(self):
        if self._hwnd:
            import ctypes
            user = ctypes.WinDLL("user32", use_last_error=True)
            user.PostMessageW(self._hwnd, 0x0010, 0, 0)
        if self._thread:
            self._thread.join(2)

    def _run(self):
        import ctypes as C
        from ctypes import wintypes as W
        from .base import log

        user = C.WinDLL("user32", use_last_error=True)
        kernel = C.WinDLL("kernel32", use_last_error=True)
        proc_type = C.WINFUNCTYPE(C.c_ssize_t, W.HWND, W.UINT, W.WPARAM, W.LPARAM)

        class WindowClass(C.Structure):
            _fields_ = [("style", W.UINT), ("proc", proc_type),
                        ("class_extra", C.c_int), ("window_extra", C.c_int),
                        ("instance", W.HINSTANCE), ("icon", W.HICON),
                        ("cursor", W.HANDLE), ("brush", W.HBRUSH),
                        ("menu", W.LPCWSTR), ("name", W.LPCWSTR)]

        class RawInputDevice(C.Structure):
            _fields_ = [("page", W.USHORT), ("usage", W.USHORT),
                        ("flags", W.DWORD), ("target", W.HWND)]

        class Header(C.Structure):
            _fields_ = [("kind", W.DWORD), ("size", W.DWORD),
                        ("device", W.HANDLE), ("param", W.WPARAM)]

        kernel.GetModuleHandleW.argtypes = [W.LPCWSTR]
        kernel.GetModuleHandleW.restype = W.HMODULE
        user.RegisterClassW.argtypes = [C.POINTER(WindowClass)]
        user.RegisterClassW.restype = W.ATOM
        user.CreateWindowExW.argtypes = [W.DWORD, W.LPCWSTR, W.LPCWSTR, W.DWORD,
                                         C.c_int, C.c_int, C.c_int, C.c_int,
                                         W.HWND, W.HMENU, W.HINSTANCE, C.c_void_p]
        user.CreateWindowExW.restype = W.HWND
        user.DefWindowProcW.argtypes = [W.HWND, W.UINT, W.WPARAM, W.LPARAM]
        user.DefWindowProcW.restype = C.c_ssize_t
        user.GetRawInputData.argtypes = [W.HANDLE, W.UINT, C.c_void_p,
                                         C.POINTER(W.UINT), W.UINT]
        user.GetRawInputData.restype = W.UINT
        user.GetRawInputDeviceInfoW.argtypes = [W.HANDLE, W.UINT, C.c_void_p,
                                                C.POINTER(W.UINT)]
        user.GetRawInputDeviceInfoW.restype = W.UINT
        user.RegisterRawInputDevices.argtypes = [C.POINTER(RawInputDevice), W.UINT, W.UINT]
        user.RegisterRawInputDevices.restype = W.BOOL
        user.GetMessageW.argtypes = [C.POINTER(W.MSG), W.HWND, W.UINT, W.UINT]
        user.DispatchMessageW.argtypes = [C.POINTER(W.MSG)]
        user.TranslateMessage.argtypes = [C.POINTER(W.MSG)]
        user.DestroyWindow.argtypes = [W.HWND]
        user.UnregisterClassW.argtypes = [W.LPCWSTR, W.HINSTANCE]
        user.PostQuitMessage.argtypes = [C.c_int]

        def path_for(handle):
            length = W.UINT()
            if user.GetRawInputDeviceInfoW(handle, 0x20000007, None, C.byref(length)) == 0xFFFFFFFF:
                return ""
            value = C.create_unicode_buffer(length.value + 1)
            if user.GetRawInputDeviceInfoW(handle, 0x20000007, value, C.byref(length)) == 0xFFFFFFFF:
                return ""
            return value.value

        def proc(hwnd, message, wp, lp):
            try:
                if message == 0x00FF:
                    size = W.UINT()
                    if user.GetRawInputData(lp, 0x10000003, None, C.byref(size), C.sizeof(Header)) != 0:
                        return user.DefWindowProcW(hwnd, message, wp, lp)
                    raw = C.create_string_buffer(size.value)
                    copied = user.GetRawInputData(lp, 0x10000003, raw, C.byref(size), C.sizeof(Header))
                    if copied == 0xFFFFFFFF or copied < C.sizeof(Header) + 8:
                        return user.DefWindowProcW(hwnd, message, wp, lp)
                    header = Header.from_buffer_copy(raw.raw)
                    if header.kind == 2:
                        offset = C.sizeof(Header)
                        report_size = int.from_bytes(raw.raw[offset:offset + 4], "little")
                        count = int.from_bytes(raw.raw[offset + 4:offset + 8], "little")
                        payload = raw.raw[offset + 8:]
                        path = path_for(header.device)
                        for index in range(count):
                            report = payload[index * report_size:(index + 1) * report_size]
                            self.observe(path, report)
                    return 0
                if message == 0x0010:
                    user.DestroyWindow(hwnd)
                    return 0
                if message == 0x0002:
                    user.PostQuitMessage(0)
                    return 0
            except Exception:
                log.exception("Keychron Bluetooth battery callback")
            return user.DefWindowProcW(hwnd, message, wp, lp)

        callback = proc_type(proc)
        instance = kernel.GetModuleHandleW(None)
        name = "HaloBatteryKeychronBt_" + str(id(self))
        window_class = WindowClass(0, callback, 0, 0, instance, None, None, None, None, name)
        registered = False
        try:
            if not user.RegisterClassW(C.byref(window_class)):
                raise C.WinError(C.get_last_error())
            self._hwnd = user.CreateWindowExW(0, name, name, 0, 0, 0, 0, 0,
                                              W.HWND(-3), None, instance, None)
            if not self._hwnd:
                raise C.WinError(C.get_last_error())
            rid = RawInputDevice(0x000C, 0x0001, 0x00000100, self._hwnd)
            if not user.RegisterRawInputDevices(C.byref(rid), 1, C.sizeof(rid)):
                raise C.WinError(C.get_last_error())
            registered = True
            self._ok = True
            self._ready.set()
            message = W.MSG()
            while user.GetMessageW(C.byref(message), None, 0, 0) > 0:
                user.TranslateMessage(C.byref(message))
                user.DispatchMessageW(C.byref(message))
        except Exception as exc:
            self.error = str(exc)
            log.exception("Keychron Bluetooth battery listener unavailable")
        finally:
            self._ok = False
            self._ready.set()
            if registered:
                rid = RawInputDevice(0x000C, 0x0001, 1, None)
                user.RegisterRawInputDevices(C.byref(rid), 1, C.sizeof(rid))
            if self._hwnd:
                user.DestroyWindow(self._hwnd)
                self._hwnd = None
            user.UnregisterClassW(name, instance)
