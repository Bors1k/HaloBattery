"""Passively trace Windows Raw Input Consumer Control HID reports.

This diagnostic registers only usage page 0x000C / usage 0x0001 and prints the
complete bytes delivered by WM_INPUT. It never opens a HID path or writes to a
device.

Run from the repository root, then use the Bluetooth keyboard and wait for its
battery beacon::

    py tools/raw_input_consumer_trace.py --seconds 15
"""
from __future__ import annotations

import argparse
import ctypes as C
import sys
import threading
import time
from ctypes import wintypes as W

WM_INPUT = 0x00FF
WM_CLOSE = 0x0010
WM_DESTROY = 0x0002
RID_INPUT = 0x10000003
RIDI_DEVICENAME = 0x20000007
RIM_TYPEHID = 2
RIDEV_REMOVE = 0x00000001
RIDEV_INPUTSINK = 0x00000100
ERROR = 0xFFFFFFFF


class RawInputDevice(C.Structure):
    _fields_ = [
        ("usage_page", W.USHORT),
        ("usage", W.USHORT),
        ("flags", W.DWORD),
        ("target", W.HWND),
    ]


class RawInputHeader(C.Structure):
    _fields_ = [
        ("kind", W.DWORD),
        ("size", W.DWORD),
        ("device", W.HANDLE),
        ("wparam", W.WPARAM),
    ]


def device_name(user, handle: W.HANDLE) -> str:
    length = W.UINT()
    if user.GetRawInputDeviceInfoW(handle, RIDI_DEVICENAME, None, C.byref(length)) == ERROR:
        return "<device-name-error>"
    if not length.value:
        return "<unnamed-device>"
    value = C.create_unicode_buffer(length.value + 1)
    if user.GetRawInputDeviceInfoW(handle, RIDI_DEVICENAME, value, C.byref(length)) == ERROR:
        return "<device-name-error>"
    return value.value


def trace(seconds: float) -> int:
    if sys.platform != "win32":
        print("This diagnostic requires Windows.", file=sys.stderr)
        return 2

    user = C.WinDLL("user32", use_last_error=True)
    kernel = C.WinDLL("kernel32", use_last_error=True)
    window_proc_type = C.WINFUNCTYPE(C.c_ssize_t, W.HWND, W.UINT, W.WPARAM, W.LPARAM)

    class WindowClass(C.Structure):
        _fields_ = [
            ("style", W.UINT),
            ("proc", window_proc_type),
            ("class_extra", C.c_int),
            ("window_extra", C.c_int),
            ("instance", W.HINSTANCE),
            ("icon", W.HICON),
            ("cursor", W.HANDLE),
            ("brush", W.HBRUSH),
            ("menu", W.LPCWSTR),
            ("name", W.LPCWSTR),
        ]

    kernel.GetModuleHandleW.argtypes = [W.LPCWSTR]
    kernel.GetModuleHandleW.restype = W.HMODULE
    user.RegisterClassW.argtypes = [C.POINTER(WindowClass)]
    user.RegisterClassW.restype = W.ATOM
    user.CreateWindowExW.argtypes = [
        W.DWORD, W.LPCWSTR, W.LPCWSTR, W.DWORD,
        C.c_int, C.c_int, C.c_int, C.c_int,
        W.HWND, W.HMENU, W.HINSTANCE, C.c_void_p,
    ]
    user.CreateWindowExW.restype = W.HWND
    user.DefWindowProcW.argtypes = [W.HWND, W.UINT, W.WPARAM, W.LPARAM]
    user.DefWindowProcW.restype = C.c_ssize_t
    user.GetRawInputData.argtypes = [W.HANDLE, W.UINT, C.c_void_p, C.POINTER(W.UINT), W.UINT]
    user.GetRawInputData.restype = W.UINT
    user.GetRawInputDeviceInfoW.argtypes = [W.HANDLE, W.UINT, C.c_void_p, C.POINTER(W.UINT)]
    user.GetRawInputDeviceInfoW.restype = W.UINT
    user.RegisterRawInputDevices.argtypes = [C.POINTER(RawInputDevice), W.UINT, W.UINT]
    user.RegisterRawInputDevices.restype = W.BOOL
    user.GetMessageW.argtypes = [C.POINTER(W.MSG), W.HWND, W.UINT, W.UINT]
    user.DispatchMessageW.argtypes = [C.POINTER(W.MSG)]
    user.DispatchMessageW.restype = C.c_ssize_t
    user.TranslateMessage.argtypes = [C.POINTER(W.MSG)]
    user.PostMessageW.argtypes = [W.HWND, W.UINT, W.WPARAM, W.LPARAM]
    user.DestroyWindow.argtypes = [W.HWND]
    user.UnregisterClassW.argtypes = [W.LPCWSTR, W.HINSTANCE]
    user.PostQuitMessage.argtypes = [C.c_int]

    def window_proc(hwnd, message, _wparam, lparam):
        if message == WM_INPUT:
            size = W.UINT()
            if user.GetRawInputData(lparam, RID_INPUT, None, C.byref(size), C.sizeof(RawInputHeader)) != 0:
                return user.DefWindowProcW(hwnd, message, _wparam, lparam)
            raw = C.create_string_buffer(size.value)
            copied = user.GetRawInputData(
                lparam, RID_INPUT, raw, C.byref(size), C.sizeof(RawInputHeader)
            )
            if copied == ERROR or copied < C.sizeof(RawInputHeader) + 8:
                return user.DefWindowProcW(hwnd, message, _wparam, lparam)
            header = RawInputHeader.from_buffer_copy(raw.raw)
            if header.kind != RIM_TYPEHID:
                return user.DefWindowProcW(hwnd, message, _wparam, lparam)
            offset = C.sizeof(RawInputHeader)
            report_size = int.from_bytes(raw.raw[offset:offset + 4], "little")
            report_count = int.from_bytes(raw.raw[offset + 4:offset + 8], "little")
            payload = raw.raw[offset + 8:offset + 8 + report_size * report_count]
            path = device_name(user, header.device)
            stamp = time.strftime("%H:%M:%S")
            for index in range(report_count):
                report = payload[index * report_size:(index + 1) * report_size]
                print(f"{stamp} device={path}")
                print(f"  report {index + 1}/{report_count} size={report_size}: {report.hex(' ')}", flush=True)
            return 0
        if message == WM_CLOSE:
            user.DestroyWindow(hwnd)
            return 0
        if message == WM_DESTROY:
            user.PostQuitMessage(0)
            return 0
        return user.DefWindowProcW(hwnd, message, _wparam, lparam)

    callback = window_proc_type(window_proc)
    instance = kernel.GetModuleHandleW(None)
    class_name = f"HaloBatteryConsumerTrace_{id(callback)}"
    window_class = WindowClass(0, callback, 0, 0, instance, None, None, None, None, class_name)
    if not user.RegisterClassW(C.byref(window_class)):
        raise C.WinError(C.get_last_error())

    hwnd = user.CreateWindowExW(
        0, class_name, class_name, 0, 0, 0, 0, 0,
        W.HWND(-3), None, instance, None,
    )
    if not hwnd:
        user.UnregisterClassW(class_name, instance)
        raise C.WinError(C.get_last_error())

    registered = False
    try:
        rid = RawInputDevice(0x000C, 0x0001, RIDEV_INPUTSINK, hwnd)
        if not user.RegisterRawInputDevices(C.byref(rid), 1, C.sizeof(rid)):
            raise C.WinError(C.get_last_error())
        registered = True
        timer = threading.Timer(seconds, lambda: user.PostMessageW(hwnd, WM_CLOSE, 0, 0))
        timer.daemon = True
        timer.start()
        print(f"Listening for Consumer Control Raw Input for {seconds:g} seconds.")
        print("Disconnect USB, use the Bluetooth keyboard, then wait up to 4 seconds.", flush=True)
        message = W.MSG()
        while user.GetMessageW(C.byref(message), None, 0, 0) > 0:
            user.TranslateMessage(C.byref(message))
            user.DispatchMessageW(C.byref(message))
        timer.cancel()
    finally:
        if registered:
            remove = RawInputDevice(0x000C, 0x0001, RIDEV_REMOVE, None)
            user.RegisterRawInputDevices(C.byref(remove), 1, C.sizeof(remove))
        if user.IsWindow(hwnd):
            user.DestroyWindow(hwnd)
        user.UnregisterClassW(class_name, instance)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seconds", type=float, default=15.0,
                        help="capture duration (default: 15)")
    args = parser.parse_args()
    if args.seconds <= 0:
        parser.error("--seconds must be positive")
    return trace(args.seconds)


if __name__ == "__main__":
    raise SystemExit(main())
