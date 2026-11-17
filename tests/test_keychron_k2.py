"""K2 Pro USB rate-limit and Bluetooth beacon tests; no hardware needed."""
import os
import sys
import types
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from providers import keychron as K  # noqa: E402
from providers import keychron_bt as B  # noqa: E402

K2_PATH = (r"\\?\HID#{00001124-0000-1000-8000-00805f9b34fb}"
           r"_VID&00023434_PID&0220&Col03#c&58c654f&2&0002"
           r"#{4d1e55b2-f16f-11cf-88cb-001111000030}")
K2_INFO = {"path": b"k2-via", "interface_number": 1,
           "usage_page": K.K2_USAGE_PAGE, "usage": K.K2_USAGE,
           "product_id": K.K2_PRO_PID}


def usb_reply(level=75):
    frame = [0] * K.K2_REPORT_SIZE
    frame[:6] = [K.K2_COMMAND, K.K2_RESPONSE, K.K2_VERSION, 0,
                 K.K2_PAYLOAD_SIZE, level]
    frame[8] = K.K2_PERCENT_VALID
    frame[12] = K.K2_VALID
    checksum = sum(frame[:30]) & 0xFFFF
    frame[30:32] = [checksum & 0xFF, checksum >> 8]
    return frame


class FakeDevice:
    def __init__(self, replies):
        self.replies = list(replies)
        self.writes = []

    def open_path(self, _path):
        pass

    def write(self, data):
        self.writes.append(bytes(data))
        return len(data)

    def read(self, _size, _timeout):
        return self.replies.pop(0) if self.replies else []

    def close(self):
        pass


class FakeBluetooth:
    error = None
    wake = None

    def start(self):
        return True

    def snapshot(self):
        return None

    def close(self):
        pass


class BluetoothTest(unittest.TestCase):
    def test_confirmed_capture_decodes_and_release_is_ignored(self):
        self.assertTrue(B.is_k2_consumer_path(K2_PATH))
        self.assertEqual((97, False), B.decode_beacon(bytes.fromhex("0a 61 03 00 00 00 00")))
        self.assertIsNone(B.decode_beacon(bytes.fromhex("0a 00 00 00 00 00 00")))

    def test_usb_power_range_and_unrelated_reports(self):
        self.assertEqual((100, True), B.decode_beacon(bytes.fromhex("0a e4 03 00 00 00 00")))
        self.assertIsNone(B.decode_beacon(bytes.fromhex("0a e9 00 00 00 00 00")))
        self.assertIsNone(B.decode_beacon(bytes.fromhex("09 61 03 00 00 00 00")))


class UsbRateLimitTest(unittest.TestCase):
    def setUp(self):
        self.saved = K.hid, K.hidlist, K.monotonic
        self.now = 100.0
        K.monotonic = lambda: self.now
        K.hidlist = types.SimpleNamespace(enumerate=lambda _vid=0: [dict(K2_INFO)])

    def tearDown(self):
        K.hid, K.hidlist, K.monotonic = self.saved

    def test_success_is_queried_at_most_once_per_minute(self):
        device = FakeDevice([usb_reply(75), usb_reply(76)])
        K.hid = types.SimpleNamespace(device=lambda: device)
        provider = K.KeychronProvider(bluetooth_listener=FakeBluetooth())
        self.assertEqual(75, provider.poll()[0].level)
        self.now += 5
        self.assertEqual(75, provider.poll()[0].level)
        self.assertEqual(1, len(device.writes))
        self.now += 55
        self.assertEqual(76, provider.poll()[0].level)
        self.assertEqual(2, len(device.writes))

    def test_timeout_gets_only_two_attempts_per_minute(self):
        device = FakeDevice([])
        K.hid = types.SimpleNamespace(device=lambda: device)
        provider = K.KeychronProvider(bluetooth_listener=FakeBluetooth())
        provider.poll()
        self.assertEqual(2, len(device.writes))
        self.now += 5
        provider.poll()
        self.assertEqual(2, len(device.writes))


if __name__ == "__main__":
    unittest.main()
