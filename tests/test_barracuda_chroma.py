"""Tests for the captured Barracuda X Chroma MediaTek protocol."""
import types
import unittest

from providers import barracuda_chroma as B


PATH = b"barracuda-chroma"


def reply(command, value):
    data = [0] * B.REPORT_LEN
    data[0] = B.REPORT_ID
    data[1] = 0x02
    data[2] = 0x60
    data[6] = 0x05
    data[9] = 0x80
    data[10] = 0x80
    data[11] = command
    data[12] = 0x01
    data[13] = 0x01
    data[14] = value
    return data


class FakeDevice:
    def __init__(self, answers):
        self.answers = answers
        self.pending = []
        self.written = []
        self.closed = False

    def open_path(self, path):
        if path == b"gone":
            raise OSError("device disappeared")

    def write(self, data):
        frame = bytes(data)
        self.written.append(frame)
        command = frame[10]
        if command in self.answers:
            answer = self.answers[command]
            if answer is not None:
                self.pending.append(reply(command, answer))
        return len(frame)

    def read(self, size, timeout=0):
        return self.pending.pop(0) if self.pending else []

    def close(self):
        self.closed = True


class FrameTest(unittest.TestCase):
    def test_battery_frame_matches_the_synapse_capture(self):
        frame = B.frame_query(B.CMD_BATTERY)
        self.assertEqual(B.REPORT_LEN, len(frame))
        self.assertEqual([0x02, 0x00, 0x60, 0, 0, 0, 0x04, 0, 0, 0x80, 0x21], list(frame[:11]))
        self.assertEqual(0xC7, frame[62])

    def test_reply_accepts_report_id_present_or_absent(self):
        captured = reply(B.CMD_BATTERY, 0x60)
        self.assertEqual(96, B.parse_reply(captured, B.CMD_BATTERY))
        self.assertEqual(96, B.parse_reply(captured[1:], B.CMD_BATTERY))

    def test_short_wrong_and_garbage_replies_are_rejected(self):
        self.assertIsNone(B.parse_reply([], B.CMD_BATTERY))
        self.assertIsNone(B.parse_reply([0xFF] * B.REPORT_LEN, B.CMD_BATTERY))
        self.assertIsNone(B.parse_reply(reply(B.CMD_CHARGING, 1), B.CMD_BATTERY))


class PollTest(unittest.TestCase):
    INFO = [{"vendor_id": B.VID, "product_id": B.PID, "path": PATH,
             "usage_page": B.USAGE_PAGE, "usage": B.USAGE, "interface_number": 3}]

    def setUp(self):
        self.saved = B.hid, B.hidlist

    def tearDown(self):
        B.hid, B.hidlist = self.saved

    def poll(self, answers, infos=None):
        dev = FakeDevice(answers)
        B.hid = types.SimpleNamespace(device=lambda: dev)
        B.hidlist = types.SimpleNamespace(enumerate=lambda vid=0: list(self.INFO if infos is None else infos))
        return B.BarracudaChromaProvider().poll(), dev

    def test_captured_level_and_charging_are_displayed(self):
        out, dev = self.poll({B.CMD_BATTERY: 96, B.CMD_CHARGING: 0})
        self.assertEqual([(s.key, s.name, s.level, s.charging, s.online, s.kind) for s in out],
                         [(B.KEY, B.NAME, 96, False, True, "headset")])
        self.assertEqual([B.CMD_BATTERY, B.CMD_CHARGING], [frame[10] for frame in dev.written])
        self.assertTrue(dev.closed)

    def test_levels_zero_and_one_hundred_are_valid(self):
        for level in (0, 100):
            out, _ = self.poll({B.CMD_BATTERY: level, B.CMD_CHARGING: 1})
            self.assertEqual(level, out[0].level)
            self.assertTrue(out[0].charging)

    def test_out_of_range_level_is_not_displayed(self):
        out, _ = self.poll({B.CMD_BATTERY: 101})
        self.assertIsNone(out[0].level)
        self.assertFalse(out[0].online)

    def test_unknown_charging_state_keeps_level(self):
        out, _ = self.poll({B.CMD_BATTERY: 50, B.CMD_CHARGING: 7})
        self.assertEqual(50, out[0].level)
        self.assertFalse(out[0].charging_known)

    def test_missing_reply_and_disappearing_device_are_offline(self):
        out, _ = self.poll({})
        self.assertFalse(out[0].online)
        gone = [dict(self.INFO[0], path=b"gone")]
        out, _ = self.poll({}, gone)
        self.assertFalse(out[0].online)

    def test_unrelated_collection_is_not_opened(self):
        out, dev = self.poll({}, [dict(self.INFO[0], usage_page=0xFF13)])
        self.assertFalse(out[0].online)
        self.assertEqual([], dev.written)


if __name__ == "__main__":
    unittest.main()
