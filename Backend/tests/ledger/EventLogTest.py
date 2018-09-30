try:
    import unittest2 as unittest
except ImportError:
    import unittest
import os.path
from ledger.EventLog import EventLog


class EventLogTest(unittest.TestCase):

    def setUp(self):
        event_log_file_path = os.getcwd() + '\\..\\..\\ledger\\EventLog'
        if os.path.isfile(event_log_file_path):
            os.remove(event_log_file_path)

    def test_write_read(self):
        event_log = EventLog()
        message = "This is a message"
        event_log.write(message)
        print(event_log.read_last())
        self.assertTrue(message in event_log.read_last())
        print(event_log.read_all())
        self.assertTrue(message in event_log.read_all())

        message1 = "This is another message"
        event_log.write(message1)
        print(event_log.read_last())
        self.assertTrue(message1 in event_log.read_last())
        self.assertTrue(message not in event_log.read_last())
        print(event_log.read_all())
        self.assertTrue(message1 in event_log.read_all())
        self.assertTrue(message in event_log.read_all())

    def test_save_load(self):
        event_log = EventLog()
        message = "This is a message"
        event_log.write(message)
        event_log.close()

        event_log1 = EventLog()
        print(event_log1.read_last())
        self.assertTrue(message in event_log1.read_last())
        print(event_log1.read_all())
        self.assertTrue(message in event_log1.read_all())

    def test_close(self):
        event_log = EventLog()
        message = "This is a message"
        event_log.write(message)
        print(event_log.read_last())
        self.assertTrue(message in event_log.read_last())
        self.assertTrue(message in event_log.read_all())
        event_log.close()

        self.assertEqual(None, event_log.read_last())
        self.assertEqual(None, event_log.read_all())
