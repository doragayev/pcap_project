import unittest
from metrics import MetricsServer

class TestMetricsServer(unittest.TestCase):

    def test_record_packet_does_not_fail(self):
        """בדיקה ש-record_packet רצה בלי שגיאה"""
        MetricsServer.record_packet('tcp', 100)
        MetricsServer.record_packet('udp', 64)

    def test_record_packet_with_none_protocol(self):
        """בדיקה שפרוטוקול None מטופל"""
        MetricsServer.record_packet(None, 50)

    def test_record_elastic_write_success(self):
        """בדיקה שכתיבה מוצלחת לא נכשלת"""
        MetricsServer.record_elastic_write(True)

    def test_record_elastic_write_fail(self):
        """בדיקה שכתיבה כושלת לא נכשלת"""
        MetricsServer.record_elastic_write(False)


if __name__ == '__main__':
    unittest.main()
