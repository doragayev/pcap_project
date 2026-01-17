"""
 חשיפת מטריקות ל-Prometheus
"""

import os
import logging
from prometheus_client import Counter, Histogram, start_http_server

logger = logging.getLogger(__name__)

packets_total = Counter(
    'pcap_packets_total',
    'Total number of packets processed',
    ['protocol']
)

bytes_total = Counter(
    'pcap_bytes_total',
    'Total bytes processed',
    ['protocol']
)

elastic_write_total = Counter(
    'pcap_elastic_write_total',
    'Total Elasticsearch write operations',
    ['status']
)

packet_processing_duration = Histogram(
    'pcap_packet_processing_seconds',
    'Time spent processing packets',
    ['protocol']
)


class MetricsServer:
    def __init__(self, port=None):
        self.port = port or int(os.getenv('METRICS_PORT', '9100'))
        logger.info(f"Metrics server will run on port {self.port}")

    def start(self):
        start_http_server(self.port)
        logger.info(f"Prometheus metrics server started on http://localhost:{self.port}/metrics")

    @staticmethod
    def record_packet(protocol, packet_length):
        protocol = protocol or 'other'
        packets_total.labels(protocol=protocol).inc()
        bytes_total.labels(protocol=protocol).inc(packet_length)

    @staticmethod
    def record_elastic_write(success):
        status = 'success' if success else 'fail'
        elastic_write_total.labels(status=status).inc()


def start_metrics_server(port=None):
    metrics_server = MetricsServer(port)
    metrics_server.start()
    return metrics_server


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    server = start_metrics_server()
    
    import time
    server.record_packet('tcp', 100)
    server.record_packet('udp', 64)
    server.record_elastic_write(True)
    
    logger.info("Metrics server running. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Stopping metrics server")
