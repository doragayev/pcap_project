#!/usr/bin/env python3
"""
=קורא קובץ PCAP, שומר ב-Elasticsearch וחושף מטריקות ל-Prometheus
"""

import os
import sys
import argparse
import logging
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(description='PCAP Analyzer')
    parser.add_argument(
        '--pcap',
        type=str,
        default=os.getenv('PCAP_FILE', ''),
        help='Path to PCAP file (or set PCAP_FILE env var)'
    )
    
    args = parser.parse_args()
    
    pcap_file = args.pcap
    if not pcap_file:
        logger.error("No PCAP file specified. Use --pcap or set PCAP_FILE env var")
        sys.exit(1)
    
    if not Path(pcap_file).exists():
        logger.error(f"PCAP file not found: {pcap_file}")
        sys.exit(1)
    
    logger.info(f"Starting PCAP analysis for: {pcap_file}")
    
    from pcap_reader import read_pcap
    from elastic_writer import ElasticWriter
    from metrics import start_metrics_server
    
    logger.info("Starting Prometheus metrics server...")
    metrics_server = start_metrics_server()
    
    logger.info("Initializing Elasticsearch connection...")
    try:
        es_writer = ElasticWriter()
    except Exception as e:
        logger.error(f"Failed to connect to Elasticsearch: {e}")
        logger.warning("Continuing without Elasticsearch (metrics will still work)")
        es_writer = None
    
    logger.info("Processing PCAP file...")
    processed_count = 0
    success_count = 0
    fail_count = 0
    
    try:
        for packet_info in read_pcap(pcap_file):
            processed_count += 1
            
            protocol = packet_info.get('l4_protocol', 'other')
            packet_length = packet_info.get('packet_length', 0)
            metrics_server.record_packet(protocol, packet_length)
            
            if es_writer:
                success = es_writer.write_packet(packet_info)
                if success:
                    success_count += 1
                    metrics_server.record_elastic_write(True)
                else:
                    fail_count += 1
                    metrics_server.record_elastic_write(False)
            
            if processed_count % 1000 == 0:
                logger.info(f"Processed {processed_count} packets...")
        
        logger.info("=" * 60)
        logger.info("PCAP processing completed!")
        logger.info(f"Total packets processed: {processed_count}")
        if es_writer:
            logger.info(f"Elasticsearch writes - Success: {success_count}, Failed: {fail_count}")
        logger.info(f"Metrics available at: http://localhost:{metrics_server.port}/metrics")
        logger.info("=" * 60)
        logger.info("Press Ctrl+C to stop the metrics server")
        
        import time
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        logger.info("\nShutting down...")
    except Exception as e:
        logger.error(f"Error processing PCAP: {e}", exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()
