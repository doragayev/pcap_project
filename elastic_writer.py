#!/usr/bin/env python3
"""
Elasticsearch Writer - כתיבה ל-Elasticsearch
"""

import os
import logging
from datetime import datetime
from typing import Dict
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk
import time

logger = logging.getLogger(__name__)


class ElasticWriter:

    def __init__(self):
        elastic_url = os.getenv('ELASTIC_URL', 'http://localhost:9200')
        elastic_index = os.getenv('ELASTIC_INDEX', 'pcap-packets')
        username = os.getenv('ELASTIC_USERNAME')
        password = os.getenv('ELASTIC_PASSWORD')

        es_config = {'hosts': [elastic_url]}
        if username and password:
            es_config['basic_auth'] = (username, password)

        self.es = Elasticsearch(**es_config)
        self.index = elastic_index
        self.use_date_index = os.getenv('ELASTIC_USE_DATE_INDEX', 'false').lower() == 'true'

        logger.info(f"Connected to Elasticsearch: {elastic_url}")
        logger.info(f"Using index: {self.index}")
    
    def get_index_name(self):
        if self.use_date_index:
            date_str = datetime.now().strftime('%Y.%m.%d')
            return f"{self.index}-{date_str}"
        return self.index
    
    def write_packet(self, packet_info, max_retries: int = 3):
        index_name = self.get_index_name()
        ts_raw = packet_info.get('timestamp_raw', packet_info.get('timestamp'))
        if isinstance(ts_raw, str):
            ts_iso = ts_raw
        elif ts_raw is not None:
            ts_iso = datetime.fromtimestamp(float(ts_raw)).isoformat()
        else:
            raise ValueError("Missing timestamp in packet_info")
        
        doc = {
            'timestamp': ts_iso,
            'src_ip': packet_info.get('src_ip'),
            'dst_ip': packet_info.get('dst_ip'),
            'src_port': packet_info.get('src_port'),
            'dst_port': packet_info.get('dst_port'),
            'l4_protocol': packet_info.get('l4_protocol', 'other'),
            'packet_length': packet_info.get('packet_length', 0),
            '@timestamp': ts_iso
        }
        
        for attempt in range(max_retries):
            try:
                self.es.index(index=index_name, document=doc)
                logger.debug(f"Wrote packet {packet_info.get('packet_number')} to Elasticsearch")
                return True
            except Exception as e:
                if attempt < max_retries - 1:
                    wait_time = 2 ** attempt
                    logger.warning(f"Failed to write to Elasticsearch (attempt {attempt+1}/{max_retries}): {e}. Retrying in {wait_time}s...")
                    time.sleep(wait_time)
                else:
                    logger.error(f"Failed to write to Elasticsearch after {max_retries} attempts: {e}")
                    return False
        
        return False
    
    def bulk_write(self, packets: list, max_retries: int = 3) -> Dict[str, int]:
        index_name = self.get_index_name()
        actions = []
        
        for packet_info in packets:
            ts_raw = packet_info.get('timestamp_raw', packet_info.get('timestamp'))
            if isinstance(ts_raw, str):
                ts_iso = ts_raw
            else:
                ts_iso = datetime.fromtimestamp(float(ts_raw)).isoformat()
            
            doc = {
                'timestamp': ts_iso,
                'src_ip': packet_info.get('src_ip'),
                'dst_ip': packet_info.get('dst_ip'),
                'src_port': packet_info.get('src_port'),
                'dst_port': packet_info.get('dst_port'),
                'l4_protocol': packet_info.get('l4_protocol', 'other'),
                'packet_length': packet_info.get('packet_length', 0),
                '@timestamp': ts_iso
            }
            actions.append({
                '_index': index_name,
                '_source': doc
            })
        
        success_count = 0
        fail_count = 0
        
        for attempt in range(max_retries):
            try:
                results = bulk(self.es, actions, raise_on_error=False)
                success_count = results[0]
                fail_count = len(actions) - success_count
                logger.info(f"Bulk write: {success_count} successful, {fail_count} failed")
                return {'success': success_count, 'fail': fail_count}
            except Exception as e:
                if attempt < max_retries - 1:
                    wait_time = 2 ** attempt
                    logger.warning(f"Bulk write failed (attempt {attempt+1}/{max_retries}): {e}. Retrying in {wait_time}s...")
                    time.sleep(wait_time)
                else:
                    logger.error(f"Bulk write failed after {max_retries} attempts: {e}")
                    return {'success': 0, 'fail': len(actions)}
        
        return {'success': success_count, 'fail': fail_count}
