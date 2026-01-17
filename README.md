# PCAP Analyzer

שירות קטן שקורא קבצי PCAP, מחלץ מידע מה-packets, שומר ב-Elasticsearch וחושף מטריקות ל-Prometheus.

## מה השירות עושה

השירות קורא קובץ PCAP ומחלץ מכל packet:
- `timestamp` - מתי נשלח
- `src_ip`, `dst_ip` - כתובות IP
- `src_port`, `dst_port` - פורטים
- `l4_protocol` - פרוטוקול (tcp/udp/icmp/arp/other)
- `packet_length` - גודל ה-packet

כל packet נשמר כ-document ב-Elasticsearch, והשירות חושף מטריקות בפורמט Prometheus.

## דרישות

- Python 3.8+
- pip
- Elasticsearch (ניתן להריץ עם docker-compose)

## התקנה

```bash
pip3 install -r requirements.txt
# או: pip install -r requirements.txt
```

## הרצת Elasticsearch ו-Kibana

```bash
docker-compose up -d
```

לבדיקה:
```bash
curl http://localhost:9200
```

Kibana יהיה זמין ב: http://localhost:5601

לעצירה:
```bash
docker-compose down
```

## משתני סביבה

```bash
# נתיב לקובץ PCAP (אופציונלי - ניתן להעביר גם ב-argument)
PCAP_FILE=samples/packetcapture-igb1-20260113105742.pcap

# Elasticsearch
ELASTIC_URL=http://localhost:9200
ELASTIC_INDEX=pcap-packets
ELASTIC_USERNAME=  # אופציונלי
ELASTIC_PASSWORD=  # אופציונלי

# Prometheus Metrics
METRICS_PORT=9100
```

## הרצה

```bash
# עם CLI argument
python3 main.py --pcap samples/packetcapture-igb1-20260113105742.pcap
# או: python main.py --pcap samples/packetcapture-igb1-20260113105742.pcap

# או עם משתנה סביבה
export PCAP_FILE=samples/packetcapture-igb1-20260113105742.pcap
python3 main.py
# או: python main.py
```

## בדיקת מטריקות

השירות חושף endpoint `/metrics` בפורמט Prometheus על פורט 9100 (ברירת מחדל).

```bash
curl http://localhost:9100/metrics
```

או פתח בדפדפן: http://localhost:9100/metrics

**המטריקות:**
- `pcap_packets_total{protocol="tcp|udp|icmp|other"}` - סה"כ packets
- `pcap_bytes_total{protocol="tcp|udp|icmp|other"}` - סה"כ bytes
- `pcap_elastic_write_total{status="success|fail"}` - כתיבות ל-Elasticsearch

## קובץ PCAP לדוגמה

השתמש בקובץ: `samples/packetcapture-igb1-20260113105742.pcap`

## דוגמה ל-Document ב-Elasticsearch

```json
{
  "timestamp": "2026-01-13T20:57:44.245161",
  "src_ip": "10.10.10.67",
  "dst_ip": "57.144.221.33",
  "src_port": 61839,
  "dst_port": 443,
  "l4_protocol": "tcp",
  "packet_length": 91,
  "@timestamp": "2026-01-13T20:57:44.245161"
}
```

## מבנה הפרויקט

```
.
├── main.py              # נקודת כניסה ראשית
├── pcap_reader.py       # קריאת וניתוח PCAP
├── elastic_writer.py    # כתיבה ל-Elasticsearch (עם retry logic)
├── metrics.py           # מטריקות Prometheus
├── requirements.txt     # תלויות Python
├── docker-compose.yml   # Elasticsearch + Kibana
└── samples/            # קבצי PCAP לדוגמה
    └── packetcapture-igb1-20260113105742.pcap
```
