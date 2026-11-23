#!/usr/bin/env bash
# =============================================================================
# lan_mqtt_tls_toolkit.sh  -  Nhom 11, phan MQTT / bao mat (Vu Hoang Lan)
#
# Gom tat ca lenh va code da dung de:
#   (1) kiem chung bang byte MQTT QoS 0 / QoS 1 bang tcpdump + tshark
#   (2) tao chung chi TLS, cau hinh Mosquitto cong 8883
#   (3) do chi phi TLS (byte them moi tin, tong byte ca phien)
#   (4) do thoi gian ket noi co va khong TLS (script Python, paho-mqtt)
#   (5) demo K9a: xem noi dung goi khi khong TLS va co TLS
#   (6) tao ban TLS cua gw_mqtt.py / srv_mqtt.py (dua tren code cua Duy Anh)
#
# Cach dung (trong Ubuntu/WSL):   bash lan_mqtt_tls_toolkit.sh <lenh>
#   certs        tao CA (neu chua co) va cap lai chung chi server (co IP 10.0.3.2)
#   broker       bat Mosquitto nghe ca 1883 va 8883
#   bytes [off]  do byte MQTT QoS 0 va QoS 1 khong TLS (off = tat TCP timestamp,
#                mac dinh; "on" = giu timestamp, ky vong lech +12 byte)
#   tls-bytes    do chi phi TLS tren cung mot ket noi (20 tin)
#   venv         cai paho-mqtt 2.x vao ~/iot (can cho handshake va adapters)
#   handshake    do thoi gian ket noi co/khong TLS (20 lan moi loai)
#   k9-view      demo K9a: noi dung goi khong TLS va co TLS
#   adapters     ghi gw_mqtt_tls.py, srv_mqtt_tls.py vao thu muc hien tai
#   all          certs -> broker -> bytes -> tls-bytes -> handshake -> k9-view
#
# Luu y:
#  - Moi lan do tren loopback (lo) trong mot may, chua phai trong Mininet.
#  - K9b (flood + iptables) KHONG co o day: phu thuoc topology va host `att`
#    cua Gia Bao, chua duoc thu.
#  - Ghi AI Log neu dung AI de viet/sua cac script nay.
# =============================================================================

WORK="$HOME/mqtt_tls"
PCAP="$HOME/mqtt_pcap"
mkdir -p "$WORK" "$PCAP"

# --- tien ich -----------------------------------------------------------------
need_sudo() { sudo -v || { echo "Can quyen sudo"; exit 1; }; }

set_ts() { sudo sysctl -q -w net.ipv4.tcp_timestamps="$1" >/dev/null 2>&1 || echo "(canh bao: khong dat duoc tcp_timestamps=$1)"; }

# cap <file> <port> <lenh...> : bat goi tren lo trong luc chay <lenh>
cap() {
  local file="$1" port="$2"; shift 2
  sudo rm -f "$file"
  sudo timeout 40 tcpdump -i lo -Z "$USER" -w "$file" "port $port" >/dev/null 2>&1 &
  local pid=$!
  sleep 2
  "$@"
  sleep 1
  sudo pkill -INT -f "tcpdump -i lo -Z $USER -w $file" 2>/dev/null
  wait "$pid" 2>/dev/null
}

pub_each() {      # moi tin mot ket noi moi: pub_each <port> <qos> [tls]
  local port="$1" qos="$2" tls="$3" extra=()
  [ -n "$tls" ] && extra=(--cafile "$WORK/ca.crt")
  for i in $(seq 1 20); do
    mosquitto_pub -h 127.0.0.1 -p "$port" "${extra[@]}" -t sensor1 -m "0123456789" -q "$qos"
  done
}

pub_stream() {    # 20 tin tren CUNG mot ket noi: pub_stream <port> [tls]
  local port="$1" tls="$2" extra=()
  [ -n "$tls" ] && extra=(--cafile "$WORK/ca.crt")
  for i in $(seq 1 20); do echo 0123456789; sleep 0.2; done \
    | mosquitto_pub -h 127.0.0.1 -p "$port" "${extra[@]}" -t sensor1 -l -q 0
}

# --- 1. chung chi -------------------------------------------------------------
cmd_certs() {
  cd "$WORK" || exit 1
  if [ ! -f ca.crt ]; then
    openssl genrsa -out ca.key 2048
    openssl req -x509 -new -nodes -key ca.key -sha256 -days 365 -subj "/CN=Nhom11-CA" -out ca.crt
  else
    echo "Giu nguyen CA cu (ca.crt khong doi, ban gui cho Thanh Lam van dung duoc)."
  fi
  [ -f server.key ] || openssl genrsa -out server.key 2048
  openssl req -new -key server.key -subj "/CN=localhost" -out server.csr
  printf "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:10.0.3.2\n" > san.ext
  openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -days 365 -sha256 -extfile san.ext
  ls "$WORK"
  echo "Chi gui ca.crt cho nguoi khac. KHONG gui ca.key va server.key."
}

# --- 2. broker ----------------------------------------------------------------
cmd_broker() {
  need_sudo
  # Chay bang root (vi du trong Mininet) thi Mosquitto ha quyen xuong user "mosquitto"
  # va khong doc duoc server.key cua ban; khi do dung "user root" (chi trong lab).
  local asroot=""; [ "$(id -u)" -eq 0 ] && asroot="user root"
  cat > "$WORK/mosq_both.conf" << EOF
$asroot
allow_anonymous true

listener 1883 0.0.0.0

listener 8883 0.0.0.0
cafile $WORK/ca.crt
certfile $WORK/server.crt
keyfile $WORK/server.key
EOF
  sudo systemctl stop mosquitto 2>/dev/null
  sudo pkill mosquitto 2>/dev/null
  sleep 1
  mosquitto -c "$WORK/mosq_both.conf" -d
  sleep 1
  (ss -ltn 2>/dev/null || netstat -ltn 2>/dev/null) | grep -E "1883|8883" || echo "CANH BAO: broker chua nghe 1883/8883, chay: mosquitto -c $WORK/mosq_both.conf -v"
}

# --- 3. byte MQTT khong TLS ---------------------------------------------------
cmd_bytes() {
  local ts="${1:-off}"
  need_sudo
  [ "$ts" = "off" ] && set_ts 0 || set_ts 1
  trap 'set_ts 1' EXIT
  for q in 0 1; do
    cap "$PCAP/mqtt_qos${q}_ts${ts}.pcap" 1883 pub_each 1883 "$q"
    echo "=== QoS $q, TCP timestamp $ts  (cot: msgtype frame.len ip.len tcp.hdr_len mqtt.len) ==="
    tshark -r "$PCAP/mqtt_qos${q}_ts${ts}.pcap" -Y "mqtt.msgtype == 3 || mqtt.msgtype == 4" \
      -T fields -e mqtt.msgtype -e frame.len -e ip.len -e tcp.hdr_len -e mqtt.len 2>/dev/null | head -6
  done
  echo "Ky vong (tat timestamp): QoS0 PUBLISH 61 ; QoS1 PUBLISH 63 + PUBACK 44 = 107 (ip.len)."
}

# --- 4. chi phi TLS -----------------------------------------------------------
cmd_tls_bytes() {
  need_sudo
  set_ts 0
  trap 'set_ts 1' EXIT
  cap "$PCAP/mqtt_plain_l.pcap" 1883 pub_stream 1883
  cap "$PCAP/mqtt_tls_l.pcap"   8883 pub_stream 8883 tls
  echo "=== khong TLS: so goi, ip.len (goi mang du lieu) ==="
  tshark -r "$PCAP/mqtt_plain_l.pcap" -Y "tcp.dstport==1883 && tcp.len>0" -T fields -e ip.len 2>/dev/null | sort -n | uniq -c
  echo "=== co TLS: so goi, ip.len ==="
  tshark -r "$PCAP/mqtt_tls_l.pcap"   -Y "tcp.dstport==8883 && tcp.len>0" -T fields -e ip.len 2>/dev/null | sort -n | uniq -c
  echo "=== phien ban TLS (0x0304 = TLS 1.3) va cipher (0x1302 = AES-256-GCM) ==="
  tshark -r "$PCAP/mqtt_tls_l.pcap" -Y "tls.handshake.type==2" \
    -T fields -e tls.handshake.extensions.supported_version -e tls.handshake.ciphersuite 2>/dev/null
  echo "=== goi bat tay: so khung, ip.len, loai (1 = ClientHello, 2 = ServerHello) ==="
  tshark -r "$PCAP/mqtt_tls_l.pcap" -Y "tls.handshake" -T fields -e frame.number -e ip.len -e tls.handshake.type 2>/dev/null
  echo "=== tong ip.len ca phien: khong TLS / co TLS ==="
  tshark -r "$PCAP/mqtt_plain_l.pcap" -T fields -e ip.len 2>/dev/null | awk '{s+=$1} END{print s}'
  tshark -r "$PCAP/mqtt_tls_l.pcap"   -T fields -e ip.len 2>/dev/null | awk '{s+=$1} END{print s}'
  echo "Ky vong: 20 goi 61 (khong TLS) va 20 goi 83 (co TLS) => +22 byte moi tin."
}

# --- 5. paho + script do thoi gian --------------------------------------------
cmd_venv() {
  need_sudo
  sudo apt install -y python3-venv >/dev/null
  python3 -m venv --system-site-packages "$HOME/iot"
  "$HOME/iot/bin/python" -m pip install 'paho-mqtt>=2,<3'
}

write_handshake() { cat > "$WORK/handshake.py" << 'PYEOF'
#!/usr/bin/env python3
"""Do thoi gian ket noi MQTT (TCP + [TLS] + CONNECT/CONNACK), co va khong TLS.

Chay tren loopback: RTT ~ 0 nen so do chu yeu la chi phi tinh toan cua TLS,
KHONG phai chi phi do tre mang. Muon thay anh huong RTT, chay lai trong Mininet
voi netem (kich ban K6).
"""
import csv, os, statistics, sys, threading, time
import paho.mqtt.client as mqtt

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
N = int(sys.argv[2]) if len(sys.argv) > 2 else 20
CA = os.path.expanduser("~/mqtt_tls/ca.crt")
OUT = os.path.expanduser("~/mqtt_tls/handshake_times.csv")


def once(port, tls):
    done = threading.Event()
    c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="hs-%d" % time.time_ns())

    def on_connect(client, userdata, flags, reason_code, properties):
        done.set()

    c.on_connect = on_connect
    if tls:
        c.tls_set(ca_certs=CA)
    t0 = time.perf_counter()
    c.connect(HOST, port, keepalive=60)
    c.loop_start()
    ok = done.wait(5)
    ms = (time.perf_counter() - t0) * 1000
    c.disconnect()
    c.loop_stop()
    return ms if ok else None


rows = []
for label, port, tls in (("khong_TLS", 1883, False), ("co_TLS", 8883, True)):
    once(port, tls)  # chay khoi dong, khong tinh
    vals = []
    for i in range(N):
        ms = once(port, tls)
        if ms is None:
            print("Lan %d (%s): khong nhan duoc CONNACK" % (i + 1, label))
            continue
        vals.append(ms)
        rows.append([label, i + 1, round(ms, 3)])
        time.sleep(0.2)
    if vals:
        print("%-10s n=%d  trung binh=%.2f ms  do lech chuan=%.2f  min=%.2f  max=%.2f" % (
            label, len(vals), statistics.mean(vals),
            statistics.stdev(vals) if len(vals) > 1 else 0.0, min(vals), max(vals)))

with open(OUT, "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["mode", "run", "ms"])
    w.writerows(rows)
print("Da ghi", OUT)
PYEOF
}

cmd_handshake() {
  [ -x "$HOME/iot/bin/python" ] || cmd_venv
  write_handshake
  "$HOME/iot/bin/python" "$WORK/handshake.py" 127.0.0.1 20
}

# --- 6. demo K9a --------------------------------------------------------------
cmd_k9_view() {
  need_sudo
  local msg="NHIET_DO_25.5_NHOM11"
  oneshot() { mosquitto_pub -h 127.0.0.1 -p "$1" "${@:3}" -t sensor1 -m "$msg" -q 0; }
  cap "$PCAP/k9_plain.pcap" 1883 oneshot 1883 x
  cap "$PCAP/k9_tls.pcap"   8883 oneshot 8883 x --cafile "$WORK/ca.crt"
  echo "=== KHONG TLS: noi dung ban tin doc duoc trong goi ==="
  sudo tcpdump -r "$PCAP/k9_plain.pcap" -A 2>/dev/null | grep -a "$msg" | head -2
  echo "So dong chua noi dung: $(sudo tcpdump -r "$PCAP/k9_plain.pcap" -A 2>/dev/null | grep -a -c "$msg")"
  echo "=== CO TLS: tim lai noi dung trong goi ==="
  echo "So dong chua noi dung: $(sudo tcpdump -r "$PCAP/k9_tls.pcap" -A 2>/dev/null | grep -a -c "$msg")   (ky vong 0)"
  echo "Chup man hinh + giu file pcap: $PCAP/k9_plain.pcap, $PCAP/k9_tls.pcap"
}

# --- 7. adapters TLS (dua tren code cua Duy Anh) ------------------------------
cmd_adapters() {
cat > gw_mqtt_tls.py << 'PYEOF'
#!/usr/bin/env python3
"""[TLS-capable copy of Duy Anh's gw_mqtt.py: adds --tls and --ca]
MQTT adapter on Mininet node hg: sensor UDP/5000 -> MQTT broker on server.

Sensor payload: network byte order !HIf = sensor_id:uint16, seq:uint32,
value:float32 (10 bytes). The same bytes are published without alteration.
Requires paho-mqtt >= 2.0.
"""
import argparse
import logging
import os
import signal
import socket
import struct
import threading
import time

import paho.mqtt.client as mqtt

SENSOR_RECORD = struct.Struct('!HIf')


def main():
    parser = argparse.ArgumentParser(description='UDP sensor -> MQTT gateway adapter')
    parser.add_argument('--server', default='10.0.3.2', help='MQTT broker IP on Mininet server')
    parser.add_argument('--port', type=int, default=None, help='default 1883, or 8883 with --tls')
    parser.add_argument('--tls', action='store_true', help='MQTT over TLS')
    parser.add_argument('--ca', default=os.path.expanduser('~/mqtt_tls/ca.crt'), help='CA certificate (with --tls)')
    parser.add_argument('--topic', default='f1/s1/t')
    parser.add_argument('--qos', type=int, choices=(0, 1), default=0)
    parser.add_argument('--udp-port', type=int, default=5000)
    parser.add_argument('--udp-bind', default='0.0.0.0')
    args = parser.parse_args()
    port = args.port or (8883 if args.tls else 1883)

    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    stopped = threading.Event()
    connected = threading.Event()

    def stop(*_):
        stopped.set()

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id='iot-gw-mqtt')

    def on_connect(client, userdata, flags, reason_code, properties):
        if reason_code == 0:
            connected.set()
            logging.info('Connected to broker %s:%d (tls=%s)', args.server, port, args.tls)
        else:
            connected.clear()
            logging.error('MQTT connection rejected: %s', reason_code)

    def on_disconnect(client, userdata, disconnect_flags, reason_code, properties):
        connected.clear()
        if not stopped.is_set():
            logging.warning('MQTT disconnected: %s', reason_code)

    client.on_connect = on_connect
    client.on_disconnect = on_disconnect
    client.reconnect_delay_set(min_delay=1, max_delay=10)
    if args.tls:
        client.tls_set(ca_certs=args.ca)
    # Fail fast if the broker is not reachable at startup.
    client.connect(args.server, port, keepalive=60)
    client.loop_start()

    accepted = 0
    published = 0
    invalid = 0
    publish_errors = 0
    try:
        if not connected.wait(timeout=10):
            raise RuntimeError('MQTT broker did not confirm connection within 10 seconds')
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind((args.udp_bind, args.udp_port))
            sock.settimeout(0.5)
            logging.info('Receiving sensor UDP on %s:%d (MQTT QoS=%d, topic=%s)',
                         args.udp_bind, args.udp_port, args.qos, args.topic)
            while not stopped.is_set():
                try:
                    payload, _source = sock.recvfrom(65535)
                except socket.timeout:
                    continue
                accepted += 1
                if len(payload) != SENSOR_RECORD.size:
                    invalid += 1
                    logging.warning('Drop unexpected sensor payload length: %d bytes', len(payload))
                    continue
                if not connected.is_set():
                    publish_errors += 1
                    logging.warning('Broker offline; dropping sensor message')
                    continue
                info = client.publish(args.topic, payload, qos=args.qos)
                if info.rc != mqtt.MQTT_ERR_SUCCESS:
                    publish_errors += 1
                    logging.warning('MQTT publish queue rejected message (rc=%s)', info.rc)
                else:
                    published += 1
    finally:
        # Allow queued MQTT packets to be transmitted; not a delivery guarantee.
        time.sleep(0.5)
        client.disconnect()
        client.loop_stop()
        logging.info('UDP received=%d MQTT queued=%d invalid=%d publish_errors=%d',
                     accepted, published, invalid, publish_errors)


if __name__ == '__main__':
    main()
PYEOF
cat > srv_mqtt_tls.py << 'PYEOF'
#!/usr/bin/env python3
"""[TLS-capable copy of Duy Anh's srv_mqtt.py: adds --tls and --ca]
MQTT subscriber on Mininet node server. Logs received sensor packets to CSV.

CSV columns: sensor_id,seq,recv_epoch_ns. Match sensor_h<id>.csv on
(sensor_id, seq), using send_epoch_ns from the sensor's own log.
Requires paho-mqtt >= 2.0.
"""
import argparse
import csv
import logging
import os
import signal
import struct
import threading
import time

import paho.mqtt.client as mqtt

SENSOR_RECORD = struct.Struct('!HIf')


def main():
    parser = argparse.ArgumentParser(description='MQTT receiver -> CSV logger')
    parser.add_argument('--broker', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=None, help='default 1883, or 8883 with --tls')
    parser.add_argument('--tls', action='store_true', help='MQTT over TLS')
    parser.add_argument('--ca', default=os.path.expanduser('~/mqtt_tls/ca.crt'), help='CA certificate (with --tls)')
    parser.add_argument('--topic', default='f1/s1/t')
    parser.add_argument('--run-id', default='m01', help='Optional label for console logs only')
    parser.add_argument('--out', default='m01.server.csv')
    args = parser.parse_args()
    port = args.port or (8883 if args.tls else 1883)

    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    out_dir = os.path.dirname(os.path.abspath(args.out))
    os.makedirs(out_dir, exist_ok=True)
    stopping = threading.Event()

    def stop(*_):
        stopping.set()

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    n_received = 0
    n_malformed = 0
    # line buffering ensures that another process can read logs while running.
    with open(args.out, 'w', newline='', buffering=1, encoding='utf-8') as handle:
        writer = csv.writer(handle)
        writer.writerow(['sensor_id', 'seq', 'recv_epoch_ns'])
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id='iot-srv-mqtt')

        def on_connect(client, userdata, flags, reason_code, properties):
            if reason_code == 0:
                result, _mid = client.subscribe(args.topic, qos=1)
                logging.info('Subscribed %s (result=%s, run=%s)', args.topic, result, args.run_id)
            else:
                logging.error('Broker rejected subscriber: %s', reason_code)

        def on_message(client, userdata, message):
            nonlocal n_received, n_malformed
            received_ns = time.time_ns()
            data = message.payload
            if not data or len(data) % SENSOR_RECORD.size:
                n_malformed += 1
                logging.warning('Drop malformed MQTT message (%d bytes)', len(data))
                return
            for index in range(0, len(data), SENSOR_RECORD.size):
                sensor_id, seq, _value = SENSOR_RECORD.unpack_from(data, index)
                writer.writerow([sensor_id, seq, received_ns])
                n_received += 1
            handle.flush()

        client.on_connect = on_connect
        client.on_message = on_message
        client.reconnect_delay_set(min_delay=1, max_delay=10)
        if args.tls:
            client.tls_set(ca_certs=args.ca)
        client.connect(args.broker, port, keepalive=60)
        client.loop_start()
        logging.info('Writing %s', args.out)
        try:
            while not stopping.wait(0.2):
                pass
        finally:
            client.disconnect()
            client.loop_stop()
            logging.info('CSV records=%d malformed messages=%d', n_received, n_malformed)


if __name__ == '__main__':
    main()
PYEOF
  echo "Da ghi gw_mqtt_tls.py va srv_mqtt_tls.py vao $(pwd)"
  echo "Vi du: gw_mqtt_tls.py --server 10.0.3.2 --tls --ca /duong/dan/ca.crt --qos 1"
}

# --- dieu phoi ----------------------------------------------------------------
case "$1" in
  certs) cmd_certs ;;
  broker) cmd_broker ;;
  bytes) cmd_bytes "$2" ;;
  tls-bytes) cmd_tls_bytes ;;
  venv) cmd_venv ;;
  handshake) cmd_handshake ;;
  k9-view) cmd_k9_view ;;
  adapters) cmd_adapters ;;
  all) cmd_certs; cmd_broker; cmd_bytes off; cmd_tls_bytes; cmd_handshake; cmd_k9_view ;;
  *) sed -n '2,32p' "$0" ;;
esac
