#!/usr/bin/env python3
import sys
import socket
import struct
import re

TCP_STATES = {
    '01': 'ESTABLISHED',
    '02': 'SYN_SENT',
    '03': 'SYN_RECV',
    '04': 'FIN_WAIT1',
    '05': 'FIN_WAIT2',
    '06': 'TIME_WAIT',
    '07': 'CLOSE',
    '08': 'CLOSE_WAIT',
    '09': 'LAST_ACK',
    '0A': 'LISTEN',
    '0B': 'CLOSING'
}

def hex_to_ip_port(h):
    """
    Da stringa 'IPHEX:PORTHEX' restituisce (ip_string, port_int).
    IPHEX è little-endian, può non essere 8 caratteri → zfill.
    """
    ip_hex, port_hex = h.split(':')
    ip_hex = ip_hex.zfill(8)
    packed = struct.pack('<L', int(ip_hex, 16))
    ip = socket.inet_ntoa(packed)
    port = int(port_hex, 16)
    return ip, port

def parse_records(text):
    """
    Cerca tutte le occorrenze di:
      <indice>: <IPHEX:PORTHEX> <IPHEX:PORTHEX> <ST>
    e le decodifica.
    """
    pattern = re.compile(
        r'(\d+):\s+'
        r'([0-9A-Fa-f]{1,8}:[0-9A-Fa-f]{1,4})\s+'
        r'([0-9A-Fa-f]{1,8}:[0-9A-Fa-f]{1,4})\s+'
        r'([0-9A-Fa-f]{2})'
    )
    entries = []
    for m in pattern.finditer(text):
        idx = int(m.group(1))
        local_raw = m.group(2)
        remote_raw = m.group(3)
        state_raw = m.group(4).upper()
        lip, lport = hex_to_ip_port(local_raw)
        rip, rport = hex_to_ip_port(remote_raw)
        state = TCP_STATES.get(state_raw, state_raw)
        entries.append((idx, f"{lip}:{lport} → {rip}:{rport}  [{state}]"))
    for _, line in sorted(entries, key=lambda x: x[0]):
        print(line)

def main(path):
    try:
        with open(path, 'r') as f:
            text = f.read()
        parse_records(text)
    except FileNotFoundError:
        print(f"File non trovato: {path}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Errore durante il parsing: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f"Uso: {sys.argv[0]} <file_proc_net_tcp>", file=sys.stderr)
        sys.exit(1)
    main(sys.argv[1])
