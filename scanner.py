import re
import socket
import time

import dnslib
from scapy.all import sr, Raw, Packet, raw, conf, L3RawSocket
from scapy.layers.dns import DNS
from scapy.layers.inet import IP, UDP, TCP, ICMP

from port_data import PortData, PortStatus, ConnectionType, Protocol
from protocols import UDP_PROTOCOLS, TCP_PROTOCOLS

conf.L3socket = L3RawSocket

UNANSWERED_STATUS = {
    ConnectionType.UDP: PortStatus.OPEN_FILTERED,
    ConnectionType.TCP: PortStatus.FILTERED
}

PROTOCOLS = {
    ConnectionType.UDP: UDP_PROTOCOLS,
    ConnectionType.TCP: TCP_PROTOCOLS
}

SOURCE_PORT = 8888


def scan_ports(connection: ConnectionType,
               address: str, ports: list[int],
               max_opened_sockets: int = 256,
               timeout: int = 2,
               is_define_protocol: bool = False) -> list[PortData]:
    answer = []
    for i in range(0, len(ports), max_opened_sockets):
        chunk = ports[i:i + max_opened_sockets]
        results, unanswered = send_request(
            connection, address, chunk, Raw(b'ping'), timeout)
        raw_answer = {port.dport: PortData(port.dport, connection,
                                           UNANSWERED_STATUS[connection])
                      for port in unanswered}
        to_define = set()
        if connection == ConnectionType.UDP:
            to_define = {port.dport for port in unanswered}
        for query, response in results:
            status, port = get_udp_port_status_and_port(response)
            if connection == ConnectionType.TCP:
                status = get_tcp_port_status(response)
            receive_time = response.time - query.sent_time
            raw_answer[port] = PortData(port, connection,
                                        status, receive_time)
            if status == PortStatus.OPEN:
                to_define.add(port)
        if is_define_protocol:
            if connection == ConnectionType.UDP:
                raw_answer |= define_udp_protocols(address, to_define, timeout)
            else:
                raw_answer |= define_tcp_protocols(address, to_define, timeout)
        answer += raw_answer.values()
    return answer


def send_request(connection_type: ConnectionType,
                 address: str, ports: list[int],
                 message: Packet, timeout: int = 2) -> tuple:
    packet = UDP(sport=SOURCE_PORT, dport=ports) / message
    if connection_type == connection_type.TCP:
        packet = TCP(sport=SOURCE_PORT, dport=ports, flags="S")
    results, unanswered = sr(IP(dst=address) / packet,
                             timeout=timeout, verbose=0)
    return results, unanswered


def get_udp_port_status_and_port(response: Packet) -> tuple[PortStatus, int]:
    port = response.sport
    status = PortStatus.FILTERED
    if response.haslayer(UDP):
        status = PortStatus.OPEN
    elif response.haslayer(ICMP):
        port = response.dport
        if response[ICMP].code == 3:
            status = PortStatus.CLOSED
    return status, port


def get_tcp_port_status(response: Packet) -> PortStatus:
    status = PortStatus.FILTERED
    if response.haslayer(TCP):
        if response[TCP].flags == 0x12:
            status = PortStatus.OPEN
        elif response[TCP].flags == 0x14:
            status = PortStatus.CLOSED
    return status


def define_udp_protocols(address: str, ports: set[int],
                         timeout: int = 2) -> dict[int, PortData]:
    answer = {}
    for protocol in UDP_PROTOCOLS.items():
        results, unanswered = send_request(
            ConnectionType.UDP, address, list(ports), protocol[1], timeout)
        for query, response in results:
            port = response.sport
            if response.haslayer(ICMP):
                port = response.dport
            receive_time = response.time - query.sent_time
            raw_response = raw(response)
            if response.haslayer(DNS):
                raw_response = raw(response[DNS])
            proto = define_protocol_by_response(protocol[1], raw_response)
            answer[port] = PortData(port, ConnectionType.UDP,
                                    PortStatus.OPEN, receive_time,
                                    proto)
    return answer


def define_tcp_protocols(address: str, ports: set[int],
                         timeout: int = 2) -> dict[int, PortData]:
    answer = {}
    for port in ports:
        for protocol in TCP_PROTOCOLS.items():
            try:
                connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                connection.connect((address, port))
                connection.settimeout(timeout)
                connection.sendall(protocol[1])
                start = time.time()
                data = connection.recv(4096)
                if protocol[0] == 'dns':
                    data = data[2:]
                proto = define_protocol_by_response(protocol[1], data)
                if proto is None:
                    continue
                receive_time = time.time() - start
                answer[port] = PortData(port, ConnectionType.TCP,
                                        PortStatus.OPEN, receive_time,
                                        proto)
                connection.close()
                break
            except (socket.timeout, ConnectionError, TimeoutError):
                continue
    return answer


def define_protocol_by_response(query: bytes,
                                response: bytes) -> Protocol:
    if query == response:
        return Protocol.ECHO
    if b'HTTP' in response:
        return Protocol.HTTP
    if b'SSH' in response:
        return Protocol.SSH
    if b'FTP' in response:
        return Protocol.FTP
    if b'POP3' in response:
        return Protocol.POP3
    if re.match(b'[0-9]{3}', response[:3]):
        return Protocol.SMTP
    try:
        dnslib.DNSRecord.parse(response)
        return Protocol.DNS
    except dnslib.DNSError:
        pass
