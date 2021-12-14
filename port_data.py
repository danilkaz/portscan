from dataclasses import dataclass
from enum import Enum


class ConnectionType(Enum):
    TCP = 'tcp'
    UDP = 'udp'


class PortStatus(Enum):
    OPEN = 'open'
    CLOSED = 'closed'
    FILTERED = 'filtered'
    OPEN_FILTERED = 'open|filtered'


class Protocol(Enum):
    HTTP = 'http'
    DNS = 'dns'
    ECHO = 'echo'
    SSH = 'ssh'
    SMTP = 'smtp'
    FTP = 'ftp'
    POP3 = 'pop3'


@dataclass
class PortData:
    port: int
    connection_type: ConnectionType
    status: PortStatus
    response_time: float = None
    protocol: Protocol = None
