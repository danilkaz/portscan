import argparse
import ipaddress

from port_data import ConnectionType, PortData, PortStatus
from scanner import scan_ports


def get_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser('portscan')
    parser.add_argument('-t',
                        '--timeout',
                        type=int,
                        default=2,
                        metavar='SECONDS',
                        help='Timeout of connection, default = 2s')
    parser.add_argument('-j',
                        '--sockets-count',
                        type=int,
                        default=256,
                        metavar='NUMBER',
                        help='Maximum number of open sockets, default = 256')
    parser.add_argument('-v',
                        '--verbose',
                        action='store_true',
                        help='The output contains the response time')
    parser.add_argument('-g',
                        '--guess',
                        action='store_true',
                        help='The output contains '
                             'the application layer protocol '
                             'that runs on the desired port')
    parser.add_argument('IP_ADDRESS',
                        type=str,
                        default='127.0.0.1',
                        help='Server IP address')
    parser.add_argument('ports',
                        type=str,
                        default='tcp/1-1024',
                        nargs='*',
                        metavar='{tcp|udp} [/[PORT|PORT-PORT], ...]',
                        help='Ports for scanning, '
                             'sample: tcp/80 tcp/12000-12500 '
                             'udp/3000-3100,3200,3300-4000')
    return parser.parse_args()


def check_arguments(args: argparse.Namespace):
    timeout = args.timeout
    sockets_count = args.sockets_count
    ip = args.IP_ADDRESS
    try:
        int(timeout)
    except ValueError:
        print(f'Invalid timeout: {timeout}')
        exit(1)
    try:
        int(sockets_count)
    except ValueError:
        print(f'Invalid sockets count: {sockets_count}')
        exit(2)
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        print(f'Invalid IP address: {ip}')
        exit(3)


def get_tcp_and_udp_ports_from_argument(
        raw_ports: list[str]) -> tuple[list[int], list[int]]:
    tcp_ports = []
    udp_ports = []
    for port_set in raw_ports:
        ports = []
        ports_list = port_set[4:].split(',')
        for item in ports_list:
            if '-' in item:
                left = None
                right = None
                try:
                    left = int(item[:item.index('-')])
                    right = int(item[item.index('-') + 1:])
                except ValueError:
                    print(f'Invalid left or right value: {item}')
                    exit(4)
                if left > right:
                    print(f'Invalid range: {left} > {right}')
                    exit(5)
                ports += [port for port in range(left, right + 1)]
            else:
                ports.append(int(item))
        if 'tcp' in port_set:
            tcp_ports += ports
        elif 'udp' in port_set:
            udp_ports += ports
        else:
            print(f'Invalid connection type: {port_set}')
            exit(6)
    return tcp_ports, udp_ports


def print_answer(answer: list[PortData],
                 verbose: bool = False, guess: bool = False):
    for port_data in answer:
        print(port_data.connection_type.value, port_data.port, end=' ')
        print(port_data.status, end=' ')
        if verbose:
            if port_data.response_time is None:
                print('timeout', end=' ')
            else:
                print(str(int(port_data.response_time * 1000)) + 'ms', end=' ')
        if guess:
            if port_data.protocol is None:
                print('-', end=' ')
            else:
                print(port_data.protocol.value, end=' ')
        print()


def main():
    args = get_arguments()
    check_arguments(args)
    tcp_ports, udp_ports = get_tcp_and_udp_ports_from_argument(args.ports)
    answer = []
    for connection, ports in ((ConnectionType.UDP, udp_ports),
                              (ConnectionType.TCP, tcp_ports)):
        answer += scan_ports(connection,
                             args.IP_ADDRESS,
                             ports,
                             args.sockets_count,
                             args.timeout,
                             args.guess)

    cmp = lambda p: p.connection_type == ConnectionType.UDP or p.port
    print_answer(sorted(filter(lambda x: x.status not in (PortStatus.CLOSED, PortStatus.OPEN_FILTERED), answer), key=cmp),
                 args.verbose, args.guess)


if __name__ == '__main__':
    main()
