from scapy.layers.dns import DNS

PROTOCOLS = {
    'echo': b'hello'
}

UDP_PROTOCOLS = PROTOCOLS | {
    'dns': DNS(b'\x12\xa3\x01 \x00\x01\x00\x00\x00\x00\x00\x01\x06yandex\x02ru'
               b'\x00\x00\x01\x00\x01\x00\x00)\x10\x00\x00\x00\x00\x00\x00\x0c'
               b'\x00\n\x00\x08\x0b\xa0q\xc3\xc6\xab\x8ei')
}

TCP_PROTOCOLS = PROTOCOLS | {
    'http': b'GET / HTTP/1.1\nHost:yandex.ru\n\n',
    'smtp|ftp|pop3': b'hello',
    'dns': b'\x00\x32\x12\xa3\x01 \x00\x01\x00\x00\x00\x00\x00\x01\x06'
           b'yandex\x02ru\x00\x00\x01\x00\x01\x00\x00)\x10\x00\x00\x00'
           b'\x00\x00\x00\x0c\x00\n\x00\x08\x0b\xa0q\xc3\xc6\xab\x8ei'
}
