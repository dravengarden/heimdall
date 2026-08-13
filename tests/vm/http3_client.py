#!/usr/bin/env python3
import asyncio
import ssl
import sys

from aioquic.asyncio import QuicConnectionProtocol, connect
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration


EXPECTED = b"heimdall-http3:" + (b"0123456789abcdef" * 2048)


class Http3Client(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = H3Connection(self._quic)
        self.waiters = {}

    async def get(self, path):
        stream_id = self._quic.get_next_available_stream_id()
        waiter = self._loop.create_future()
        self.waiters[stream_id] = [waiter, bytearray(), None]
        self.http.send_headers(
            stream_id=stream_id,
            headers=[
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", b"fixture.test:18443"),
                (b":path", path.encode()),
            ],
            end_stream=True,
        )
        self.transmit()
        return await asyncio.wait_for(waiter, timeout=5)

    def quic_event_received(self, event):
        for http_event in self.http.handle_event(event):
            state = self.waiters.get(http_event.stream_id)
            if state is None:
                continue
            if isinstance(http_event, HeadersReceived):
                state[2] = dict(http_event.headers).get(b":status")
            elif isinstance(http_event, DataReceived):
                state[1].extend(http_event.data)
            if http_event.stream_ended:
                waiter, body, status = self.waiters.pop(http_event.stream_id)
                waiter.set_result((status, bytes(body)))


async def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    configuration = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
    configuration.verify_mode = ssl.CERT_NONE
    async with connect(
        host,
        18443,
        configuration=configuration,
        create_protocol=Http3Client,
    ) as client:
        for path in ("/first", "/second"):
            status, body = await client.get(path)
            if status != b"200" or body != EXPECTED:
                raise RuntimeError(
                    f"HTTP/3 response mismatch for {path}: {status!r}, {len(body)} bytes"
                )

    print("http3-ok")


asyncio.run(main())
