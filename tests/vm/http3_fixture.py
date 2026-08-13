#!/usr/bin/env python3
import asyncio
import sys

from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ProtocolNegotiated


BODY = b"heimdall-http3:" + (b"0123456789abcdef" * 2048)


class Http3Protocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = None

    def quic_event_received(self, event):
        if isinstance(event, ProtocolNegotiated):
            self.http = H3Connection(self._quic)
        if self.http is None:
            return
        for http_event in self.http.handle_event(event):
            if isinstance(http_event, HeadersReceived):
                self.http.send_headers(
                    stream_id=http_event.stream_id,
                    headers=[
                        (b":status", b"200"),
                        (b"content-length", str(len(BODY)).encode()),
                    ],
                )
                self.http.send_data(
                    stream_id=http_event.stream_id,
                    data=BODY,
                    end_stream=True,
                )
                self.transmit()


async def main():
    configuration = QuicConfiguration(
        is_client=False,
        alpn_protocols=H3_ALPN,
    )
    configuration.load_cert_chain(sys.argv[1], sys.argv[2])
    await serve(
        "127.0.0.1",
        18443,
        configuration=configuration,
        create_protocol=Http3Protocol,
        retry=True,
    )
    await asyncio.Future()


asyncio.run(main())
