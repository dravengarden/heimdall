#!/usr/bin/env node
const dgram = require("node:dgram");
const net = require("node:net");

const mode = process.argv[2];

function tcp() {
  return new Promise((resolve, reject) => {
    let response = "";
    const socket = net.createConnection({ host: "fixture.test", port: 18080 });
    socket.setTimeout(5000, () => socket.destroy(new Error("TCP timeout")));
    socket.on("connect", () =>
      socket.write("GET / HTTP/1.0\r\nHost: fixture.test\r\n\r\n"),
    );
    socket.on("data", (data) => (response += data));
    socket.on("end", () => {
      if (!response.endsWith("fixture-v4")) {
        reject(new Error(`unexpected TCP response: ${response}`));
      } else {
        resolve();
      }
    });
    socket.on("error", reject);
  });
}

function udp() {
  return new Promise((resolve, reject) => {
    const ipv6 = mode === "udp6";
    if (!ipv6 && mode !== "udp4") throw new Error(`unknown mode: ${mode}`);
    const host = ipv6 ? "::1" : "127.0.0.1";
    const port = ipv6 ? 18083 : 18082;
    const expected = Buffer.from(`${ipv6 ? "udp-v6" : "udp-v4"}:runtime-node`);
    const socket = dgram.createSocket(ipv6 ? "udp6" : "udp4");
    const timeout = setTimeout(() => {
      socket.close();
      reject(new Error("UDP timeout"));
    }, 5000);
    socket.on("error", reject);
    socket.on("message", (message, peer) => {
      clearTimeout(timeout);
      socket.close();
      if (!message.equals(expected) || peer.address !== host || peer.port !== port) {
        reject(new Error(`unexpected UDP response: ${message} from ${peer.address}:${peer.port}`));
      } else {
        resolve();
      }
    });
    socket.connect(port, host, () => socket.send("runtime-node"));
  });
}

(async () => {
  if (mode === "tcp") await tcp();
  else await udp();
  console.log(`nodejs-${mode}-ok`);
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
