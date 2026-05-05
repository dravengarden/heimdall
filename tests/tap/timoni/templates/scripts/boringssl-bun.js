// BoringSSL static test case for heimdall's TLS-plaintext tap.
//
// Bun (oven/bun) statically links BoringSSL for its TLS stack, so any
// `fetch()` call here exercises the BoringSSL `SSL_write` / `SSL_read`
// path that heimdall's BoringSSL-static scanner attaches uprobes to.
// Successful capture is observable in heimdall's `messages` table and
// in `journalctl -u heimdall | grep tap\\[`.

const URL = "https://httpbin.org/json";
const INTERVAL_MS = 5000;

async function tick() {
  try {
    const res = await fetch(URL);
    const body = await res.text();
    console.log(`[bun] OK ${res.status} bytes=${body.length}`);
  } catch (e) {
    console.log(`[bun] ERR ${e.message}`);
  }
}

console.log(`[bun] starting; URL=${URL} interval=${INTERVAL_MS}ms`);
setInterval(tick, INTERVAL_MS);
tick();
