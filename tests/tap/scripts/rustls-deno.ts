// rustls test case for heimdall's TLS-plaintext tap.
//
// Deno (denoland/deno) uses the Rust `rustls` crate for its TLS stack
// (via the `deno_tls` runtime crate). Any `fetch()` call here exercises
// the rustls `<...PlaintextSink>::write` / `<Reader>::read` symbols
// that heimdall's rustls scanner attaches uprobes to. Successful
// capture is observable in heimdall's `messages` table and in
// `journalctl -u heimdall | grep tap\\[`.

const URL = "https://httpbin.org/json";
const INTERVAL_MS = 5000;

async function tick(): Promise<void> {
  try {
    const res = await fetch(URL);
    const body = await res.text();
    console.log(`[deno] OK ${res.status} bytes=${body.length}`);
  } catch (e) {
    console.log(`[deno] ERR ${(e as Error).message}`);
  }
}

console.log(`[deno] starting; URL=${URL} interval=${INTERVAL_MS}ms`);
setInterval(tick, INTERVAL_MS);
tick();
