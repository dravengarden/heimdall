/// Diagnostic tool: reads COOKIE_MAP and PORT_MAP from the running heimdall instance.
/// This works because aya pins maps in /sys/fs/bpf when using pinned maps.
/// Since we don't pin, this won't work directly. Instead, use bpftool.
fn main() {
    println!("Use: bpftool map dump name PORT_MAP");
    println!("     bpftool map dump name COOKIE_MAP");
}
