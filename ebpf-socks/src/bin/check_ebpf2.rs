#[repr(C, align(8))]
struct AlignedBytes<const N: usize>([u8; N]);

static EBPF_OBJ: AlignedBytes<{ include_bytes!(
    "../../../ebpf-socks-ebpf/target/bpfel-unknown-none/release/ebpf-socks-ebpf"
).len() }> = AlignedBytes(*include_bytes!(
    "../../../ebpf-socks-ebpf/target/bpfel-unknown-none/release/ebpf-socks-ebpf"
));

fn main() {
    let bytes: &[u8] = &EBPF_OBJ.0;
    println!("Embedded size: {} bytes", bytes.len());
    match aya::Ebpf::load(bytes) {
        Ok(bpf) => {
            println!("Load OK! Programs:");
            for (name, prog) in bpf.programs() {
                println!("  {name}: {:?}", prog.prog_type());
            }
        }
        Err(e) => {
            eprintln!("Load error: {e:#?}");
        }
    }
}
