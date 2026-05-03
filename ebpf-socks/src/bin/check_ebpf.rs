fn main() {
    let data = std::fs::read("/home/draven/land/ebpf-socks/ebpf-socks-ebpf/target/bpfel-unknown-none/release/ebpf-socks-ebpf").expect("read ebpf file");
    println!("File size: {} bytes", data.len());
    match aya::Ebpf::load(&data) {
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
