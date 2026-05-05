fn main() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../heimdall-ebpf/target/bpfel-unknown-none/release/heimdall-ebpf",
    );
    let data = std::fs::read(path).expect("read ebpf file");
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
