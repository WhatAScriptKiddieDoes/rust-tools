use std::env;
use std::fs::File;
use std::io::Write;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        println!("Usage: {} payload.bin output.rs", args[0]);
        return;
    }

    let payload_file = &args[1];
    let output_file = &args[2];
    let bytes = std::fs::read(payload_file).unwrap();
    let mut w = File::create(output_file).unwrap();
    write!(&mut w, "const PAYLOAD: [u8; {}] = ", bytes.len()).unwrap();
    write!(&mut w, "{:02?}", bytes).unwrap();
    writeln!(&mut w, ";").unwrap();
    writeln!(&mut w, "pub fn get_payload() -> Vec<u8> {{ return PAYLOAD.to_vec(); }}").unwrap();
}
