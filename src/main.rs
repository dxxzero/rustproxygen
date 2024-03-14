use std::env;
use std::fs;
use std::fs::File;
use std::io::Write;

pub mod pe_parser;


fn main() {
    let args: Vec<String> = env::args().collect();
    let file_path = &args[1];
    println!("Proxying {}", file_path);

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

    let content_export_asm = fs::read_to_string(".\\export.rs")
    .expect("Could not find exports template file");

    let export_asm = content_export_asm.replace("{}", function_exports.as_str());

    let contents = fs::read_to_string(".\\template.rs")
        .expect("Could not find main template file");
    
    let mut file = File::create(".\\proxy.rs").expect("Could not create proxy.rs file");
    file.write_all(contents.replace("{}", export_asm.as_str()).as_bytes()).expect("Could not write to proxy.rs file");

    println!("Wrote proxy dll template to .\\proxy.rs");

}

