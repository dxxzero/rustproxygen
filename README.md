# RustProxyGen
This project creates a (forwarder) proxy dll rust template.

# Build 
```
cargo build --release
```

# Usage
```
Usage: rustproxygen.exe [OPTIONS] --dll <DLL>

Options:
  -d, --dll <Dll Path>
  -s, --shellcode <Shellcode Path>
  -o, --output <Output Directory>
  -r, --resources <Resources Directory>
  -e, --encryption <AES>
  -h, --help                     Print help
  -V, --version                  Print version
```


# Example
```
rustproxygen.exe -o C:\temp\output -s C:\temp\shellcode.bin -d C:\temp\test.dll -r C:\temp\resources -e AES
	Proxying "C:\\temp\\test.dll"
	Embedding shellcode "C:\\temp\\shellcode.bin"
	Parsed an x64 PE file
	Found 2 exported functions
	Using AES encryption
	Wrote shellcode to "C:\\temp\\output\\shellcode.rs"
	Wrote proxy dll template to "C:\\temp\\output\\proxy.rs"
```
