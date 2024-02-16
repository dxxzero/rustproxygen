# RustProxyGen
This project creates a (forwarder) proxy dll rust template.

# Build 
```
cargo build --target=i686-pc-windows-msvc --release
```

# Usage
```
rustproxygen.exe <Path/To/DllFile>
```
Make sure you have copied the export.rs and template.rs into the same location as the rustproxygen.exe file.

# Example
```
rustproxygen.exe C:\temp\test_dll.dll
    Proxying C:\temp\test_dll.dll
    Parsed an x86 PE file
    Found 3 exported functions
    Wrote proxy dll template to .\proxy.rs
```
