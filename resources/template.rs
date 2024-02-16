use windows::Win32::Foundation::HMODULE;
    
{}

#[no_mangle]
#[allow(non_snake_case, unused_variables)]
extern "system" fn DllMain(h_module: HMODULE, call_reason: u32, _: *mut ()) -> bool {
    if call_reason == 1 {
    }

    true
}