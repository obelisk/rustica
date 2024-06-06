use std::ffi::{c_char, CString};

/// Free a string allocated by Rust
#[no_mangle]
pub unsafe extern "C" fn ffi_free_rust_string(string_ptr: *mut c_char) {
    drop(CString::from_raw(string_ptr));
}
