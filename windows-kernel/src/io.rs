/*MIT License

Copyright (c) 2021 S.J.R. van Schaik

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
use core::result;

use windows_kernel_sys::base::ANSI_STRING;
use windows_kernel_sys::ntoskrnl::{DbgPrint, PsGetCurrentThread, PsGetThreadId};

use crate::Error;

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => ($crate::io::_print(format_args!($($arg)*)));
}

#[macro_export]
macro_rules! println {
    () => ($crate::print!("\n"));
    ($($arg:tt)*) => ($crate::print!("{}\n", format_args!($($arg)*)));
}

#[doc(hidden)]
pub fn _print(args: core::fmt::Arguments) {
    // Format the string using the `alloc::format!` as this is guaranteed to return a `String`
    // instead of a `Result` that we would have to `unwrap`. This ensures that this code stays
    // panic-free.
    let s = alloc::format!("{}", args);

    let object = unsafe { PsGetCurrentThread() };
    let handle = unsafe { PsGetThreadId(object) };
    let id = handle as usize;
    let s = alloc::format!("[{id}]{}", s);

    // Print the string. We must make sure to not pass this user-supplied string as the format
    // string, as `DbgPrint` may then format any format specifiers it contains. This could
    // potentially be an attack vector.
    let s = ANSI_STRING {
        Length: s.len() as u16,
        MaximumLength: s.len() as u16,
        Buffer: s.as_ptr() as _,
    };

    unsafe { DbgPrint("%Z\0".as_ptr() as _, &s) };
}

pub type Result<T> = result::Result<T, Error>;

pub const DEFAULT_BUF_SIZE: usize = if cfg!(target_os = "espidf") {
    512
} else {
    8 * 1024
};
