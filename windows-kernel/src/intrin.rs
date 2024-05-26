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
use windows_kernel_sys::intrin::{read_msr_safe, write_msr_safe};

use crate::error::{Error, IntoResult};

/// Attempts to read the given model-specific register. Accessing an invalid model-specific
/// register would normally result in a CPU exception. This function uses Structured Exception
/// Handling (SEH) to safely catch CPU exceptions and to turn them into an [`Error`]. This prevents
/// a hang.
pub fn read_msr(register: u32) -> Result<u64, Error> {
    let mut value = 0;

    unsafe { read_msr_safe(register, &mut value) }.into_result()?;

    Ok(value)
}

/// Attempts to write the given value to the given model-specific register. Accessing an invalid
/// model-specific register would normally result in a CPU exception. This function uses Structured
/// Handling (SEH) to safely catch CPU exceptions and to turn them into an [`Error`]. This prevents
/// a hang.
pub fn write_msr(register: u32, value: u64) -> Result<(), Error> {
    unsafe { write_msr_safe(register, value) }.into_result()?;

    Ok(())
}
