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
use widestring::U16CString;

use windows_kernel_sys::ntoskrnl::{IoCreateSymbolicLink, IoDeleteSymbolicLink};

use crate::error::{Error, IntoResult};
use crate::string::create_unicode_string;

pub struct SymbolicLink {
    name: U16CString,
}

impl SymbolicLink {
    pub fn new(name: &str, target: &str) -> Result<Self, Error> {
        // Convert the name to UTF-16 and then create a UNICODE_STRING.
        let name = U16CString::from_str(name).unwrap();
        let mut name_ptr = create_unicode_string(name.as_slice());

        // Convert the target to UTF-16 and then create a UNICODE_STRING.
        let target = U16CString::from_str(target).unwrap();
        let mut target_ptr = create_unicode_string(target.as_slice());

        unsafe { IoCreateSymbolicLink(&mut name_ptr, &mut target_ptr) }.into_result()?;

        Ok(Self { name })
    }
}

impl Drop for SymbolicLink {
    fn drop(&mut self) {
        let mut name_ptr = create_unicode_string(self.name.as_slice());

        unsafe {
            IoDeleteSymbolicLink(&mut name_ptr);
        }
    }
}
