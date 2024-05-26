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
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use crate::base::*;

#[link(name = "wrapper_intrin")]
extern "C" {
    pub fn read_cr3() -> u64;
    pub fn write_cr3(value: u64);
    pub fn read_msr(register: u32) -> u64;
    pub fn read_msr_safe(register: u32, value: &mut u64) -> NTSTATUS;
    pub fn write_msr(register: u32, value: u64);
    pub fn write_msr_safe(register: u32, value: u64) -> NTSTATUS;
    pub fn invlpg(value: usize);
    pub fn AddressOfReturnAddress() -> PVOID;
}
