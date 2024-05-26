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

pub use cty::*;

include!(concat!(env!("OUT_DIR"), "/base.rs"));

pub const STATUS_SUCCESS: NTSTATUS = 0x00000000;
pub const STATUS_GUARD_PAGE_VIOLATION: NTSTATUS = 0x80000001 as u32 as i32;
pub const STATUS_DATATYPE_MISALIGNMENT: NTSTATUS = 0x80000002 as u32 as i32;
pub const STATUS_BREAKPOINT: NTSTATUS = 0x80000003 as u32 as i32;
pub const STATUS_SINGLE_STEP: NTSTATUS = 0x80000004 as u32 as i32;
pub const STATUS_UNWIND_CONSOLIDATE: NTSTATUS = 0x80000029 as u32 as i32;
pub const STATUS_UNSUCCESSFUL: NTSTATUS = 0xC0000001 as u32 as i32;
pub const STATUS_NOT_IMPLEMENTED: NTSTATUS = 0xC0000002 as u32 as i32;
pub const STATUS_ACCESS_VIOLATION: NTSTATUS = 0xC0000005 as u32 as i32;
pub const STATUS_IN_PAGE_ERROR: NTSTATUS = 0xC0000006 as u32 as i32;
pub const STATUS_INVALID_HANDLE: NTSTATUS = 0xC0000008 as u32 as i32;
pub const STATUS_INVALID_PARAMETER: NTSTATUS = 0xC000000D as u32 as i32;
pub const STATUS_END_OF_FILE: NTSTATUS = 0xC0000011 as u32 as i32;
pub const STATUS_NO_MEMORY: NTSTATUS = 0xC0000017 as u32 as i32;
pub const STATUS_ILLEGAL_INSTRUCTION: NTSTATUS = 0xC000001D as u32 as i32;
pub const STATUS_NONCONTINUABLE_EXCEPTION: NTSTATUS = 0xC0000025 as u32 as i32;
pub const STATUS_INVALID_DISPOSITION: NTSTATUS = 0xC0000026 as u32 as i32;
pub const STATUS_ARRAY_BOUNDS_EXCEEDED: NTSTATUS = 0xC000008C as u32 as i32;
pub const STATUS_FLOAT_DENORMAL_OPERAND: NTSTATUS = 0xC000008D as u32 as i32;
pub const STATUS_FLOAT_DIVIDE_BY_ZERO: NTSTATUS = 0xC000008E as u32 as i32;
pub const STATUS_FLOAT_INEXACT_RESULT: NTSTATUS = 0xC000008F as u32 as i32;
pub const STATUS_FLOAT_INVALID_OPERATION: NTSTATUS = 0xC0000090 as u32 as i32;
pub const STATUS_FLOAT_OVERFLOW: NTSTATUS = 0xC0000091 as u32 as i32;
pub const STATUS_FLOAT_STACK_CHECK: NTSTATUS = 0xC0000092 as u32 as i32;
pub const STATUS_FLOAT_UNDERFLOW: NTSTATUS = 0xC0000093 as u32 as i32;
pub const STATUS_INTEGER_DIVIDE_BY_ZERO: NTSTATUS = 0xC0000094 as u32 as i32;
pub const STATUS_INTEGER_OVERFLOW: NTSTATUS = 0xC0000095 as u32 as i32;
pub const STATUS_PRIVILEGED_INSTRUCTION: NTSTATUS = 0xC0000096 as u32 as i32;
pub const STATUS_INSUFFICIENT_RESOURCES: NTSTATUS = 0xC000009A as u32 as i32;
pub const STATUS_INVALID_USER_BUFFER: NTSTATUS = 0xC00000E8 as u32 as i32;
pub const STATUS_STACK_OVERFLOW: NTSTATUS = 0xC00000FD as u32 as i32;
