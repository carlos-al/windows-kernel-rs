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
#define _AMD64_

#include "wdm.h"
#include "intrin.h"

unsigned __int64 read_cr3(void) {
	return __readcr3();
}

void write_cr3(unsigned __int64 Value) {
	__writecr3(Value);
}

unsigned __int64 read_msr(
	unsigned long Register
) {
	return __readmsr(Register);
}

NTSTATUS read_msr_safe(
	unsigned long Register,
	unsigned __int64 *Value
) {
	if (!Value) {
		return STATUS_INVALID_PARAMETER;
	}

	__try {
		*Value = __readmsr(Register);
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		return GetExceptionCode();
	}

	return STATUS_SUCCESS;
}

void write_msr(
	unsigned long Register,
	unsigned __int64 Value
) {
	__writemsr(Register, Value);
}

NTSTATUS write_msr_safe(
	unsigned long Register,
	unsigned __int64 Value
) {
	__try {
		__writemsr(Register, Value);
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		return GetExceptionCode();
	}

	return STATUS_SUCCESS;
}

void invlpg(
	void *Address
) {
	__invlpg(Address);
}

void*  AddressOfReturnAddress() {
	_AddressOfReturnAddress();
}


    