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

#include "ntdef.h"
#include "ntstatus.h"

typedef ULONG_PTR _EX_PUSH_LOCK;
typedef ULONG_PTR EX_PUSH_LOCK;
typedef ULONG_PTR *PEX_PUSH_LOCK;

typedef union _KGDTENTRY64
{
	struct
	{
		unsigned short LimitLow;
		unsigned short BaseLow;
		union
		{
			struct
			{
				unsigned char BaseMiddle;
				unsigned char Flags1;
				unsigned char Flags2;
				unsigned char BaseHigh;
			} Bytes;
			struct
			{
				unsigned long BaseMiddle : 8;
				unsigned long Type : 5;
				unsigned long Dpl : 2;
				unsigned long Present : 1;
				unsigned long LimitHigh : 4;
				unsigned long System : 1;
				unsigned long LongMode : 1;
				unsigned long DefaultBig : 1;
				unsigned long Granularity : 1;
				unsigned long BaseHigh : 8;
			} Bits;
		};
		unsigned long BaseUpper;
		unsigned long MustBeZero;
	};
	unsigned __int64 Alignment;
} KGDTENTRY64, *PKGDTENTRY64;

typedef union _KIDTENTRY64
{
	struct
	{
		unsigned short OffsetLow;
		unsigned short Selector;
		unsigned short IstIndex : 3;
		unsigned short Reserved0 : 5;
		unsigned short Type : 5;
		unsigned short Dpl : 2;
		unsigned short Present : 1;
		unsigned short OffsetMiddle;
		unsigned long OffsetHigh;
		unsigned long Reserved1;
	};
	unsigned __int64 Alignment;
} KIDTENTRY64, *PKIDTENTRY64;

#include "Ntifs.h"
#include "Ntddk.h"