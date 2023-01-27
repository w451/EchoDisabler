#pragma once
#include "imports.h"
#include "structs.h"



NTSTATUS CVM(PVOID SourceAddress, PVOID TargetAddress, ULONG64 size) {
	ULONG64 copied = 0;
	NTSTATUS nt = MmCopyVirtualMemory(PsGetCurrentProcess(), SourceAddress, PsGetCurrentProcess(), TargetAddress, size, KernelMode, &copied);
	if (nt != STATUS_SUCCESS) {
		//DbgPrintEx(0, 0, "Fail to copy %llX to %llX ERR: %lX\n", (ULONG64)SourceAddress, (ULONG64)TargetAddress, nt);
	}
	return nt;
}

ULONG64 ScanPattern(ULONG64 base, ULONG64 size, ULONG64 patternLen, char* pattern, char* mask) {

	for (ULONG64 i = 0; i < size - patternLen; i++)
	{
		for (ULONG64 j = 0; j < patternLen; j++)
		{
			if (mask[j] != '?' && *((char*)(base + i + j)) != (char)pattern[j])
				break;

			if (j == patternLen - 1)
				return (ULONG64)(base)+i;
		}
	}

	return 0;
}

#define PAGELK (0x4B4C45474150)
ULONG64 GetKernelBase() {

	auto entry = __readmsr(0xC0000082) & ~0xffff;

	do {

		auto addr = *(USHORT*)entry;

		if (addr == IMAGE_DOS_SIGNATURE) {

			for (auto x = entry; x < entry + 0x400; x += 8) {

				if (*(ULONG64*)x == PAGELK) {
					return (ULONG64)entry;
				}

			}
		}

		entry -= 0x10000;

	} while (TRUE);
}

PKLDR_DATA_TABLE_ENTRY findModule(PKLDR_DATA_TABLE_ENTRY entry, int nbytes, WCHAR* name) {
	PKLDR_DATA_TABLE_ENTRY current = entry->NextModule;
	while (current != entry) {
		if (current->BaseDllName.Length == nbytes) {
			int found = 1;
			for (int x = 0; x < nbytes / 2; x++) {
				if (name[x] != current->BaseDllName.Buffer[x]) {
					found = 0;
					break;
				}
			}
			if (found) {
				return current;
			}
		}

		current = current->NextModule;
	}
	return 0;
}

int cmpWstr(wchar_t* a, wchar_t* b, ULONG64 l) {
	for (ULONG64 x = 0; x < l; x++) {
		if (a[x]!=b[x]) {
			return 0;
		}
	}
	return 1;
}

int wstrContains(wchar_t* big, ULONG64 bl, wchar_t* inside, ULONG64 il) {
	if (bl < il) {
		return -1;
	}
	for (int x = 0; x < bl-il+1; x++) {
		int suc = 1;
		for (int y = 0; y < il; y++) {
			if (big[x+y] != inside[y]) {
				suc = 0;
				break;
			}
		}
		if (suc) {
			return x;
		}
	}
	return -1;
}

bool writeReadonly(void* address, void* buffer, ULONG size)
{
	PMDL mdl = IoAllocateMdl(address, size, FALSE, FALSE, NULL);
	if (!mdl) { return false; }

	MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
	void* map = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
	MmProtectMdlSystemAddress(mdl, PAGE_EXECUTE_READWRITE);

	memcpy(map, buffer, size);

	MmUnmapLockedPages(map, mdl);
	MmUnlockPages(mdl);
	IoFreeMdl(mdl);

	return true;
}

CHEBPROCESS* getNext(CHEBPROCESS* now) {
	return (CHEBPROCESS*)((ULONG64)now->ActiveProcessLinks.Flink - 0x448);
}

CHEBPROCESS* getEProcByName(CHEBPROCESS* sysProc, char* name, int len) {
	if (len > 15) {
		return 0;
	}
	CHEBPROCESS* current = getNext(sysProc);
	while (current != sysProc) {
		int found = 1;
		for (int x = 0; x < len; x++) {
			if (current->ImageFileName[x] != name[x]) {
				found = 0;
				break;
			}
		}
		if (found) {
			return current;
		}
		current = getNext(current);
	}
	return 0;
}

CHEBPROCESS* getEProcByPid(CHEBPROCESS* sysProc, ULONG64 pid) {
	CHEBPROCESS* current = getNext(sysProc);
	while (current != sysProc) {
		if (current->UniqueProcessID == pid) {
			return sysProc;
		}
		current = getNext(current);
	}
	return 0;
}