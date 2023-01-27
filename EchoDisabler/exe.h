#pragma once
#include "imports.h"
#include "structs.h"
#include "util.h"


typedef struct _LLWSTRING {
	_LLWSTRING* next;
	UNICODE_STRING str;
} LLWSTRING, * PLLWSTRING;

PLLWSTRING strListHead = (PLLWSTRING)0;

typedef struct _LLPID {
	_LLPID* next;
	ULONG64 pid;
} LLPID, * PLLPID;

PLLPID pidListHead = (PLLPID)0;


int addToFilterList(wchar_t* data, ULONG64 len) {

	PLLWSTRING entry = (PLLWSTRING)ExAllocatePool(NonPagedPool, sizeof(LLWSTRING));

	if (entry == 0) {
		DbgPrintEx(0, 0, "Failed to alloc LLWSTRING");
		return 0;
	}
	RtlSecureZeroMemory(entry, sizeof(LLWSTRING)); //This is necessary otherwise for some reason next will be -1 and cause bsod haha

	entry->str.Buffer = data;
	entry->str.Length = (USHORT)len;
	entry->str.MaximumLength = (USHORT)len;
	if (strListHead == 0) {
		strListHead = entry;
	}
	else {
		PLLWSTRING current = strListHead;
		while (current->next != 0) {
			current = current->next;
		}
		current->next = entry;
	}
	return 1;
}

int removeFromFilterList(wchar_t* data, ULONG64 len) {
	PLLWSTRING previous = 0;
	PLLWSTRING current = strListHead;
	while (current != 0) {
		if (current->str.Length == len && cmpWstr(current->str.Buffer, data, len / 2)) {
			if (previous == 0) {
				strListHead = current->next;
			}
			else {
				previous->next = current->next;
			}
			//Since we are unlinking current we might as well also free its memory
			ExFreePool(current->str.Buffer);
			ExFreePool(current);
			return 1;
		}
		previous = current;
		current = current->next;
	}
	return 0;
}

void dbgFilterList() {
	PLLWSTRING current = strListHead;
	ULONG64 x = 0;
	while (current != 0) {
		x++;
		DbgPrintEx(0, 0, "%wZ %hu\n", &current->str, current->str.Length);
		current = current->next;
	}
	DbgPrintEx(0, 0, "%llX entries in the list\n", x);
}

int recordIsFiltered(PUSN_RECORD rec) {
	PLLWSTRING current = strListHead;
	while (current != 0) {
		if (rec->MajorVersion == 2) {
			if (wstrContains(rec->FileName, rec->FileNameLength / 2, current->str.Buffer, current->str.Length / 2) != -1) {
				return 1;
			}
		}
		else if (rec->MajorVersion == 3) {
			PUSN_RECORD_V3 realStruc = (PUSN_RECORD_V3)rec;
			if (wstrContains(realStruc->FileName, realStruc->FileNameLength / 2, current->str.Buffer, current->str.Length / 2) != -1) {
				return 1;
			}
		}
		else {
			return 0;
		}
		current = current->next;
	}
	return 0;
}

ULONG64 sanitizeBuffer(PVOID buffer, ULONG64 len) {
	PUSN_RECORD UsnRecord = (PUSN_RECORD)(((PUCHAR)buffer) + sizeof(USN));

	PVOID modified = ExAllocatePool(NonPagedPool, len);
	if (modified == 0) {
		return len;
	}

	memcpy(modified, buffer, sizeof(USN));

	ULONG64 dwRetBytes = len - sizeof(USN);
	ULONG64 counter = sizeof(USN);
	while (dwRetBytes > 0) {
		if (!recordIsFiltered(UsnRecord)) {
			memcpy((void*)((ULONG64)modified + counter), UsnRecord, UsnRecord->RecordLength);
			counter += UsnRecord->RecordLength;
		}

		dwRetBytes -= UsnRecord->RecordLength;
		UsnRecord = (PUSN_RECORD)(((PCHAR)UsnRecord) + UsnRecord->RecordLength);
	}

	memcpy(buffer, modified, len);
	ExFreePool(modified);

	return counter;
}

void removeStrFromProc(CHEBPROCESS* proc, char* str, ULONG64 bytes) {

	bytes; str;

	MEMORY_BASIC_INFORMATION mbi = { 0 };
	KAPC_STATE kap;

	ULONG_PTR ulBase = (ULONG_PTR)0;
	NTSTATUS status = STATUS_SUCCESS;
	ULONG64 ulRet = 0;

	KeStackAttachProcess((PEPROCESS)proc, &kap);

	do
	{
		status = ZwQueryVirtualMemory(NtCurrentProcess(), (PVOID)ulBase, MemoryBasicInformation, &mbi, sizeof(MEMORY_BASIC_INFORMATION), &ulRet);
		
		if (NT_SUCCESS(status))
		{
			if (mbi.State == MEM_COMMIT) {
				char* buffer = (char*)ExAllocatePool(NonPagedPool, mbi.RegionSize);

				if (buffer != 0) {
					SIZE_T t = 0;
					MM_COPY_ADDRESS cheb;
					cheb.VirtualAddress = (PVOID)ulBase;
					NTSTATUS nt = MmCopyMemory(buffer, cheb, mbi.RegionSize, MM_COPY_MEMORY_VIRTUAL, &t);

					if (NT_SUCCESS(nt) || buffer[0] != 0) {
						int copyBack = 0;

						for (ULONG64 a = 0; a < mbi.RegionSize - bytes; a++) {
							int suc = 1;
							for (int x = 0; x < bytes; x++) {
								if (buffer[a + x] != str[x]) {
									suc = 0;
									break;
								}
							}
							if (suc) {
								DbgPrintEx(0, 0, "Nulled address: %llX in %llu", (ulBase + a), proc->UniqueProcessID);
								memset(buffer + a, 0, bytes);
								copyBack = 1;
							}
						}

						if (copyBack) {
							CVM(buffer, (PVOID)ulBase, mbi.RegionSize);
						}
					}

					ExFreePool(buffer);
				}
				else {
					DbgPrintEx(0, 0, "Failed to get pool!\n");
				}


			}

			ulBase += mbi.RegionSize;
		}
		else
		{
			ulBase += PAGE_SIZE;
		}

	} while (ulBase < 0x7fffffffffff);
	KeUnstackDetachProcess(&kap);
}

int removeStringCsrss(wchar_t* str, ULONG64 bytes) {
	str;
	bytes;
	CHEBPROCESS* csrssFirst = getEProcByName((CHEBPROCESS*)PsInitialSystemProcess, "csrss.exe", 9);
	CHEBPROCESS* csrssCurrent = csrssFirst;

	do {
		DbgPrintEx(0, 0, "Found csrss id: %llu", csrssCurrent->UniqueProcessID);
		removeStrFromProc(csrssCurrent, (char*)str, bytes);
		csrssCurrent = getEProcByName(csrssCurrent, "csrss.exe", 9);
	} while (csrssCurrent != csrssFirst);
	return 1;
}

int addToProtectedProcesses(ULONG64 pid) {
	PLLPID entry = (PLLPID)ExAllocatePool(NonPagedPool, sizeof(LLPID));
	RtlSecureZeroMemory(entry, sizeof(PLLPID));
	if (entry == 0) {
		DbgPrintEx(0, 0, "Failed to alloc LLPID");
		return 0;
	}

	entry->pid = pid;

	if (pidListHead == 0) {
		pidListHead = entry;
	} else {
		PLLPID current = pidListHead;
		while (current->next != 0) {
			current = current->next;
		}
		current->next = entry;
	}
	
	return 1;
}

int removeFromProtectedProcesses(ULONG64 pid) {
	PLLPID previous = 0;
	PLLPID current = pidListHead;
	while (current != 0) {
		if (current->pid == pid) {
			if (previous == 0) {
				pidListHead = current->next;
			}
			else {
				previous->next = current->next;
			}
			ExFreePool(current);
			return 1;
		}
		previous = current;
		current = current->next;
	}
	return 0;
}

int isProcProtected(CHEBPROCESS* proc) {
	PLLPID current = pidListHead;
	while (current != 0) { 
		if (proc->UniqueProcessID == current->pid) {
			return 1;
		}
		current = current->next;
	}
	return 0;
}