#pragma once
#include <ntifs.h>
#include <intrin.h>
#include <ntimage.h>
#include <wdftypes.h>

extern "C" NTSTATUS NTAPI MmCopyVirtualMemory
(
	PEPROCESS SourceProcess,
	PVOID SourceAddress,
	PEPROCESS TargetProcess,
	PVOID TargetAddress,
	SIZE_T BufferSize,
	KPROCESSOR_MODE PreviousMode,
	PSIZE_T ReturnSize
);

extern "C" NTSTATUS NTAPI ObReferenceObjectByName(
	PUNICODE_STRING ObjectPath,
	ULONG Attributes,
	PACCESS_STATE PassedAccessState OPTIONAL,
	ACCESS_MASK DesiredAccess OPTIONAL,
	POBJECT_TYPE ObjectType,
	KPROCESSOR_MODE AccessMode,
	PVOID ParseContext OPTIONAL,
	PVOID * ObjectPtr
);

const ULONG64 ntosPsLoadedModuleListAddressOffset = 0xc00b68;

PLIST_ENTRY PsLoadedModuleList;
extern "C" __declspec(dllimport) POBJECT_TYPE* IoDriverObjectType;