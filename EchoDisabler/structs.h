#pragma once
#include "imports.h"
typedef UINT16 WORD;
typedef ULONG32 DWORD;

typedef struct _KLDR_DATA_TABLE_ENTRY {
	_KLDR_DATA_TABLE_ENTRY* NextModule;
	char zzz[0x28];
	ULONG64 DllBase;
	ULONG64 EntryPoint;
	ULONG64 SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
} KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;

typedef struct _CHEBPROCESS {
    BYTE zzzzzzz[0x440];
    ULONG64 UniqueProcessID;
    LIST_ENTRY ActiveProcessLinks;
    BYTE zzzzzzz2[0x150];
    char ImageFileName[15];
} CHEBPROCESS;