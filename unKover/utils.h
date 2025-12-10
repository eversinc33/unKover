#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include <ntimage.h>
#include "meta.h"

typedef struct _OBJECT_DIRECTORY_INFORMATION
{
	UNICODE_STRING Name;
	UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, * POBJECT_DIRECTORY_INFORMATION;

EXTERN_C NTSTATUS ZwQueryInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength);
EXTERN_C NTSTATUS ObReferenceObjectByName(PUNICODE_STRING ObjectName, ULONG Attributes, PACCESS_STATE AccessState, ACCESS_MASK DesiredAccess, POBJECT_TYPE ObjectType, KPROCESSOR_MODE AccessMode, PVOID ParseContext, PVOID* Object);
EXTERN_C NTSTATUS ZwQueryDirectoryObject(
	_In_      HANDLE  DirectoryHandle,
	_Out_opt_ PVOID   Buffer,
	_In_      ULONG   Length,
	_In_      BOOLEAN ReturnSingleEntry,
	_In_      BOOLEAN RestartScan,
	_Inout_   PULONG  Context,
	_Out_opt_ PULONG  ReturnLength
);

typedef struct _KLDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	PVOID ExceptionTable;
	UINT32 ExceptionTableSize;
	PVOID GpValue;
	NON_PAGED_DEBUG_INFO* NonPagedDebugInfo;
	PVOID DllBase;
	PVOID EntryPoint;
	UINT32 SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	UINT32 Flags;
	UINT16 LoadCount;
	UINT16 SignatureInfo;
	PVOID SectionPointer;
	UINT32 CheckSum;
	UINT32 CoverageSectionSize;
	PVOID CoverageSection;
	PVOID LoadedImports;
	PVOID Spare;
	UINT32 SizeOfImageNotRounded;
	UINT32 TimeDateStamp;
} KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;

VOID
UkStripDriverPrefix(
    _In_ PUNICODE_STRING InputString,
    _Out_ PUNICODE_STRING OutputString
);

NTSTATUS
UkGetDriverImagePath(
    _In_ PUNICODE_STRING DriverName,
    _Out_ PUNICODE_STRING ImagePath
);

INT
_strcmpi_w(
    _In_ const wchar_t* s1,
    _In_ const wchar_t* s2
);

PKLDR_DATA_TABLE_ENTRY
UkGetDriverForAddress(
    _In_ ULONG_PTR address
);

ULONG_PTR
UkGetThreadStartAddress(
    _In_ PETHREAD ThreadObj
);

VOID
UkSleepMs(
    INT milliseconds
);

//
// globals
//
extern BOOLEAN g_doAPCStackWalk;
extern KEVENT g_kernelApcSyncEvent;
extern KEVENT g_rundownApcSyncEvent;
extern KEVENT g_apcFinishedEvent;
