#pragma once

#include <ntddk.h>
#include "meta.h"

EXTERN_C NTSTATUS ZwQueryInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength);

/* Minimal KLDR_DATA_TABLE_ENTRY used by UkGetDriverForAddress. */
typedef struct _KLDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    UINT32 SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;

/* Declarations only — implementations in utils.cpp */
VOID UkStripDriverPrefix(PUNICODE_STRING InputString, PUNICODE_STRING OutputString);
NTSTATUS UkGetDriverImagePath(_In_ PUNICODE_STRING DriverName, _Out_ PUNICODE_STRING ImagePath);
INT _strcmpi_w(const wchar_t* s1, const wchar_t* s2);
PKLDR_DATA_TABLE_ENTRY UkGetDriverForAddress(ULONG_PTR address);
ULONG_PTR UkGetThreadStartAddress(PETHREAD ThreadObj);
VOID UkSleepMs(INT milliseconds);

/* globals declared extern — define in a single .cpp (e.g., utils.cpp) */
extern BOOLEAN g_doAPCStackWalk;
extern KEVENT g_kernelApcSyncEvent;
extern KEVENT g_rundownApcSyncEvent;
extern KEVENT g_apcFinishedEvent;
