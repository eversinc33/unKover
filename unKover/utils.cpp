#include <ntifs.h>
#include <ntddk.h>
#include "meta.h"
#include "utils.hpp"

BOOLEAN g_doAPCStackWalk = TRUE;
KEVENT g_kernelApcSyncEvent;
KEVENT g_rundownApcSyncEvent;
KEVENT g_apcFinishedEvent;

VOID
UkStripDriverPrefix(
    PUNICODE_STRING InputString,
    PUNICODE_STRING OutputString
)
{
    UNICODE_STRING prefix = RTL_CONSTANT_STRING(L"\\Driver");
    if (RtlPrefixUnicodeString(&prefix, InputString, TRUE))
    {
        USHORT newLength = (USHORT)(InputString->Length - prefix.Length);
        OutputString->Buffer = InputString->Buffer + (prefix.Length / sizeof(WCHAR));
        OutputString->Length = newLength;
        OutputString->MaximumLength = newLength;
    }
    else
    {
        RtlCopyUnicodeString(OutputString, InputString);
    }
}

NTSTATUS
UkGetDriverImagePath(
    _In_ PUNICODE_STRING DriverName,
    _Out_ PUNICODE_STRING ImagePath
)
{
    NTSTATUS status;
    UNICODE_STRING registryPath;
    OBJECT_ATTRIBUTES objectAttributes;
    HANDLE keyHandle = NULL;
    ULONG resultLength;
    PKEY_VALUE_PARTIAL_INFORMATION keyValueInfo = NULL;

    WCHAR registryPathBuffer[256];
    registryPath.Buffer = registryPathBuffer;
    registryPath.Length = 0;
    registryPath.MaximumLength = sizeof(registryPathBuffer);
    RtlAppendUnicodeToString(&registryPath, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services");
    RtlAppendUnicodeStringToString(&registryPath, DriverName);

    InitializeObjectAttributes(&objectAttributes, &registryPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    status = ZwOpenKey(&keyHandle, KEY_READ, &objectAttributes);
    if (!NT_SUCCESS(status))
    {
        UkTraceEtw("LOG", "[!] Failed to open registry key: %wZ, Status: 0x%x", &registryPath, status);
        goto Cleanup;
    }

    ULONG keyValueInfoSize = sizeof(KEY_VALUE_PARTIAL_INFORMATION) + 256 * sizeof(WCHAR);
    keyValueInfo = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(PagedPool, keyValueInfoSize, POOL_TAG);
    if (!keyValueInfo)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    UNICODE_STRING valueName;
    RtlInitUnicodeString(&valueName, L"ImagePath");
    status = ZwQueryValueKey(keyHandle, &valueName, KeyValuePartialInformation, keyValueInfo, keyValueInfoSize, &resultLength);
    if (NT_SUCCESS(status))
    {
        RtlInitUnicodeString(ImagePath, (PCWSTR)keyValueInfo->Data);
    }
    else
    {
        UkTraceEtw("LOG", "Failed to query ImagePath value, Status: 0x%x", status);
        goto Cleanup;
    }

Cleanup:
    if (keyValueInfo) { ExFreePoolWithTag(keyValueInfo, POOL_TAG); }
    if (keyHandle) { ZwClose(keyHandle); }
    return status;
}

INT
_strcmpi_w(const wchar_t* s1, const wchar_t* s2)
{
    WCHAR c1, c2;

    if (s1 == s2)
        return 0;

    if (s1 == 0)
        return -1;

    if (s2 == 0)
        return 1;

    do {
        c1 = RtlUpcaseUnicodeChar(*s1);
        c2 = RtlUpcaseUnicodeChar(*s2);
        s1++;
        s2++;
    } while ((c1 != 0) && (c1 == c2));

    return (INT)(c1 - c2);
}

PKLDR_DATA_TABLE_ENTRY
UkGetDriverForAddress(ULONG_PTR address)
{
    if (!address || g_drvObj == NULL)
    {
        return NULL;
    }

    PKLDR_DATA_TABLE_ENTRY entry = (PKLDR_DATA_TABLE_ENTRY)g_drvObj->DriverSection;

    for (auto i = 0; i < 512 && entry; ++i)
    {
        UINT64 startAddr = (UINT64)entry->DllBase;
        UINT64 endAddr = startAddr + (UINT64)entry->SizeOfImage;
        if (address >= startAddr && address < endAddr)
        {
            return entry;
        }
        entry = (PKLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink;
    }

    return NULL;
}

ULONG_PTR
UkGetThreadStartAddress(PETHREAD ThreadObj)
{
    HANDLE hThread;
    ULONG_PTR startAddress = 0;
    ULONG bytesReturned = 0;

    if (!ThreadObj)
        return 0;

    if (ObOpenObjectByPointer(ThreadObj, OBJ_KERNEL_HANDLE, NULL, GENERIC_READ, *PsThreadType, KernelMode, &hThread) != STATUS_SUCCESS)
    {
        return 0;
    }

    if (!NT_SUCCESS(ZwQueryInformationThread(hThread, (THREADINFOCLASS)ThreadQuerySetWin32StartAddress, &startAddress, sizeof(startAddress), &bytesReturned)))
    {
        ZwClose(hThread);
        return 0;
    }

    if (!MmIsAddressValid((PVOID)startAddress))
    {
        ZwClose(hThread);
        return 0;
    }

    ZwClose(hThread);
    return startAddress;
}

VOID
UkSleepMs(INT milliseconds)
{
    LARGE_INTEGER interval;
    interval.QuadPart = -1 * (LONGLONG)(milliseconds * 10000);
    KeDelayExecutionThread(KernelMode, FALSE, &interval);
}
