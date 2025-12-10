#include <ntifs.h>
#include <ntddk.h>
#include "meta.h"
#include "utils.h"

BOOLEAN g_doAPCStackWalk = TRUE;
KEVENT g_kernelApcSyncEvent;
KEVENT g_rundownApcSyncEvent;
KEVENT g_apcFinishedEvent;

/**
 * @brief Remove common driver path prefixes from the input string.
 *
 * @param[IN]  InputString  Original UNICODE string.
 * @param[OUT] OutputString Result string without prefix.
 */
_IRQL_requires_same_
_IRQL_requires_(PASSIVE_LEVEL)
VOID
UkStripDriverPrefix(
    _In_ PUNICODE_STRING InputString,
    _Out_ PUNICODE_STRING OutputString
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

/**
 * @brief Resolve driver image path from a given driver name.
 *
 * @param[IN]  DriverName Driver base name.
 * @param[OUT] ImagePath  Full image path.
 *
 * @return NTSTATUS.
 */
_IRQL_requires_same_
_IRQL_requires_(PASSIVE_LEVEL)
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

/**
 * @brief Case-insensitive wide-character strcmp.
 *
 * @param[IN] s1 First string.
 * @param[IN] s2 Second string.
 *
 * @return Comparison result.
 */
_IRQL_requires_same_
_IRQL_requires_(PASSIVE_LEVEL)
INT
_strcmpi_w(
    _In_ const wchar_t* s1,
    _In_ const wchar_t* s2
)
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

/**
 * @brief Get the driver module corresponding to a virtual address.
 *
 * @param[IN] address Target virtual address.
 *
 * @return Pointer to KLDR_DATA_TABLE_ENTRY, or NULL if not found.
 */
_IRQL_requires_same_
_IRQL_requires_max_(APC_LEVEL)
PKLDR_DATA_TABLE_ENTRY
UkGetDriverForAddress(
    _In_ ULONG_PTR address
)
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

/**
 * @brief Query a thread's start address.
 *
 * @param[IN] ThreadObj ETHREAD object pointer.
 *
 * @return Start address as ULONG_PTR.
 */
_IRQL_requires_same_
_IRQL_requires_(PASSIVE_LEVEL)
ULONG_PTR
UkGetThreadStartAddress(
    _In_ PETHREAD ThreadObj
)
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

/**
 * @brief Sleep the current thread for a given number of milliseconds.
 *
 * @param[IN] milliseconds Delay duration.
 */
_IRQL_requires_same_
_IRQL_requires_(PASSIVE_LEVEL)
VOID
UkSleepMs(
    INT milliseconds
)
{
    LARGE_INTEGER interval;
    interval.QuadPart = -1 * (LONGLONG)(milliseconds * 10000);
    KeDelayExecutionThread(KernelMode, FALSE, &interval);
}