#pragma once

#include <ntddk.h>
#include "meta.hpp"
#include "utils.hpp"

EXTERN_C NTSTATUS ZwQueryDirectoryObject(
    IN HANDLE DirectoryHandle,
    OUT PVOID Buffer,
    IN ULONG BufferLength,
    IN BOOLEAN ReturnSingleEntry,
    IN BOOLEAN RestartScan,
    IN OUT PULONG Context,
    OUT PULONG ReturnLength OPTIONAL
);

EXTERN_C NTSTATUS ObReferenceObjectByName(
    IN PUNICODE_STRING ObjectPath,
    IN ULONG Attributes,
    IN PACCESS_STATE PassedAccessState,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_TYPE ObjectType,
    IN KPROCESSOR_MODE AccessMode,
    IN OUT PVOID ParseContext,
    OUT PVOID* ObjectPtr
);

typedef struct _OBJECT_DIRECTORY_INFORMATION {
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, *POBJECT_DIRECTORY_INFORMATION;

typedef struct _OBJECT_TYPE_INITIALIZER
{
    USHORT Length;
    UCHAR ObjectTypeFlags;
    ULONG CaseInsensitive : 1;
    ULONG UnnamedObjectsOnly : 1;
    ULONG UseDefaultObject : 1;
    ULONG SecurityRequired : 1;
    ULONG MaintainHandleCount : 1;
    ULONG MaintainTypeList : 1;
    ULONG ObjectTypeCode;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccessMask;
    POOL_TYPE PoolType;
    ULONG DefaultPagedPoolCharge;
    ULONG DefaultNonPagedPoolCharge;
    PVOID DumpProcedure;
    LONG* OpenProcedure;
    PVOID CloseProcedure;
    PVOID DeleteProcedure;
    LONG* ParseProcedure;
    LONG* SecurityProcedure;
    LONG* QueryNameProcedure;
    UCHAR* OkayToCloseProcedure;
} OBJECT_TYPE_INITIALIZER, * POBJECT_TYPE_INITIALIZER;

typedef struct _OBJECT_TYPE
{
    // ERESOURCE Mutex; -> not in WinDbg probably negative offset or removed
    LIST_ENTRY TypeList;
    UNICODE_STRING Name;
    PVOID DefaultObject;
    UCHAR Index;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    OBJECT_TYPE_INITIALIZER TypeInfo;
    EX_PUSH_LOCK TypeLock;
    ULONG Key;
    LIST_ENTRY CallbackList;
} OBJECT_TYPE, * POBJECT_TYPE;

typedef struct _DEVICE_MAP* PDEVICE_MAP;

typedef struct _OBJECT_DIRECTORY_ENTRY
{
    _OBJECT_DIRECTORY_ENTRY* ChainLink;
    PVOID Object;
    ULONG HashValue;
} OBJECT_DIRECTORY_ENTRY, * POBJECT_DIRECTORY_ENTRY;

typedef struct _OBJECT_DIRECTORY
{
    POBJECT_DIRECTORY_ENTRY HashBuckets[37];
    EX_PUSH_LOCK Lock;
    PDEVICE_MAP DeviceMap;
    ULONG SessionId;
    PVOID NamespaceEntry;
    ULONG Flags;
} OBJECT_DIRECTORY, * POBJECT_DIRECTORY;

BOOLEAN g_scanDriverObjects = TRUE;
KEVENT g_scanDriverObjectsFinishedEvent;
ULONG_PTR g_hashBucketLock = NULL;

/**
 * Iterates all driver objects to check for hints to unbacked memory.
 * 
 * Original Credit: https://github.com/not-wlan/driver-hijack/blob/master/memedriver/hijack.cpp#L136
 */
VOID 
UkCheckDriverObjects(IN PVOID StartContext)
{
    UNREFERENCED_PARAMETER(StartContext);

    KeInitializeEvent(&g_scanDriverObjectsFinishedEvent, NotificationEvent, FALSE);

    NTSTATUS status;
    PVOID directory;
    HANDLE handle;
    OBJECT_ATTRIBUTES attributes;
    UNICODE_STRING directoryName = RTL_CONSTANT_STRING(L"\\Driver");

    // Get Handle to \Driver directory
    InitializeObjectAttributes(&attributes, &directoryName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    status = ZwOpenDirectoryObject(&handle, DIRECTORY_ALL_ACCESS, &attributes);
    if (!NT_SUCCESS(status))
    {
        LOG_DBG("Couldnt get \\Driver directory handle\n");
        return;
    }

    status = ObReferenceObjectByHandle(handle, DIRECTORY_ALL_ACCESS, nullptr, KernelMode, &directory, nullptr);
    if (!NT_SUCCESS(status))
    {
        ZwClose(handle);
        LOG_DBG("Couldnt get \\Driver directory object from handle\n");
        return;
    }

    POBJECT_DIRECTORY directoryObject = (POBJECT_DIRECTORY)directory;
    g_hashBucketLock = directoryObject->Lock;

    do
    {
        LOG_DBG("Scanning DriverObjects...\n");

        // Lock for the hashbucket
        KeEnterCriticalRegion(); 
        ExAcquirePushLockExclusiveEx(&g_hashBucketLock, 0);

        for (POBJECT_DIRECTORY_ENTRY entry : directoryObject->HashBuckets)
        {
            if (!entry)
            {
                continue;
            }

            while (entry != nullptr && entry->Object)
            {
                PDRIVER_OBJECT driver = (PDRIVER_OBJECT)entry->Object;

                // Check memory of DriverStart
                if (UkGetDriverForAddress((ULONG_PTR)driver->DriverStart) == NULL)
                {
                    LOG_MSG("[DeviceObjectScanner] -> Detected DriverObject.DriverStart pointing to unbacked or invalid region %ws @ 0x%llx\n",
                        driver->DriverName.Buffer,
                        (ULONG_PTR)driver->DriverStart
                    );
                }
                if (UkGetDriverForAddress((ULONG_PTR)driver->DriverInit) == NULL)
                {
                    LOG_MSG("[DeviceObjectScanner] -> Detected DriverEntry pointing to unbacked region %ws @ 0x%llx\n",
                        driver->DriverName.Buffer,
                        (ULONG_PTR)driver->DriverInit
                    );
                }

                entry = entry->ChainLink;
            }
        }

        ExReleasePushLockExclusiveEx(&g_hashBucketLock, 0);
        KeLeaveCriticalRegion();

        UkSleepMs(5000);

    } while (g_scanDriverObjects);

    ObDereferenceObject(directory);
    ZwClose(handle);
    KeSetEvent(&g_scanDriverObjectsFinishedEvent, 0, FALSE);
    PsTerminateSystemThread(STATUS_SUCCESS);
}