#include "deviceobjects.h"

BOOLEAN g_scanDriverObjects = TRUE;
KEVENT g_scanDriverObjectsFinishedEvent;
ULONG_PTR g_hashBucketLock = NULL;

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

    // Get Handle to \\Driver directory
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
        UkTraceEtw("DeviceObjectScanner", "Scanning DriverObjects...");

        // Lock for the hashbucket
        KeEnterCriticalRegion(); 
        ExAcquirePushLockExclusiveEx((PEX_PUSH_LOCK)&g_hashBucketLock, 0);

        for (size_t i = 0; i < 37; ++i)
        {
            POBJECT_DIRECTORY_ENTRY entry = directoryObject->HashBuckets[i];
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
                    UkTraceEtw("DeviceObjectScanner", "Detected DriverObject.DriverStart pointing to unbacked or invalid region %ws @ 0x%llx",
                        driver->DriverName.Buffer,
                        (ULONG_PTR)driver->DriverStart
                    );
                }
                if (UkGetDriverForAddress((ULONG_PTR)driver->DriverInit) == NULL)
                {
                    UkTraceEtw("DeviceObjectScanner", "Detected DriverEntry pointing to unbacked region %ws @ 0x%llx",
                        driver->DriverName.Buffer,
                        (ULONG_PTR)driver->DriverInit
                    );
                }

                entry = entry->ChainLink;
            }
        }

        ExReleasePushLockExclusiveEx((PEX_PUSH_LOCK)&g_hashBucketLock, 0);
        KeLeaveCriticalRegion();

        UkSleepMs(5000);

    } while (g_scanDriverObjects);

    ObDereferenceObject(directory);
    ZwClose(handle);    

    KeSetEvent(&g_scanDriverObjectsFinishedEvent, 0, TRUE);
    KeWaitForSingleObject(&g_scanDriverObjectsFinishedEvent, Executive, KernelMode, FALSE, NULL);

    PsTerminateSystemThread(STATUS_SUCCESS);
}
