#include "handlers.h"
#include "utils.h"
#include "deviceobjects.h"

BOOLEAN g_checkHandlers = TRUE;
KEVENT g_checkHandlersFinishedEvent;

extern POBJECT_TYPE* IoDeviceObjectType;

/**
 * @brief Checks for hooked IOCTL handlers in the driver object of each driver.
 *
 * @param[IN] StartContext Context parameter (unused).
 */
_IRQL_requires_same_
_IRQL_requires_(PASSIVE_LEVEL)
VOID
UkCheckHandlers(
    _In_ PVOID StartContext
)
{
    UNREFERENCED_PARAMETER(StartContext);

    KeInitializeEvent(&g_checkHandlersFinishedEvent, SynchronizationEvent, FALSE);

    NTSTATUS status;
    PVOID directory = nullptr;
    HANDLE handle = nullptr;
    OBJECT_ATTRIBUTES attributes;
    UNICODE_STRING directoryName = RTL_CONSTANT_STRING(L"\\Driver");

    //
    // Get Handle to \\Driver directory
    //
    InitializeObjectAttributes(&attributes, &directoryName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    status = ZwOpenDirectoryObject(&handle, DIRECTORY_ALL_ACCESS, &attributes);
    if (!NT_SUCCESS(status))
    {
        LOG_DBG("Couldnt get \\Driver directory handle\n");
        KeSetEvent(&g_checkHandlersFinishedEvent, IO_NO_INCREMENT, FALSE);
        PsTerminateSystemThread(status);
        return;
    }

    status = ObReferenceObjectByHandle(handle, DIRECTORY_ALL_ACCESS, nullptr, KernelMode, &directory, nullptr);
    if (!NT_SUCCESS(status))
    {
        LOG_DBG("Couldnt get \\Driver directory object from handle\n");
        ZwClose(handle);
        KeSetEvent(&g_checkHandlersFinishedEvent, IO_NO_INCREMENT, FALSE);
        PsTerminateSystemThread(status);
        return;
    }

    POBJECT_DIRECTORY directoryObject = (POBJECT_DIRECTORY)directory;

    do
    {
        UkTraceEtw("HandlerChecker", "Scanning DriverObjects...");

        KeEnterCriticalRegion();
        ExAcquirePushLockExclusiveEx((PEX_PUSH_LOCK)&directoryObject->Lock, 0);

        for (size_t i = 0; i < 37; ++i)
        {
            POBJECT_DIRECTORY_ENTRY entry = directoryObject->HashBuckets[i];
            if (!entry)
                continue;

            while (entry != nullptr && entry->Object)
            {
                PDRIVER_OBJECT driver = (PDRIVER_OBJECT)entry->Object;

                if (!driver)
                {
                    entry = entry->ChainLink;
                    continue;
                }

                for (INT j = 0; j < IRP_MJ_MAXIMUM_FUNCTION; ++j)
                {
                    const ULONG_PTR handlerAddress = (ULONG_PTR)driver->MajorFunction[j];
                    if (!handlerAddress)
                        continue;

                    PKLDR_DATA_TABLE_ENTRY handlerEntry = UkGetDriverForAddress(handlerAddress);
                    if (!handlerEntry)
                    {
                        UkTraceEtw("HandlerChecker",
                            "Driver %wZ has hooked MajorFunction[%d] at address 0x%p",
                            driver->DriverName,
                            j,
                            (PVOID)handlerAddress
                        );
                    }
                }

                entry = entry->ChainLink;
            }
        }

        ExReleasePushLockExclusiveEx((PEX_PUSH_LOCK)&directoryObject->Lock, 0);
        KeLeaveCriticalRegion();

        UkSleepMs(5000);

    } while (g_checkHandlers);

    // 
    // Cleanup object references before signaling completion
    //
    ObDereferenceObject(directory);
    ZwClose(handle);

    KeSetEvent(&g_checkHandlersFinishedEvent, IO_NO_INCREMENT, FALSE);
    PsTerminateSystemThread(STATUS_SUCCESS);
}