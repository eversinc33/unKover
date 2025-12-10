#include "threads.h"
#include "meta.h"

BOOLEAN g_scanSystemThreads = TRUE;
KEVENT g_scanSystemThreadsFinishedEvent;

/**
 * @brief Scans running system threads to detect unbacked start addresses.
 *
 * @param[IN] StartContext Unused.
 */
_IRQL_requires_same_
_IRQL_requires_(PASSIVE_LEVEL)
VOID
UkScanSystemThreads(
    _In_ PVOID StartContext
)
{
    UNREFERENCED_PARAMETER(StartContext);

    KeInitializeEvent(&g_scanSystemThreadsFinishedEvent, SynchronizationEvent, FALSE);

    do
    {
        UkTraceEtw("SystemThreadScanner", "Scanning running system threads...");

        //
        // Scan system threads. TIDs are a multiple of 4 TODO: max number?
        //
        for (auto tid=4; tid<0xFFFF; tid += 4)
        {
            PETHREAD ThreadObj = NULL;

            //
            // Get ETHREAD object for TID
            //
            if (tid == 0 || !NT_SUCCESS(PsLookupThreadByThreadId(ULongToHandle(tid), &ThreadObj)))
            {
                continue;
            }

            //
            // Ignore current thread and non system threads
            //
            if (!PsIsSystemThread(ThreadObj) || ThreadObj == (PETHREAD)KeGetCurrentThread())
            {
                if (ThreadObj) { ObDereferenceObject(ThreadObj); }
                continue;
            }

            //
            // Resolve start address
            //
            ULONG_PTR startAddress = UkGetThreadStartAddress(ThreadObj);
            if (startAddress != 0)
            {
                if (UkGetDriverForAddress(startAddress) == NULL)
                {
                    UkTraceEtw("SystemThreadScanner", "Detected system thread start address pointing to unbacked region: TID: %lu @ 0x%llx", tid, startAddress);
                }
            }

            ObDereferenceObject(ThreadObj);
        }

        UkSleepMs(5000);

    } while(g_scanSystemThreads);
    
    KeSetEvent(&g_scanSystemThreadsFinishedEvent, 0, TRUE);
    PsTerminateSystemThread(STATUS_SUCCESS);
}
