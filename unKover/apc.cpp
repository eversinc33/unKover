#include "apc.h"
#include "meta.h"

/**
 * @brief Normal APC routine; no operation.
 *
 * @param[IN] NormalContext   Optional normal context.
 * @param[IN] SystemArgument1 Optional system argument.
 * @param[IN] SystemArgument2 Optional system argument.
 */
_IRQL_requires_same_
_IRQL_requires_(PASSIVE_LEVEL)
VOID
UkNormalAPC(
    _In_opt_ PVOID NormalContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
)
{
    UNREFERENCED_PARAMETER(NormalContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);
}

/**
 * @brief APC rundown routine; releases APC object.
 *
 * @param[IN] Apc APC object to free.
 */
_IRQL_requires_same_
_IRQL_requires_(PASSIVE_LEVEL)
VOID
UkRundownAPC(
    _In_ PRKAPC Apc
)
{
    ExFreePoolWithTag(Apc, POOL_TAG);
}

/**
 * @brief Kernel APC routine that captures and analyzes the current thread's stack.
 *
 * @param[IN] Apc             APC object.
 * @param[OUT] NormalRoutine  Receives normal routine pointer.
 * @param[OUT] NormalContext  Receives normal context pointer.
 * @param[OUT] SystemArgument1 Receives system argument pointer.
 * @param[OUT] SystemArgument2 Receives system argument pointer.
 */
_IRQL_requires_same_
_IRQL_requires_(PASSIVE_LEVEL)
VOID 
UkCaptureStackAPC(
    IN PKAPC Apc,
    IN OUT PKNORMAL_ROUTINE* NormalRoutine,
    IN OUT PVOID* NormalContext,
    IN OUT PVOID* SystemArgument1,
    IN OUT PVOID* SystemArgument2
)
{
    UNREFERENCED_PARAMETER(Apc);
    UNREFERENCED_PARAMETER(NormalRoutine);
    UNREFERENCED_PARAMETER(NormalContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    PVOID* stackFrames = (PVOID*)ExAllocatePoolWithTag(NonPagedPoolNx, MAX_STACK_DEPTH * sizeof(PVOID), POOL_TAG);
    if (!stackFrames)
    {
        //
        // Signal that APC is done
        //
        ExFreePoolWithTag(Apc, POOL_TAG);
        KeSetEvent(&g_kernelApcSyncEvent, 0, FALSE);
        return;
    }

    RtlSecureZeroMemory(stackFrames, MAX_STACK_DEPTH * sizeof(PVOID));
    HANDLE threadId = PsGetCurrentThreadId();
    USHORT framesCaptured = RtlCaptureStackBackTrace(0, MAX_STACK_DEPTH, stackFrames, NULL);

    //
    // Stack trace analysis
    //
    for (auto i = 0; i < framesCaptured; ++i)
    {
        //
        // Check if address of frame is from unbacked memory
        //
        ULONG_PTR addr = (ULONG_PTR)stackFrames[i];
        if (UkGetDriverForAddress(addr) == NULL)
        {
            UkTraceEtw("APCStackWalk", "Detected stack frame pointing to unbacked region: TID: %lu @ 0x%llx", HandleToUlong(threadId), addr);
            
            //
            // Print stack frame TODO: clean this code
            //
            for (auto j = 0; j < framesCaptured; ++j)
            {
                ULONG_PTR address = (ULONG_PTR)stackFrames[j];
                PKLDR_DATA_TABLE_ENTRY driver = UkGetDriverForAddress(address);
                if (driver == NULL) 
                { 
                    UkTraceEtw("APCStackWalk", "  [%d] Stack frame %lu: 0x%llx // %ws", HandleToUlong(threadId), j, address, L"??? <------ Unbacked!"); 
                }
                else 
                {
                    auto offsetToFunction = (driver == NULL) ? address : (address - (ULONG_PTR)driver->DllBase);
                    PWCHAR driverName = driver->BaseDllName.Buffer;
                    UkTraceEtw("APCStackWalk", "  [%d] Stack frame %lu: 0x%llx+0x%llx // %ws", HandleToUlong(threadId), j, (ULONG_PTR)driver->DllBase, offsetToFunction, driverName);
                }
            }
        }
    }

    if (stackFrames) { ExFreePoolWithTag(stackFrames, POOL_TAG); }

    //
    // Signal that APC is done
    //
    ExFreePoolWithTag(Apc, POOL_TAG);
    KeSetEvent(&g_kernelApcSyncEvent, 0, FALSE);
}

/**
 * @brief Worker function that periodically queues kernel APCs to system threads to analyze stacks.
 *
 * @param[IN] StartContext Optional start context.
 */
_IRQL_requires_same_
_IRQL_requires_(PASSIVE_LEVEL)
VOID
UkAPCStackWalk(
    IN PVOID StartContext
)
{
    UNREFERENCED_PARAMETER(StartContext);

    NTSTATUS NtStatus;

    KeInitializeEvent(&g_apcFinishedEvent, SynchronizationEvent, FALSE);
    KeInitializeEvent(&g_kernelApcSyncEvent, NotificationEvent, FALSE);

    do
    {
        LOG_DBG("Scanning running system thread call stacks via APC...\n");

        //
        // Queue APCs to system threads. TIDs are a multiple of 4. TODO: max number?
        //
        for (auto tid = 4; tid < 0xFFFF; tid += 4)
        {
            PETHREAD ThreadObj;
            PKAPC apc;

            //
            // Get ETHREAD object for TID
            //
            if (!NT_SUCCESS(PsLookupThreadByThreadId(UlongToHandle(tid), &ThreadObj)))
            {
                continue;
            }

            //
            // Ignore current thread and non system threads
            //
            if (!PsIsSystemThread(ThreadObj) || ThreadObj == (PETHREAD)KeGetCurrentThread())
            {
                ObDereferenceObject(ThreadObj);
                continue;
            }

            //
            // Initialize APC
            //
            apc = (PKAPC)ExAllocatePoolWithTag(
                NonPagedPool,
                sizeof(KAPC),
                POOL_TAG
            );
            KeInitializeApc(apc,
                (PKTHREAD)ThreadObj,
                OriginalApcEnvironment,
                UkCaptureStackAPC,
                UkRundownAPC,
                UkNormalAPC,
                KernelMode,
                NULL
            );

            //
            // Queue APC
            //
            NtStatus = KeInsertQueueApc(apc, NULL, NULL, IO_NO_INCREMENT);
            if (!NT_SUCCESS(NtStatus))
            {
                LOG_DBG("KeInsertQueueApc failed\n");
                KeSetEvent(&g_kernelApcSyncEvent, 0, FALSE);
                KeSetEvent(&g_rundownApcSyncEvent, 0, FALSE);
            }

            //
            // Wait for event to signal that the apc is done before queueing the next one
            //
            UkSleepMs(50);
            LARGE_INTEGER timeout;
            timeout.QuadPart = 5000;
            NtStatus = KeWaitForSingleObject(&g_kernelApcSyncEvent, Executive, KernelMode, FALSE, &timeout);
            if (NtStatus == STATUS_TIMEOUT)
            {
                LOG_DBG("APC did not return before timeout (tid: %u)\n", tid);
            }
            KeResetEvent(&g_kernelApcSyncEvent);

            //
            // Clean up
            //
            if (ThreadObj) { ObDereferenceObject(ThreadObj); }
        }

        UkSleepMs(5000);

    } while (g_doAPCStackWalk);

    KeSetEvent(&g_apcFinishedEvent, 0, TRUE);
    PsTerminateSystemThread(STATUS_SUCCESS);
}
