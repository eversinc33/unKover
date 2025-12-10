#include "nmi.h"
#include "utils.h"

EXTERN_C VOID KeInitializeAffinityEx(PKAFFINITY_EX affinity);
EXTERN_C VOID KeAddProcessorAffinityEx(PKAFFINITY_EX affinity, INT num);
EXTERN_C VOID HalSendNMI(PKAFFINITY_EX affinity);

ULONG g_numCores = 0;
PVOID g_NmiCallbackHandle = NULL;
PKAFFINITY_EX g_NmiAffinity = NULL;
PNMI_CONTEXT g_NmiContext = NULL;
HANDLE SendNMIThreadHandle = NULL;

BOOLEAN g_sendNmis = TRUE;
KEVENT g_sendNmisFinishedEvent;

/**
 * @brief NMI callback that captures minimal stack information per processor.
 *
 * @param[IN] context   Per-processor NMI_CONTEXT array.
 * @param[IN] handled   Whether NMI was handled (unused).
 *
 * @return TRUE always.
 */
_IRQL_requires_same_
BOOLEAN 
UkNmiCallback(
    _In_ PVOID context,
    _In_ BOOLEAN handled
)
{
    UNREFERENCED_PARAMETER(handled);

    PNMI_CONTEXT nmiContext = (PNMI_CONTEXT)context;
    ULONG procNum = KeGetCurrentProcessorNumber();
    
    nmiContext[procNum].numFired++;
    nmiContext[procNum].threadId = HandleToULong(PsGetCurrentThreadId());
    nmiContext[procNum].framesCaptured = RtlCaptureStackBackTrace(
        0, 
        STACK_CAPTURE_SIZE, 
        (PVOID*)nmiContext[procNum].stackFrames,
        NULL
    );

    return TRUE;
}

/**
 * @brief Analyze captured NMI data and emit ETW reports for suspicious frames.
 */
_IRQL_requires_same_
_IRQL_requires_(PASSIVE_LEVEL)
VOID
UkAnalyzeNmiData(
    VOID
)
{
    for (auto core=0u; core<g_numCores; ++core)
    {
        PETHREAD ThreadObj = NULL;
        NMI_CONTEXT nmiContext = g_NmiContext[core];

        LOG_DBG("NMI callback data: TID: %l\n", nmiContext.threadId);

        if (nmiContext.threadId == 0)
        {
            continue;
        }

        if (!NT_SUCCESS(PsLookupThreadByThreadId(ULongToHandle(nmiContext.threadId), &ThreadObj)))
        {
            LOG_DBG("PsLookupThreadByThreadId error\n");
            continue;
        }

        //
        // Check each stack frame for origin
        //
        for (auto i = 0; i < nmiContext.framesCaptured; ++i)
        {
            ULONG_PTR addr = (ULONG_PTR)(nmiContext.stackFrames[i]);
            PKLDR_DATA_TABLE_ENTRY driver = UkGetDriverForAddress(addr);

            if (driver == NULL)
            {
                UkTraceEtw("NmiCallback", "Detected stack frame pointing to unbacked region. TID: %u @ 0x%llx", nmiContext.threadId, addr);
            
                //
                // Print stack frame TODO: clean this code
                //
                for (auto j = 0; j < nmiContext.framesCaptured; ++j)
                {
                    ULONG_PTR address = (ULONG_PTR)nmiContext.stackFrames[j];
                    PKLDR_DATA_TABLE_ENTRY currDriver = UkGetDriverForAddress(address);
                    if (currDriver == NULL)
                    {
                        UkTraceEtw("NmiCallback", "[%d] Stack frame %lu: 0x%llx // %ws\n", nmiContext.threadId, j, address, L"??? <------ Unbacked!");
                    }
                    else
                    {
                        auto offsetToFunction = (currDriver == NULL) ? address : (address - (ULONG_PTR)currDriver->DllBase);
                        PWCHAR driverName = currDriver->BaseDllName.Buffer;
                        UkTraceEtw("NmiCallback", "[%d] Stack frame %lu: 0x%llx+0x%llx // %ws\n", nmiContext.threadId, j, (ULONG_PTR)currDriver->DllBase, offsetToFunction, driverName);
                    }
                }
            }
        }
        
        if (ThreadObj)
        {
            ObDereferenceObject(ThreadObj);
        }
    }
}

/**
 * @brief Allocate and initialize NMI resources and state.
 *
 * @return TRUE on success; FALSE otherwise.
 */
_IRQL_requires_same_
_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN 
UkRegisterNmiCallbacks(
    VOID
)
{
    g_numCores = KeQueryActiveProcessorCountEx(0);
    ULONG nmiContextLength = g_numCores * sizeof(NMI_CONTEXT);

    g_NmiContext = (PNMI_CONTEXT)ExAllocatePoolWithTag(NonPagedPool, nmiContextLength, POOL_TAG);
    g_NmiAffinity = (PKAFFINITY_EX)ExAllocatePoolWithTag(NonPagedPool, sizeof(KAFFINITY_EX), POOL_TAG);

    if (!g_NmiAffinity || !g_NmiContext)
        return FALSE;

    RtlSecureZeroMemory(g_NmiContext, nmiContextLength);

    return TRUE;
}

/**
 * @brief Release NMI-related resources and deregister callback if present.
 */
_IRQL_requires_same_
_IRQL_requires_(PASSIVE_LEVEL)
VOID 
UkUnloadNMI(
    VOID
)
{
    if (g_NmiCallbackHandle) KeDeregisterNmiCallback(g_NmiCallbackHandle);
    if (g_NmiAffinity) ExFreePoolWithTag(g_NmiAffinity, POOL_TAG);
    if (g_NmiContext) ExFreePoolWithTag(g_NmiContext, POOL_TAG);
}

/**
 * @brief Send NMI to each processor and process captured data.
 *
 * @param[IN] StartContext unused.
 */
_IRQL_requires_same_
_IRQL_requires_(PASSIVE_LEVEL)
VOID
UkSendNMI(
    _In_ PVOID StartContext
)
{
    UNREFERENCED_PARAMETER(StartContext);

    NTSTATUS NtStatus;

    KeInitializeEvent(&g_sendNmisFinishedEvent, SynchronizationEvent, FALSE);

    do
    {
        //
        // Register callback
        //
        g_NmiCallbackHandle = KeRegisterNmiCallback(UkNmiCallback, g_NmiContext);

        //
        // Fire NMI for each core
        //
        for (auto core=0u; core<g_numCores; ++core)
        {
            KeInitializeAffinityEx(g_NmiAffinity);
            KeAddProcessorAffinityEx(g_NmiAffinity, core);

            LOG_DBG("Sending NMI to analyze thread running on core %d...\n", core);
            HalSendNMI(g_NmiAffinity);

            //
            // Sleep for 1 seconds between each NMI to allow completion
            //
            UkSleepMs(1000);
        }

        //
        // Unregister callback
        //
        if (g_NmiCallbackHandle)
        {
            NtStatus = KeDeregisterNmiCallback(g_NmiCallbackHandle);
            if (!NT_SUCCESS(NtStatus))
            {
                LOG_DBG("KeDeregisterNmiCallback error: %d\n", NtStatus);
            }
        }

        //
        // Analyze data
        //
        UkAnalyzeNmiData();

        UkSleepMs(5000);

    } while (g_sendNmis);

    KeSetEvent(&g_sendNmisFinishedEvent, 0, FALSE);
    PsTerminateSystemThread(STATUS_SUCCESS);
}
