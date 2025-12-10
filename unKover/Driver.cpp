#include "Driver.h"
#include <ntifs.h>
#include <ntddk.h>

#include "meta.h"
#include "nmi.h"
#include "threads.h"
#include "apc.h"
#include "deviceobjects.h"
#include "sectioncompare.h"
#include "hiding.h"
#include "handlers.h"

//
// define handles
//
HANDLE g_hScanSystemThreads = NULL;
HANDLE g_hSendNmis = NULL;
HANDLE g_hCheckDriverObjects = NULL;
HANDLE g_hAPCCheck = NULL;
HANDLE g_hTextSectionCompare = NULL;
HANDLE g_hHidingDetection = NULL;
HANDLE g_hCheckHandlers = NULL;

/**
 * @brief Waits for a worker thread to signal completion and closes its handle.
 *
 * @param[IN] pThreadHandle    Pointer to thread handle to close.
 * @param[IN] pFinishedEvent   Event signaled by the worker thread.
 */
_IRQL_requires_same_
_IRQL_requires_(PASSIVE_LEVEL)
static VOID
UkShutdownThread(
    PHANDLE pThreadHandle,
    PKEVENT pFinishedEvent
)
{
    KeWaitForSingleObject(pFinishedEvent, Executive, KernelMode, FALSE, NULL);
    if (pThreadHandle)
    {
        ZwClose(*pThreadHandle);
        *pThreadHandle = NULL;
    }
}

/**
 * @brief Driver unload routine.
 *
 * @param[IN] drvObj Driver object.
 */
_Function_class_(DRIVER_UNLOAD)
_IRQL_requires_same_
_IRQL_requires_(PASSIVE_LEVEL)
VOID
DriverUnload(
    PDRIVER_OBJECT drvObj
)
{
	UNREFERENCED_PARAMETER(drvObj);

    //
    // Unload sequence
    //
    LOG_DBG("Unload called\n");
    LOG_DBG("Stopping all threads. This can a few seconds...\n");

    g_doAPCStackWalk = FALSE;
    g_sendNmis = FALSE;
    g_scanSystemThreads = FALSE;
    g_scanDriverObjects = FALSE;
    g_compareTextSections = FALSE;
    g_hidingDetection = FALSE;
	g_checkHandlers = FALSE;

    //
    // Unregister TraceLogging provider on unload
    //
    TraceLoggingUnregister(g_hTraceProvider);

    UkShutdownThread(&g_hAPCCheck, &g_apcFinishedEvent);
    UkShutdownThread(&g_hSendNmis, &g_sendNmisFinishedEvent);
    UkShutdownThread(&g_hScanSystemThreads, &g_scanSystemThreadsFinishedEvent);
    UkShutdownThread(&g_hCheckDriverObjects, &g_scanDriverObjectsFinishedEvent);
    UkShutdownThread(&g_hTextSectionCompare, &g_compareTextSectionsFinishedEvent);
    UkShutdownThread(&g_hHidingDetection, &g_hidingDetectionFinishedEvent);
    UkShutdownThread(&g_hCheckHandlers, &g_checkHandlersFinishedEvent);
    
    //
    // Wait 3 seconds for termination
    //
    UkSleepMs(3000);

    //
    // Unload NMI module
    //
    UkUnloadNMI();
}

/**
 * @brief Driver entry routine.
 *
 * @param[IN] drvObj   Driver object provided by the system.
 * @param[IN] regPath  Registry path.
 *
 * @return NTSTATUS code.
 */
EXTERN_C
_Function_class_(DRIVER_INITIALIZE)
_IRQL_requires_same_
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS 
DriverEntry(
    PDRIVER_OBJECT drvObj,
    PUNICODE_STRING regPath
)
{
    UNREFERENCED_PARAMETER(regPath);

    LOG_DBG("unKover driver entry\n");

    g_drvObj = drvObj;
    drvObj->DriverUnload = DriverUnload;

    NTSTATUS NtStatus = STATUS_SUCCESS;

    if (!UkRegisterNmiCallbacks())
    {
        UkUnloadNMI();
        return STATUS_FAILED_DRIVER_ENTRY;
    }

    //
    // Register TraceLogging provider
    //
    TraceLoggingRegister(g_hTraceProvider);

    //
    // Start monitoring threads
    //
    UkTraceEtw("LOG", "Creating thread to scan system threads");
    NtStatus = PsCreateSystemThread(&g_hScanSystemThreads, THREAD_ALL_ACCESS, NULL, NULL, NULL, UkScanSystemThreads, NULL);
    if (!NT_SUCCESS(NtStatus))
    {
        return NtStatus;
    }

    UkTraceEtw("LOG", "Creating thread to send NMIs and analyze call stacks");
    NtStatus = PsCreateSystemThread(&g_hSendNmis, THREAD_ALL_ACCESS, NULL, NULL, NULL, UkSendNMI, NULL);
    if (!NT_SUCCESS(NtStatus))
    {
        return NtStatus;
    }

    UkTraceEtw("LOG", "Creating thread to check DriverObjects in object manager");
    NtStatus = PsCreateSystemThread(&g_hCheckDriverObjects, THREAD_ALL_ACCESS, NULL, NULL, NULL, UkCheckDriverObjects, NULL);
    if (!NT_SUCCESS(NtStatus))
    {
        return NtStatus;
    }

    UkTraceEtw("LOG", "Creating thread to check call stacks via APC");
    NtStatus = PsCreateSystemThread(&g_hAPCCheck, THREAD_ALL_ACCESS, NULL, NULL, NULL, UkAPCStackWalk, NULL);
    if (!NT_SUCCESS(NtStatus))
    {
        return NtStatus;
    }

    UkTraceEtw("LOG", "Creating thread to compare driver .text sections");
    NtStatus = PsCreateSystemThread(&g_hTextSectionCompare, THREAD_ALL_ACCESS, NULL, NULL, NULL, UkCompareTextSections, NULL);
    if (!NT_SUCCESS(NtStatus))
    {
        return NtStatus;
    }

    UkTraceEtw("LOG", "Creating thread to detect threads hidden from PspCidTable");
    NtStatus = PsCreateSystemThread(&g_hHidingDetection, THREAD_ALL_ACCESS, NULL, NULL, NULL, UkDetectHiddenThreads, NULL);
    if (!NT_SUCCESS(NtStatus))
    {
        return NtStatus;
    }

    UkTraceEtw("LOG", "Creating thread to check driver IOCTL handlers for hooks");
	NtStatus = PsCreateSystemThread(&g_hCheckHandlers, THREAD_ALL_ACCESS, NULL, NULL, NULL, UkCheckHandlers, NULL);
    if (!NT_SUCCESS(NtStatus))
    {
        return NtStatus;
    }

	UkTraceEtw("LOG", "Driver initialized successfully");

    //
    // TODO: check physmem handles, hal pointers, more
    //  

    return NtStatus;
}
