#include <ntifs.h>
#include <ntddk.h>
#include "meta.hpp"
#include "nmi.hpp"
#include "threads.hpp"
#include "apc.hpp"
#include "deviceobjects.hpp"

HANDLE g_hScanSystemThreads;
HANDLE g_hSendNmis;
HANDLE g_hCheckDriverObjects;
HANDLE g_hAPCCheck;

VOID 
UkShutdownThread(PHANDLE pThreadHandle, PKEVENT pFinishedEvent)
{
	KeWaitForSingleObject(pFinishedEvent, Executive, KernelMode, FALSE, NULL);
	if (pThreadHandle)
	{
		ZwClose(pThreadHandle);
	}
}

VOID 
DriverUnload(PDRIVER_OBJECT drvObj)
{
	UNREFERENCED_PARAMETER(drvObj);

	LOG_DBG("Unload called\n");
	LOG_DBG("Stopping all threads. This can a few seconds...\n");

	g_doAPCStackWalk = FALSE;
	g_sendNmis = FALSE;
	g_scanSystemThreads = FALSE;
	g_scanDriverObjects = FALSE;
	UkShutdownThread(&g_hAPCCheck, &g_apcFinishedEvent);
	UkShutdownThread(&g_hSendNmis, &g_sendNmisFinishedEvent);
	UkShutdownThread(&g_hScanSystemThreads, &g_scanSystemThreadsFinishedEvent);
	UkShutdownThread(&g_hCheckDriverObjects, &g_scanDriverObjectsFinishedEvent);

	// Wait 5 seconds for termination
	UkSleepMs(5000);

	// Unload NMI module
	UkUnloadNMI();
}

extern "C"
{
	NTSTATUS 
		DriverEntry(PDRIVER_OBJECT drvObj, PUNICODE_STRING regPath)
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

		// Start monitoring threads
		LOG_MSG("Creating thread to scan system threads\n");
		NtStatus = PsCreateSystemThread(&g_hScanSystemThreads, THREAD_ALL_ACCESS, NULL, NULL, NULL, UkScanSystemThreads, NULL);
		if (!NT_SUCCESS(NtStatus))
		{
			return NtStatus;
		}

		LOG_MSG("Creating thread to send NMIs and analyze call stacks\n");
		NtStatus = PsCreateSystemThread(&g_hSendNmis, THREAD_ALL_ACCESS, NULL, NULL, NULL, UkSendNMI, NULL);
		if (!NT_SUCCESS(NtStatus))
		{
			return NtStatus;
		}

		LOG_MSG("Creating thread to check DriverObjects in object manager\n");
		NtStatus = PsCreateSystemThread(&g_hCheckDriverObjects, THREAD_ALL_ACCESS, NULL, NULL, NULL, UkCheckDriverObjects, NULL);
		if (!NT_SUCCESS(NtStatus))
		{
			return NtStatus;
		}

		LOG_MSG("Creating thread to check call stacks via APC\n");
		NtStatus = PsCreateSystemThread(&g_hAPCCheck, THREAD_ALL_ACCESS, NULL, NULL, NULL, UkAPCStackWalk, NULL);
		if (!NT_SUCCESS(NtStatus))
		{
			return NtStatus;
		}

		// TODO: check physmem handles
		// TODO: compare drivers on disk to mem
		// TODO: compare PIDs in PspCidTable and EPROCESS linked list to check for potentially hiding threads
		// TODO: more

		return NtStatus;
	}
}