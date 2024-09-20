#include <ntifs.h>
#include <ntddk.h>
#include "meta.hpp"
#include "nmi.hpp"
#include "threads.hpp"
#include "apc.hpp"
#include "deviceobjects.hpp"
#include "sectioncompare.hpp"
#include "hiding.hpp"

HANDLE g_hScanSystemThreads;
HANDLE g_hSendNmis;
HANDLE g_hCheckDriverObjects;
HANDLE g_hAPCCheck;
HANDLE g_hTextSectionCompare;
HANDLE g_hHidingDetection;

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
	LOG_DBG("Unload called\n");
	LOG_DBG("Stopping all threads. This can a few seconds...\n");

	g_doAPCStackWalk = FALSE;
	g_sendNmis = FALSE;
	g_scanSystemThreads = FALSE;
	g_scanDriverObjects = FALSE;
	g_compareTextSections = FALSE;
	g_hidingDetection = FALSE;
	UkShutdownThread(&g_hAPCCheck, &g_apcFinishedEvent);
	UkShutdownThread(&g_hSendNmis, &g_sendNmisFinishedEvent);
	UkShutdownThread(&g_hScanSystemThreads, &g_scanSystemThreadsFinishedEvent);
	UkShutdownThread(&g_hCheckDriverObjects, &g_scanDriverObjectsFinishedEvent);
	UkShutdownThread(&g_hTextSectionCompare, &g_compareTextSectionsFinishedEvent);
	UkShutdownThread(&g_hHidingDetection, &g_hidingDetectionFinishedEvent);
	
	// Wait 3 seconds for termination
	UkSleepMs(3000);

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

		LOG_MSG("Creating thread to compare driver .text sections\n");
		NtStatus = PsCreateSystemThread(&g_hTextSectionCompare, THREAD_ALL_ACCESS, NULL, NULL, NULL, UkCompareTextSections, NULL);
		if (!NT_SUCCESS(NtStatus))
		{
			return NtStatus;
		}

		LOG_MSG("Creating thread to detect threads hidden from PspCidTable\n");
		NtStatus = PsCreateSystemThread(&g_hHidingDetection, THREAD_ALL_ACCESS, NULL, NULL, NULL, UkDetectHiddenThreads, NULL);
		if (!NT_SUCCESS(NtStatus))
		{
			return NtStatus;
		}

		// TODO: check physmem handles
		// TODO: more

		return NtStatus;
	}
}
