#pragma once

#include <ntddk.h>
#include "utils.hpp"

BOOLEAN g_scanSystemThreads = TRUE;
KEVENT g_scanSystemThreadsFinishedEvent;

/**
 * Scans all system threads for memory that is not backed by a module on disk.
 */
VOID 
UkScanSystemThreads(IN PVOID StartContext)
{
	UNREFERENCED_PARAMETER(StartContext);

	KeInitializeEvent(&g_scanSystemThreadsFinishedEvent, NotificationEvent, FALSE);

	do
	{
		LOG_DBG("Scanning running system threads...\n");

		// Scan system threads. TIDs are a multiple of 4 TODO: max number?
		for (auto tid=4; tid<0xFFFF; tid += 4)
		{
			PETHREAD ThreadObj;

			// Get ETHREAD object for TID
			if (tid == 0 || !NT_SUCCESS(PsLookupThreadByThreadId(ULongToHandle(tid), &ThreadObj)))
			{
				continue;
			}

			// Ignore current thread and non system threads
			if (!PsIsSystemThread(ThreadObj) || ThreadObj == KeGetCurrentThread())
			{
				if (ThreadObj) { ObDereferenceObject(ThreadObj); }
				continue;
			}

			// Resolve start address
			ULONG_PTR startAddress = UkGetThreadStartAddress(ThreadObj);
			if (startAddress != 0)
			{
				if (UkGetDriverForAddress(startAddress) == NULL)
				{
					LOG_MSG("[SystemThreadScanner] -> Detected system thread start address pointing to unbacked region: TID: %lu @ 0x%llx\n", tid, startAddress);
				}
			}

			ObDereferenceObject(ThreadObj);
		}

		UkSleepMs(5000);

	} while(g_scanSystemThreads);
	
	KeSetEvent(&g_scanSystemThreadsFinishedEvent, 0, TRUE);
	KeWaitForSingleObject(&g_scanSystemThreadsFinishedEvent, Executive, KernelMode, FALSE, NULL);
	PsTerminateSystemThread(STATUS_SUCCESS);
}