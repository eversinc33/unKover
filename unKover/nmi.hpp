#pragma once

#include <ntddk.h>
#include "meta.hpp"
#include <intrin.h>
#include "utils.hpp"

typedef struct _KAFFINITY_EX
{
	USHORT Count;
	USHORT Size;
	ULONG Reserved;
	ULONGLONG Bitmap[20];
} KAFFINITY_EX, *PKAFFINITY_EX;

#define STACK_CAPTURE_SIZE 32

typedef struct _NMI_CONTEXT
{
	ULONG threadId;
	INT numFired;
	USHORT framesCaptured;
	ULONG_PTR stackFrames[STACK_CAPTURE_SIZE];
} NMI_CONTEXT, *PNMI_CONTEXT;

EXTERN_C VOID KeInitializeAffinityEx(PKAFFINITY_EX affinity);
EXTERN_C VOID KeAddProcessorAffinityEx(PKAFFINITY_EX affinity, INT num);
EXTERN_C VOID HalSendNMI(PKAFFINITY_EX affinity);

ULONG g_numCores;
PVOID g_NmiCallbackHandle;
PKAFFINITY_EX g_NmiAffinity;
PNMI_CONTEXT g_NmiContext;
HANDLE SendNMIThreadHandle;

BOOLEAN g_sendNmis = TRUE;
KEVENT g_sendNmisFinishedEvent;

/**
 * Callback function to be called on NMI
 */
BOOLEAN 
UkNmiCallback(PVOID context, BOOLEAN handled)
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

VOID
UkAnalyzeNmiData()
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

		// Check each stack frame for origin
		for (auto i = 0; i < nmiContext.framesCaptured; ++i)
		{
			ULONG_PTR addr = (ULONG_PTR)(nmiContext.stackFrames[i]);
			PKLDR_DATA_TABLE_ENTRY driver = UkGetDriverForAddress(addr);

			if (driver == NULL)
			{
				LOG_MSG("[NmiCallback] -> Detected stack frame pointing to unbacked region. TID: %u @ 0x%llx", nmiContext.threadId, addr);
			
				// Print stack frame TODO: clean this code
				for (auto j = 0; j < nmiContext.framesCaptured; ++j)
				{
					ULONG_PTR address = (ULONG_PTR)nmiContext.stackFrames[j];
					PKLDR_DATA_TABLE_ENTRY currDriver = UkGetDriverForAddress(address);
					if (currDriver == NULL)
					{
						LOG_MSG("  [%d] Stack frame %lu: 0x%llx // %ws\n", nmiContext.threadId, j, address, L"??? <------ Unbacked!");
					}
					else
					{
						auto offsetToFunction = (currDriver == NULL) ? address : (address - (ULONG_PTR)currDriver->DllBase);
						PWCHAR driverName = currDriver->BaseDllName.Buffer;
						LOG_MSG("  [%d] Stack frame %lu: 0x%llx+0x%llx // %ws\n", nmiContext.threadId, j, (ULONG_PTR)currDriver->DllBase, offsetToFunction, driverName);
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

BOOLEAN 
UkRegisterNmiCallbacks()
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

VOID 
UkUnloadNMI()
{
	if (g_NmiCallbackHandle) KeDeregisterNmiCallback(g_NmiCallbackHandle);
	if (g_NmiAffinity) ExFreePoolWithTag(g_NmiAffinity, POOL_TAG);
	if (g_NmiContext) ExFreePoolWithTag(g_NmiContext, POOL_TAG);
}

VOID
UkSendNMI(IN PVOID StartContext)
{
	UNREFERENCED_PARAMETER(StartContext);

	NTSTATUS NtStatus;

	KeInitializeEvent(&g_sendNmisFinishedEvent, NotificationEvent, FALSE);

	do
	{
		// Register callback
		g_NmiCallbackHandle = KeRegisterNmiCallback(UkNmiCallback, g_NmiContext);

		// Fire NMI for each core
		for (auto core=0u; core<g_numCores; ++core)
		{
			KeInitializeAffinityEx(g_NmiAffinity);
			KeAddProcessorAffinityEx(g_NmiAffinity, core);

			LOG_DBG("Sending NMI to analyze thread running on core %d...\n", core);
			HalSendNMI(g_NmiAffinity);

			// Sleep for 1 seconds between each NMI to allow completion
			UkSleepMs(1000);
		}

		// Unregister callback
		if (g_NmiCallbackHandle)
		{
			NtStatus = KeDeregisterNmiCallback(g_NmiCallbackHandle);
			if (!NT_SUCCESS(NtStatus))
			{
				LOG_DBG("KeDeregisterNmiCallback error: %d\n", NtStatus);
			}
		}

		// Analyze data
		UkAnalyzeNmiData();

		UkSleepMs(5000);

	} while (g_sendNmis);

	KeSetEvent(&g_sendNmisFinishedEvent, 0, FALSE);
	PsTerminateSystemThread(STATUS_SUCCESS);
}