#pragma once

#include <ntddk.h>
#include "autolock.hpp"
#include "meta.hpp"
#include "utils.hpp"

typedef enum _KAPC_ENVIRONMENT {
	OriginalApcEnvironment,
	AttachedApcEnvironment,
	CurrentApcEnvironment,
	InsertApcEnvironment
} KAPC_ENVIRONMENT;

typedef VOID(*PKNORMAL_ROUTINE)(
	_In_ PVOID NormalContext,
	_In_ PVOID SystemArgument1,
	_In_ PVOID SystemArgument2
);

typedef VOID(*PKKERNEL_ROUTINE) (
	IN PKAPC Apc,
	IN OUT PKNORMAL_ROUTINE* NormalRoutine,
	IN OUT PVOID* NormalContext,
	IN OUT PVOID* SystemArgument1,
	IN OUT PVOID* SystemArgument2
);

typedef VOID(*PKRUNDOWN_ROUTINE) (
	IN  PKAPC Apc
);

EXTERN_C VOID KeInitializeApc(
	IN  PKAPC Apc,
	IN  PKTHREAD Thread,
	IN  KAPC_ENVIRONMENT Environment,
	IN  PKKERNEL_ROUTINE KernelRoutine,
	IN  PKRUNDOWN_ROUTINE RundownRoutine OPTIONAL,
	IN  PKNORMAL_ROUTINE NormalRoutine OPTIONAL,
	IN  KPROCESSOR_MODE ApcMode OPTIONAL,
	IN  PVOID NormalContext OPTIONAL
);

EXTERN_C BOOLEAN KeInsertQueueApc(
	IN  PKAPC Apc,
	IN  PVOID SystemArgument1,
	IN  PVOID SystemArgument2,
	IN  KPRIORITY Increment
);

BOOLEAN g_doAPCStackWalk = TRUE;
KEVENT g_kernelApcSyncEvent;
KEVENT g_rundownApcSyncEvent;
KEVENT g_apcFinishedEvent;

#define MAX_STACK_DEPTH 32

VOID
UkNormalAPC(_In_opt_ PVOID NormalContext,
	_In_opt_ PVOID SystemArgument1,
	_In_opt_ PVOID SystemArgument2)
{
	UNREFERENCED_PARAMETER(NormalContext);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);
}

VOID
UkRundownAPC(_In_ PRKAPC Apc)
{
	ExFreePoolWithTag(Apc, POOL_TAG);
	KeSetEvent(&g_rundownApcSyncEvent, 0, FALSE);
}

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
		// Signal that APC is done
		KeSetEvent(&g_kernelApcSyncEvent, 0, FALSE);
		return;
	}

	RtlSecureZeroMemory(stackFrames, MAX_STACK_DEPTH * sizeof(PVOID));
	HANDLE threadId = PsGetCurrentThreadId();
	USHORT framesCaptured = RtlCaptureStackBackTrace(0, MAX_STACK_DEPTH, stackFrames, NULL);

	// Stack trace analysis
	for (auto i = 0; i < framesCaptured; ++i)
	{
		ULONG_PTR address = (ULONG_PTR)stackFrames[i];

		// Get name of driver corresponding to address
		PKLDR_DATA_TABLE_ENTRY driver = UkGetDriverForAddress(address);

#ifdef LOG_STACK_FRAMES
		if (driver == NULL)
		{
			LOG_MSG("  [%d] Stack frame %lu: 0x%llx // %ws\n", HandleToUlong(threadId), i, address, L"??? <------ Unbacked!");
		}
		else
		{
			auto offsetToFunction = (driver == NULL) ? address : (address - (ULONG_PTR)driver->DllBase);
			PWCHAR driverName = driver->BaseDllName.Buffer;
			LOG_MSG("  [%d] Stack frame %lu: 0x%llx+0x%llx // %ws\n", HandleToUlong(threadId), i, (ULONG_PTR)driver->DllBase, offsetToFunction, driverName);
		}
#endif

		// Check if address is from unbacked memory
		if (driver == NULL)
		{
			LOG_MSG("[APCStackWalk] -> Detected stack frame pointing to unbacked region: TID: %lu @ 0x%llx\n", HandleToUlong(threadId), address);
			LOG_MSG("  [%d] Stack frame %lu: 0x%llx // %ws\n", HandleToUlong(threadId), i, address, L"??? <------ Unbacked!");
		}
	}

	if (stackFrames) { ExFreePoolWithTag(stackFrames, POOL_TAG); }

	// Signal that APC is done
	ExFreePoolWithTag(Apc, POOL_TAG);
	KeSetEvent(&g_kernelApcSyncEvent, 0, FALSE);
}

/**
 */
VOID
UkAPCStackWalk(IN PVOID StartContext)
{
	UNREFERENCED_PARAMETER(StartContext);

	NTSTATUS NtStatus;

	KeInitializeEvent(&g_apcFinishedEvent, NotificationEvent, FALSE);
	KeInitializeEvent(&g_kernelApcSyncEvent, NotificationEvent, FALSE);
	KeInitializeEvent(&g_rundownApcSyncEvent, NotificationEvent, FALSE);

	do
	{
		LOG_MSG("Scanning running system thread call stacks via APC...\n");

		// Queue APCs to system threads. TIDs are a multiple of 4. TODO: max number?
		for (ULONG tid = 4; tid < 0xFFFF; tid += 4)
		{
			PETHREAD ThreadObj;
			PKAPC apc;

			// Get ETHREAD object for TID
			if (!NT_SUCCESS(PsLookupThreadByThreadId(UlongToHandle(tid), &ThreadObj)))
			{
				continue;
			}

			// Ignore current thread and non system threads
			if (!PsIsSystemThread(ThreadObj) || ThreadObj == KeGetCurrentThread())
			{
				ObDereferenceObject(ThreadObj);
				continue;
			}

			// Initialize APC
			apc = (PKAPC)ExAllocatePoolWithTag(
				NonPagedPool,
				sizeof(KAPC),
				POOL_TAG
			);
			KeInitializeApc(apc,
				ThreadObj,
				OriginalApcEnvironment,
				UkCaptureStackAPC,
				UkRundownAPC,
				UkNormalAPC,
				KernelMode,
				NULL
			);

			// Queue APC
			NtStatus = KeInsertQueueApc(apc, NULL, NULL, IO_NO_INCREMENT);
			if (!NT_SUCCESS(NtStatus))
			{
				LOG_MSG("KeInsertQueueApc failed\n");
				KeSetEvent(&g_kernelApcSyncEvent, 0, FALSE);
			}

			// Wait for event to signal that the apc is done before queueing the next one, at least sleep for 10 milliseconds
			UkSleepMs(10);
			KeWaitForSingleObject(&g_kernelApcSyncEvent, Executive, KernelMode, FALSE, NULL);
			KeWaitForSingleObject(&g_rundownApcSyncEvent, Executive, KernelMode, FALSE, NULL);
			KeSetEvent(&g_kernelApcSyncEvent, 0, FALSE);

			// Clean up
			if (ThreadObj) { ObDereferenceObject(ThreadObj); }
		}

		UkSleepMs(5000);

	} while (g_doAPCStackWalk);

	KeSetEvent(&g_apcFinishedEvent, 0, FALSE);
	PsTerminateSystemThread(STATUS_SUCCESS);
}