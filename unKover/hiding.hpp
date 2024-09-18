#pragma once

#include <ntddk.h>
#include "utils.hpp"

typedef NTSTATUS(NTAPI* ZWGETNEXTTHREAD)(_In_ HANDLE ProcessHandle, _In_ HANDLE ThreadHandle, _In_ ACCESS_MASK DesiredAccess, _In_ ULONG HandleAttributes, _In_ ULONG Flags, _Out_ PHANDLE NewThreadHandle);
ZWGETNEXTTHREAD pZwGetNextThread;
BOOLEAN g_hidingDetection = TRUE;
KEVENT g_hidingDetectionFinishedEvent;

// KTHREAD->ThreadListEntry FIXME hardcoded
#define THREAD_LIST_ENTRY_OFFSET 0x2f8
typedef struct _myKTHREAD
{
    char padding[0x2F8];                // 0x0000
    struct _LIST_ENTRY ThreadListEntry; // 0x02F8 
    // [ ... ]
} myKTHREAD, * myPKTHREAD;

NTSTATUS 
UkWalkSystemProcessThreads()
{
    
    auto currentThread = KeGetCurrentThread();
    auto threadListEntry = (PLIST_ENTRY)((ULONG_PTR)currentThread + THREAD_LIST_ENTRY_OFFSET);
    auto listEntry = threadListEntry;

    while ((listEntry = listEntry->Flink) != threadListEntry)
    {
        auto entry = CONTAINING_RECORD(listEntry, myKTHREAD, ThreadListEntry);
        auto threadId = (ULONG)PsGetThreadId((PETHREAD)entry);

        if (threadId != 0)
        {
            PETHREAD pThread = NULL;
            NTSTATUS status = PsLookupThreadByThreadId(ULongToHandle(threadId), &pThread);

            if (!NT_SUCCESS(status))
            {
                LOG_MSG("Found hidden thread: PID: 0x%llx\n", threadId);
            }
        }
    }

    return STATUS_SUCCESS;
}

/**
 * Scans for threads hidden from the PspCidTable
 */
VOID
UkDetectHiddenThreads(IN PVOID StartContext)
{
	UNREFERENCED_PARAMETER(StartContext);

    UNICODE_STRING usZwGetNextThread = RTL_CONSTANT_STRING(L"ZwGetNextThread");
    pZwGetNextThread = (ZWGETNEXTTHREAD)MmGetSystemRoutineAddress(&usZwGetNextThread);
    if (!pZwGetNextThread)
    {
        LOG_MSG("Failed to resolve ZwGetNextThread!\n");
        g_hidingDetection = FALSE;
        KeSetEvent(&g_hidingDetectionFinishedEvent, 0, FALSE);
        PsTerminateSystemThread(STATUS_SUCCESS);
        return;
    }

	KeInitializeEvent(&g_hidingDetectionFinishedEvent, NotificationEvent, FALSE);

	do
	{
        LOG_MSG("Starting to look for hidden threads\n");
        UkWalkSystemProcessThreads();
		UkSleepMs(3000);

	} while (g_hidingDetection);

	KeSetEvent(&g_hidingDetectionFinishedEvent, 0, FALSE);
	PsTerminateSystemThread(STATUS_SUCCESS);
}