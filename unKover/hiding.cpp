#include "hiding.h"
#include "meta.h"

BOOLEAN g_hidingDetection = TRUE;
KEVENT g_hidingDetectionFinishedEvent;

/**
 * @brief Returns the offset of ETHREAD::ThreadListEntry for the given Windows build.
 *
 * @param[IN] buildNumber Windows build number from RtlGetVersion.
 *
 * @return Offset in bytes.
 */
_IRQL_requires_same_
_IRQL_requires_(PASSIVE_LEVEL)
ULONG 
UkGetThreadListEntryOffset(
	_In_ ULONG buildNumber
)
{
	ULONG threadListEntry = 0UL;

	switch (buildNumber) 
	{
	case WIN_1507:
	case WIN_1511:
		threadListEntry = 0x690;
		break;
	case WIN_1607:
		threadListEntry = 0x698;
		break;
	case WIN_1703:
		threadListEntry = 0x6a0;
		break;
	case WIN_1709:
	case WIN_1803:
	case WIN_1809:
		threadListEntry = 0x6a8;
		break;
	case WIN_1903:
	case WIN_1909:
		threadListEntry = 0x6b8;
		break;
	case WIN_2004:
	case WIN_20H2:
	case WIN_21H1:
	case WIN_21H2:
	case WIN_22H2:
		threadListEntry = 0x4e8;
		break;
	case WIN_11_24H2:
		threadListEntry = 0x578;
		break;
	default:
		threadListEntry = 0x538;
		break;
	}

	return threadListEntry;
}

/**
 * @brief Walks the system process ETHREAD list and reports hidden threads.
 *
 * @return STATUS_SUCCESS.
 */
_IRQL_requires_same_
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS 
UkWalkSystemProcessThreads()
{
	auto currentThread = (PETHREAD)KeGetCurrentThread();
	
	//
	// Get windows build number to get correct offset
	//
	RTL_OSVERSIONINFOW osInfo = { 0 };
	osInfo.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);
	RtlGetVersion(&osInfo);

    auto threadListEntry = (PLIST_ENTRY)((ULONG_PTR)currentThread + UkGetThreadListEntryOffset(osInfo.dwBuildNumber));
    auto listEntry = threadListEntry;

    while ((listEntry = listEntry->Flink) != threadListEntry)
    {
        auto entry = (PETHREAD)((ULONG_PTR)listEntry - UkGetThreadListEntryOffset(osInfo.dwBuildNumber));
        auto threadId = (ULONG)PsGetThreadId((PETHREAD)entry);

        if (threadId != 0)
        {
            PETHREAD pThread = NULL;
            NTSTATUS status = PsLookupThreadByThreadId(ULongToHandle(threadId), &pThread);

            if (!NT_SUCCESS(status))
            {
                UkTraceEtw("PspCidTableScanner", "Found hidden thread: PID: 0x%llx", threadId);
            }
            else
            {
                ObDereferenceObject(pThread);
            }
        }
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Periodically detects threads hidden from PspCidTable.
 *
 * @param[IN] StartContext Optional start context.
 */
_IRQL_requires_same_
_IRQL_requires_(PASSIVE_LEVEL)
VOID
UkDetectHiddenThreads(
    _In_ PVOID StartContext
)
{
    UNREFERENCED_PARAMETER(StartContext);

    KeInitializeEvent(&g_hidingDetectionFinishedEvent, SynchronizationEvent, FALSE);

    do
    {
        UkTraceEtw("PspCidTableScanner", "Starting to look for hidden threads");
        UkWalkSystemProcessThreads();
        UkSleepMs(3000);

    } while (g_hidingDetection);

    KeSetEvent(&g_hidingDetectionFinishedEvent, 0, TRUE);
    PsTerminateSystemThread(STATUS_SUCCESS);
}
