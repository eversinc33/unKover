#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include "utils.h"

#ifdef __cplusplus
extern "C" {
#endif

ULONG
UkGetThreadListEntryOffset(
    ULONG buildNumber
);

NTSTATUS
UkWalkSystemProcessThreads(
    VOID
);

VOID
UkDetectHiddenThreads(
    IN PVOID StartContext
);

/* globals */
extern BOOLEAN g_hidingDetection;
extern KEVENT g_hidingDetectionFinishedEvent;

#ifdef __cplusplus
}
#endif
