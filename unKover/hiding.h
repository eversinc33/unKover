#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include "utils.hpp"

#ifdef __cplusplus
extern "C" {
#endif

VOID UkDetectHiddenThreads(IN PVOID StartContext);

/* globals */
extern BOOLEAN g_hidingDetection;
extern KEVENT g_hidingDetectionFinishedEvent;

#ifdef __cplusplus
}
#endif
