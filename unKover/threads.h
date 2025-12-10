#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include "utils.h"

#ifdef __cplusplus
extern "C" {
#endif


VOID
UkScanSystemThreads(
    IN PVOID StartContext
);

//
// globals
//
extern BOOLEAN g_scanSystemThreads;
extern KEVENT g_scanSystemThreadsFinishedEvent;

#ifdef __cplusplus
}
#endif
