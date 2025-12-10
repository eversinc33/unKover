#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include "deviceobjects.h"
#include "utils.h"

#ifdef __cplusplus
extern "C" {
#endif

VOID
UkCompareTextSections(
    IN PVOID StartContext
);

/* globals */
extern BOOLEAN g_compareTextSections;
extern KEVENT g_compareTextSectionsFinishedEvent;

#ifdef __cplusplus
}
#endif
