#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include "deviceobjects.h"
#include "utils.hpp"

#ifdef __cplusplus
extern "C" {
#endif

VOID UkCompareTextSections(PVOID startContext);

/* globals */
extern BOOLEAN g_compareTextSections;
extern KEVENT g_compareTextSectionsFinishedEvent;

#ifdef __cplusplus
}
#endif
