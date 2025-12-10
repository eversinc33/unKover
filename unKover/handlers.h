#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include "utils.h"

#ifdef __cplusplus
extern "C" {
#endif

_IRQL_requires_same_
_IRQL_requires_(PASSIVE_LEVEL)
VOID
UkCheckHandlers(
    _In_ PVOID StartContext
);

/* globals */
extern BOOLEAN g_checkHandlers;
extern KEVENT g_checkHandlersFinishedEvent;

#ifdef __cplusplus
}
#endif
