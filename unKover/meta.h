#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include <TraceLoggingProvider.h>

#define POOL_TAG 'rvkU'
#define DRIVER_LOG_PREFIX "[unKover] :: "
#define DRIVER_DBG_PREFIX "          :: "
#define LOG_DBG(x, ...) DbgPrint((DRIVER_DBG_PREFIX x), __VA_ARGS__)

// Declare TraceLogging provider handle for other translation units
TRACELOGGING_DECLARE_PROVIDER(g_hTraceProvider);

#ifdef __cplusplus
extern "C" {
#endif

/* global driver object */
extern PDRIVER_OBJECT g_drvObj;

/* ETW-style trace helper: type (ASCII) and printf-style message */
void UkTraceEtw(_In_ PCSTR Type, _In_ PCSTR Format, ...);

#ifdef __cplusplus
}
#endif
