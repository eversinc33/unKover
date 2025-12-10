#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include <TraceLoggingProvider.h>

//
// Pool tag and logging macros
//
#define POOL_TAG 'rvkU'
#define DRIVER_LOG_PREFIX "[unKover] :: "
#define DRIVER_DBG_PREFIX "          :: "
#define LOG_DBG(x, ...) DbgPrint((DRIVER_DBG_PREFIX x), __VA_ARGS__)

//
// Windows build numbers
//
constexpr ULONG64 WIN_1507 = 10240;
constexpr ULONG64 WIN_1511 = 10586;
constexpr ULONG64 WIN_1607 = 14393;
constexpr ULONG64 WIN_1703 = 15063;
constexpr ULONG64 WIN_1709 = 16299;
constexpr ULONG64 WIN_1803 = 17134;
constexpr ULONG64 WIN_1809 = 17763;
constexpr ULONG64 WIN_1903 = 18362;
constexpr ULONG64 WIN_1909 = 18363;
constexpr ULONG64 WIN_2004 = 19041;
constexpr ULONG64 WIN_20H2 = 19042;
constexpr ULONG64 WIN_21H1 = 19043;
constexpr ULONG64 WIN_21H2 = 19044;
constexpr ULONG64 WIN_22H2 = 19045;
constexpr ULONG64 WIN_11_21H2 = 22000;
constexpr ULONG64 WIN_11_22H2 = 22621;
constexpr ULONG64 WIN_11_23H2 = 22631;
constexpr ULONG64 WIN_11_24H2 = 26100;

//
// Declare TraceLogging provider handle for other translation units
//
TRACELOGGING_DECLARE_PROVIDER(g_hTraceProvider);

#ifdef __cplusplus
extern "C" {
#endif

//
// Global driver object pointer.
//
extern PDRIVER_OBJECT g_drvObj;


void
UkTraceEtw(
    _In_ PCSTR Type,
    _In_ PCSTR Format,
    ...
);

#ifdef __cplusplus
}
#endif
