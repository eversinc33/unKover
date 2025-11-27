#pragma once

#include <ntifs.h>
#include <ntddk.h>

#ifdef __cplusplus
extern "C" {
#endif

/* thread handles started by DriverEntry */
extern HANDLE g_hScanSystemThreads;
extern HANDLE g_hSendNmis;
extern HANDLE g_hCheckDriverObjects;
extern HANDLE g_hAPCCheck;
extern HANDLE g_hTextSectionCompare;
extern HANDLE g_hHidingDetection;

NTSTATUS DriverEntry(PDRIVER_OBJECT drvObj, PUNICODE_STRING regPath);
VOID DriverUnload(PDRIVER_OBJECT drvObj);

#ifdef __cplusplus
}
#endif
