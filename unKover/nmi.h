#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include "meta.h"
#include "utils.h"

#define STACK_CAPTURE_SIZE 32

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _NMI_CONTEXT
{
    ULONG threadId;
    INT numFired;
    USHORT framesCaptured;
    ULONG_PTR stackFrames[STACK_CAPTURE_SIZE];
} NMI_CONTEXT, *PNMI_CONTEXT;

typedef struct _KAFFINITY_EX
{
    USHORT Count;
    USHORT Size;
    ULONG Reserved;
    ULONGLONG Bitmap[20];
} KAFFINITY_EX, *PKAFFINITY_EX;

EXTERN_C VOID KeInitializeAffinityEx(PKAFFINITY_EX affinity);
EXTERN_C VOID KeAddProcessorAffinityEx(PKAFFINITY_EX affinity, INT num);
EXTERN_C VOID HalSendNMI(PKAFFINITY_EX affinity);

BOOLEAN
UkRegisterNmiCallbacks(
    VOID
);

VOID
UkUnloadNMI(
    VOID
);

VOID
UkSendNMI(
    _In_ PVOID StartContext
);

VOID
UkAnalyzeNmiData(
    VOID
);

BOOLEAN
UkNmiCallback(
    _In_ PVOID context,
    _In_ BOOLEAN handled
);

/* globals */
extern ULONG g_numCores;
extern PVOID g_NmiCallbackHandle;
extern PKAFFINITY_EX g_NmiAffinity;
extern PNMI_CONTEXT g_NmiContext;
extern HANDLE SendNMIThreadHandle;
extern BOOLEAN g_sendNmis;
extern KEVENT g_sendNmisFinishedEvent;

#ifdef __cplusplus
}
#endif
