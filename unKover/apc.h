#pragma once

#include <ntifs.h>
#include <ntddk.h>

#include "utils.h"

#ifdef __cplusplus
extern "C" {
#endif

VOID
UkAPCStackWalk(
    IN PVOID StartContext
);

typedef enum _KAPC_ENVIRONMENT {
    OriginalApcEnvironment,
    AttachedApcEnvironment,
    CurrentApcEnvironment,
    InsertApcEnvironment
} KAPC_ENVIRONMENT;

typedef VOID(*PKNORMAL_ROUTINE)(
    _In_ PVOID NormalContext,
    _In_ PVOID SystemArgument1,
    _In_ PVOID SystemArgument2
);

typedef VOID(*PKKERNEL_ROUTINE) (
    IN PKAPC Apc,
    IN OUT PKNORMAL_ROUTINE* NormalRoutine,
    IN OUT PVOID* NormalContext,
    IN OUT PVOID* SystemArgument1,
    IN OUT PVOID* SystemArgument2
);

typedef VOID(*PKRUNDOWN_ROUTINE) (
    IN  PKAPC Apc
);

EXTERN_C VOID
KeInitializeApc(
    IN  PKAPC Apc,
    IN  PKTHREAD Thread,
    IN  KAPC_ENVIRONMENT Environment,
    IN  PKKERNEL_ROUTINE KernelRoutine,
    IN  PKRUNDOWN_ROUTINE RundownRoutine OPTIONAL,
    IN  PKNORMAL_ROUTINE NormalRoutine OPTIONAL,
    IN  KPROCESSOR_MODE ApcMode OPTIONAL,
    IN  PVOID NormalContext OPTIONAL
);

EXTERN_C BOOLEAN
KeInsertQueueApc(
    IN  PKAPC Apc,
    IN  PVOID SystemArgument1,
    IN  PVOID SystemArgument2,
    IN  KPRIORITY Increment
);


extern BOOLEAN g_doAPCStackWalk;
extern KEVENT g_kernelApcSyncEvent;
extern KEVENT g_rundownApcSyncEvent;
extern KEVENT g_apcFinishedEvent;

#define MAX_STACK_DEPTH 32

#ifdef __cplusplus
}
#endif
