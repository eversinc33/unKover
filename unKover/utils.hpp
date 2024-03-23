#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include "meta.hpp"

typedef struct _NON_PAGED_DEBUG_INFO
{
	USHORT Signature;                                                       //0x0
	USHORT Flags;                                                           //0x2
	ULONG Size;                                                             //0x4
	USHORT Machine;                                                         //0x8
	USHORT Characteristics;                                                 //0xa
	ULONG TimeDateStamp;                                                    //0xc
	ULONG CheckSum;                                                         //0x10
	ULONG SizeOfImage;                                                      //0x14
	ULONGLONG ImageBase;                                                    //0x18
} NON_PAGED_DEBUG_INFO;

typedef struct _KLDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	PVOID ExceptionTable;
	UINT32 ExceptionTableSize;
	PVOID GpValue;
	NON_PAGED_DEBUG_INFO* NonPagedDebugInfo;
	PVOID DllBase;
	PVOID EntryPoint;
	UINT32 SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	UINT32 Flags;
	UINT16 LoadCount;
	UINT16 SignatureInfo;
	PVOID SectionPointer;
	UINT32 CheckSum;
	UINT32 CoverageSectionSize;
	PVOID CoverageSection;
	PVOID LoadedImports;
	PVOID Spare;
	UINT32 SizeOfImageNotRounded;
	UINT32 TimeDateStamp;
} KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;

typedef struct _SYSTEM_MODULE_ENTRY
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} SYSTEM_MODULE_ENTRY, *PSYSTEM_MODULE_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION
{
	ULONG Count;
	SYSTEM_MODULE_ENTRY Module[0];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation,
	SystemLocksInformation,
	SystemStackTraceInformation,
	SystemPagedPoolInformation,
	SystemNonPagedPoolInformation,
	SystemHandleInformation,
	SystemObjectInformation,
	SystemPageFileInformation,
	SystemVdmInstemulInformation,
	SystemVdmBopInformation,
	SystemFileCacheInformation,
	SystemPoolTagInformation,
	SystemInterruptInformation,
	SystemDpcBehaviorInformation,
	SystemFullMemoryInformation,
	SystemLoadGdiDriverInformation,
	SystemUnloadGdiDriverInformation,
	SystemTimeAdjustmentInformation,
	SystemSummaryMemoryInformation,
	SystemNextEventIdInformation,
	SystemEventIdsInformation,
	SystemCrashDumpInformation,
	SystemExceptionInformation,
	SystemCrashDumpStateInformation,
	SystemKernelDebuggerInformation,
	SystemContextSwitchInformation,
	SystemRegistryQuotaInformation,
	SystemExtendServiceTableInformation,
	SystemPrioritySeperation,
	SystemPlugPlayBusInformation,
	SystemDockInformation,
	SystemProcessorSpeedInformation,
	SystemCurrentTimeZoneInformation,
	SystemLookasideInformation
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

EXTERN_C NTSTATUS ZwQuerySystemInformation(IN SYSTEM_INFORMATION_CLASS SystemInformationClass, OUT PVOID SystemInformation, IN ULONG SystemInformationLength, OUT PULONG ReturnLength OPTIONAL);
EXTERN_C NTSTATUS ZwQueryInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength);

/**
 * compares two wchar strings without case sensitivity
 *
 * @param s1 first string
 * @param s2 second string
 * @return INT 0 if both string are qual
 */
INT
_strcmpi_w(const wchar_t* s1, const wchar_t* s2)
{
	WCHAR c1, c2;

	if (s1 == s2)
		return 0;

	if (s1 == 0)
		return -1;

	if (s2 == 0)
		return 1;

	do {
		c1 = RtlUpcaseUnicodeChar(*s1);
		c2 = RtlUpcaseUnicodeChar(*s2);
		s1++;
		s2++;
	} while ((c1 != 0) && (c1 == c2));

	return (INT)(c1 - c2);
}

PKLDR_DATA_TABLE_ENTRY
UkGetDriverForAddress(ULONG_PTR address)
{
	if (!address)
	{
		return NULL;
	}

	PKLDR_DATA_TABLE_ENTRY entry = (PKLDR_DATA_TABLE_ENTRY)(g_drvObj)->DriverSection;

	for (auto i = 0; i < 512; ++i)
	{
		UINT64 startAddr = UINT64(entry->DllBase);
		UINT64 endAddr = startAddr + UINT64(entry->SizeOfImage);
		if (address >= startAddr && address < endAddr)
		{
			return (PKLDR_DATA_TABLE_ENTRY)entry;
		}
		entry = (PKLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink;
	}

	return NULL;
}

ULONG_PTR 
UkGetThreadStartAddress(PETHREAD ThreadObj)
{
	HANDLE hThread;
	ULONG_PTR startAddress;
	ULONG bytesReturned;

	if (ObOpenObjectByPointer(ThreadObj, OBJ_KERNEL_HANDLE, NULL, GENERIC_READ, *PsThreadType, KernelMode, &hThread) != 0)
	{
		return NULL;
	}

	if (ZwQueryInformationThread(hThread, (THREADINFOCLASS)ThreadQuerySetWin32StartAddress, &startAddress, sizeof(startAddress), &bytesReturned) != 0)
	{
		ZwClose(hThread);
		return NULL;
	}

	if (!MmIsAddressValid((PVOID)startAddress))
	{
		ZwClose(hThread);
		return NULL;
	}

	ZwClose(hThread);
	return startAddress;
}

VOID
UkSleepMs(INT milliseconds)
{
	LARGE_INTEGER interval;
	interval.QuadPart = -1 * (LONGLONG)(milliseconds * 10000);
	KeDelayExecutionThread(KernelMode, FALSE, &interval);
}