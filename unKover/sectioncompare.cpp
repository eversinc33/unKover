#include <ntifs.h>
#include <ntddk.h>
#include <ntimage.h>
#include <string.h>

#include "sectioncompare.h"
#include "meta.h"

BOOLEAN g_compareTextSections = TRUE;
KEVENT g_compareTextSectionsFinishedEvent;

NTSTATUS
UkPrependWindowsPathIfStartsWithSystem32(
    PUNICODE_STRING OriginalString,
    PUNICODE_STRING ResultString
)
{
    UNICODE_STRING system32 = RTL_CONSTANT_STRING(L"System32");
    UNICODE_STRING windowsPrefix;
    RtlInitUnicodeString(&windowsPrefix, L"\\SystemRoot\\");

    BOOLEAN startsWithSystem32 = RtlPrefixUnicodeString(&system32, OriginalString, TRUE);

    if (startsWithSystem32)
    {
        USHORT newLength = windowsPrefix.Length + OriginalString->Length;

        ResultString->Buffer = (PWCH)ExAllocatePoolWithTag(NonPagedPool, newLength, POOL_TAG);
        if (ResultString->Buffer == NULL)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        ResultString->Length = newLength;
        ResultString->MaximumLength = newLength;

        RtlCopyMemory(ResultString->Buffer, windowsPrefix.Buffer, windowsPrefix.Length);
        RtlCopyMemory((PCHAR)ResultString->Buffer + windowsPrefix.Length, OriginalString->Buffer, OriginalString->Length);
    }
    else
    {
        ResultString->Buffer = (PWCH)ExAllocatePoolWithTag(NonPagedPool, OriginalString->Length, POOL_TAG);
        if (ResultString->Buffer == NULL)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        ResultString->Length = OriginalString->Length;
        ResultString->MaximumLength = OriginalString->Length;

        RtlCopyMemory(ResultString->Buffer, OriginalString->Buffer, OriginalString->Length);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
UkReadFileToMemory(
    PUNICODE_STRING FileName,
    PVOID* FileBuffer,
    ULONG* FileSize
)
{
    NTSTATUS status;
    HANDLE fileHandle = NULL;
    IO_STATUS_BLOCK ioStatusBlock;
    OBJECT_ATTRIBUTES objectAttributes;
    FILE_STANDARD_INFORMATION fileStandardInformation;
    PVOID buffer = NULL;

    InitializeObjectAttributes(&objectAttributes, FileName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = ZwCreateFile(
        &fileHandle,
        GENERIC_READ,
        &objectAttributes,
        &ioStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );

    if (!NT_SUCCESS(status))
    {
        goto Cleanup;
    }

    // get file size
    status = ZwQueryInformationFile(fileHandle, &ioStatusBlock, &fileStandardInformation, sizeof(fileStandardInformation), FileStandardInformation);
    if (!NT_SUCCESS(status))
    {
        goto Cleanup;
    }

    // allocate memory
    buffer = ExAllocatePoolWithTag(NonPagedPool, fileStandardInformation.EndOfFile.LowPart, POOL_TAG);
    if (buffer == NULL)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    status = ZwReadFile(fileHandle, NULL, NULL, NULL, &ioStatusBlock, buffer, fileStandardInformation.EndOfFile.LowPart, NULL, NULL);
    if (!NT_SUCCESS(status))
    {
        goto Cleanup;
    }

    *FileBuffer = buffer;
    *FileSize = fileStandardInformation.EndOfFile.LowPart;
    if (fileHandle) { ZwClose(fileHandle); }
    // do not free the buffer yet
    return status;

Cleanup:
    if (buffer) { ExFreePool(buffer); }
    if (fileHandle) { ZwClose(fileHandle); }
    return status;
}

NTSTATUS
UkGetPeSection(
    IN PCHAR sectionName,
    IN PVOID peBuffer,
    OUT PCHAR sectionBuffer,
    OUT PULONG size
)
{
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)peBuffer;
    if (!dosHeader)
    {
        UkTraceEtw("TextSectionComparer", "-- [!] Invalid PE header");
        return STATUS_INVALID_PARAMETER;
    }

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((CHAR*)peBuffer + dosHeader->e_lfanew);
    if (ntHeaders == NULL)
    {
        UkTraceEtw("TextSectionComparer", "-- [!] Invalid PE header");
        return STATUS_INVALID_PARAMETER;
    }

    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    for (ULONG i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
    {
        if (strncmp((char*)sectionHeader->Name, sectionName, IMAGE_SIZEOF_SHORT_NAME) == 0)
        {
            ULONG sectionOffset = sectionHeader->PointerToRawData;
            ULONG sectionSize = sectionHeader->SizeOfRawData;

            sectionBuffer = (PCHAR)ExAllocatePoolWithTag(NonPagedPool, sectionSize, POOL_TAG);
            if (sectionBuffer == NULL)
            {
                UkTraceEtw("TextSectionComparer", "[!] Failed to allocate memory for section");
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            RtlCopyMemory(sectionBuffer, (PCHAR)((ULONG_PTR)peBuffer + sectionOffset), sectionSize);
            if (size) *size = sectionSize;
            return STATUS_SUCCESS;
        }
        sectionHeader++;
    }

    UkTraceEtw("TextSectionComparer", "[!] Section not found");
    return STATUS_NOT_FOUND;
}

VOID
UkCompareTextSections(PVOID startContext)
{
    UNREFERENCED_PARAMETER(startContext);
    NTSTATUS status;
    PVOID directory;
    HANDLE handle;
    OBJECT_ATTRIBUTES attributes;
    UNICODE_STRING directoryName = RTL_CONSTANT_STRING(L"\\Driver");

    KeInitializeEvent(&g_compareTextSectionsFinishedEvent, NotificationEvent, FALSE);

    while (g_compareTextSections) 
    {
        // Get Handle to \\Driver directory
        InitializeObjectAttributes(&attributes, &directoryName, OBJ_CASE_INSENSITIVE, NULL, NULL);
        status = ZwOpenDirectoryObject(&handle, DIRECTORY_ALL_ACCESS, &attributes);
        if (!NT_SUCCESS(status))
        {
            LOG_DBG("Couldnt get \\Driver directory handle");
            return;
        }

        status = ObReferenceObjectByHandle(handle, DIRECTORY_ALL_ACCESS, nullptr, KernelMode, &directory, nullptr);
        if (!NT_SUCCESS(status))
        {
            ZwClose(handle);
            LOG_DBG("Couldnt get \\Driver directory object from handle");
            return;
        }

        POBJECT_DIRECTORY directoryObject = (POBJECT_DIRECTORY)directory;
        ULONG_PTR hashBucketLock = directoryObject->Lock;

        UkTraceEtw("TextSectionComparer", "Scanning DriverObjects...");

        // Lock for the hashbucket
        KeEnterCriticalRegion();
        ExAcquirePushLockExclusiveEx(&hashBucketLock, 0);

        for (POBJECT_DIRECTORY_ENTRY entry : directoryObject->HashBuckets)
        {
            if (!entry)
            {
                continue;
            }

            while (entry != nullptr && entry->Object)
            {
                PVOID fileBuffer = NULL;
                PCHAR textSectionOnDiskBuffer = NULL;
                PCHAR textSectionInMemBuffer = NULL;
                ULONG sectionSizeOnDisk = 0;
                ULONG sectionSizeInMem = 0;

                PDRIVER_OBJECT driver = (PDRIVER_OBJECT)entry->Object;

                UNICODE_STRING imagePath;
                WCHAR imagePathBuffer[256];
                imagePath.Buffer = imagePathBuffer;
                imagePath.Length = 0;
                imagePath.MaximumLength = sizeof(imagePathBuffer);

                UNICODE_STRING driverServiceName;
                WCHAR serviceNameBuffer[256];
                driverServiceName.Buffer = serviceNameBuffer;
                driverServiceName.Length = 0;
                driverServiceName.MaximumLength = sizeof(serviceNameBuffer);

                // Get driver service name to lookup path to binary
                UkStripDriverPrefix(&driver->DriverName, &driverServiceName);

                // get the image path
                NTSTATUS status = UkGetDriverImagePath(&driverServiceName, &imagePath);
                if (NT_SUCCESS(status))
                {
                    // LOG_MSG("[*] Checking driver: %wZ -> %wZ\n", driverServiceName, imagePath);
                }
                else
                {
                    //LOG_MSG("-- [!] Failed to get driver image path for %wZ, Status: 0x%x\n", driverServiceName, status);
                    goto Next;
                }

                UNICODE_STRING imagePathAbsolute;

                status = UkPrependWindowsPathIfStartsWithSystem32(&imagePath, &imagePathAbsolute);
                if (!NT_SUCCESS(status))
                {
                    //LOG_MSG("-- [!] Failed to construct absolute path for %wZ, Status: 0x%x\n", imagePath, status);
                    goto Next;
                }

                // read the image and compare it to the in memory image
                ULONG fileSize = 0;
                status = UkReadFileToMemory(&imagePathAbsolute, &fileBuffer, &fileSize);
                if (NT_SUCCESS(status))
                {
                    // compare .text sections
                    if (!NT_SUCCESS(UkGetPeSection(".text", fileBuffer, textSectionOnDiskBuffer, &sectionSizeOnDisk))
                        || !NT_SUCCESS(UkGetPeSection(".text", driver->DriverStart, textSectionInMemBuffer, &sectionSizeInMem))
                        || !textSectionOnDiskBuffer || !textSectionInMemBuffer)
                    {
                        goto Next;
                    }

                    if (RtlCompareMemory(textSectionOnDiskBuffer, textSectionInMemBuffer, sectionSizeOnDisk) != sectionSizeOnDisk)
                    {
                        UkTraceEtw("TextSectionComparer", " .TEXT section differs %wZ", imagePath);
                    }
                    else
                    {
                        // LOG_MSG("-- [*] .text section matches\n");
                    }
                }
                else
                {
                    LOG_DBG("Failed to read image %wZ, Status: 0x%x", imagePathAbsolute, status);
                    goto Next;
                }

            Next:
                if (fileBuffer)
                {
                    ExFreePool(fileBuffer);
                }
                if (textSectionOnDiskBuffer)
                {
                    ExFreePool(textSectionOnDiskBuffer);
                }
                if (textSectionInMemBuffer)
                {
                    ExFreePool(textSectionInMemBuffer);
                }
                entry = entry->ChainLink;
            }
        }

        ExReleasePushLockExclusiveEx(&hashBucketLock, 0);
        KeLeaveCriticalRegion();

        ObDereferenceObject(directory);
        ZwClose(handle);

        UkSleepMs(5000);

    } while (g_compareTextSections);

    KeSetEvent(&g_compareTextSectionsFinishedEvent, 0, TRUE);
    KeWaitForSingleObject(&g_compareTextSectionsFinishedEvent, Executive, KernelMode, FALSE, NULL);
    PsTerminateSystemThread(STATUS_SUCCESS);
}


