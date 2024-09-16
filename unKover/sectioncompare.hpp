#include <ntifs.h>
#include "deviceobjects.hpp"

typedef struct _IMAGE_DATA_DIRECTORY {
    ULONG   VirtualAddress;
    ULONG   Size;
} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
    USHORT      Magic;
    UCHAR       MajorLinkerVersion;
    UCHAR       MinorLinkerVersion;
    ULONG       SizeOfCode;
    ULONG       SizeOfInitializedData;
    ULONG       SizeOfUninitializedData;
    ULONG       AddressOfEntryPoint;
    ULONG       BaseOfCode;
    ULONGLONG   ImageBase;
    ULONG       SectionAlignment;
    ULONG       FileAlignment;
    USHORT      MajorOperatingSystemVersion;
    USHORT      MinorOperatingSystemVersion;
    USHORT      MajorImageVersion;
    USHORT      MinorImageVersion;
    USHORT      MajorSubsystemVersion;
    USHORT      MinorSubsystemVersion;
    ULONG       Win32VersionValue;
    ULONG       SizeOfImage;
    ULONG       SizeOfHeaders;
    ULONG       CheckSum;
    USHORT      Subsystem;
    USHORT      DllCharacteristics;
    ULONGLONG   SizeOfStackReserve;
    ULONGLONG   SizeOfStackCommit;
    ULONGLONG   SizeOfHeapReserve;
    ULONGLONG   SizeOfHeapCommit;
    ULONG       LoaderFlags;
    ULONG       NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER64, * PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_FILE_HEADER {
    USHORT  Machine;
    USHORT  NumberOfSections;
    ULONG   TimeDateStamp;
    ULONG   PointerToSymbolTable;
    ULONG   NumberOfSymbols;
    USHORT  SizeOfOptionalHeader;
    USHORT  Characteristics;
} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;

typedef struct _IMAGE_NT_HEADERS64 {
    ULONG Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, * PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_SECTION_HEADER {
    UCHAR   Name[8];
    union {
        ULONG   PhysicalAddress;
        ULONG   VirtualSize;
    } Misc;
    ULONG   VirtualAddress;
    ULONG   SizeOfRawData;
    ULONG   PointerToRawData;
    ULONG   PointerToRelocations;
    ULONG   PointerToLinenumbers;
    USHORT  NumberOfRelocations;
    USHORT  NumberOfLinenumbers;
    ULONG   Characteristics;
} IMAGE_SECTION_HEADER, * PIMAGE_SECTION_HEADER;

#define IMAGE_FIRST_SECTION( ntheader ) ((PIMAGE_SECTION_HEADER)        \
    ((ULONG_PTR)(ntheader) +                                            \
     FIELD_OFFSET( IMAGE_NT_HEADERS64, OptionalHeader ) +                 \
     ((ntheader))->FileHeader.SizeOfOptionalHeader   \
    ))

typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
    USHORT e_magic;                     // Magic number
    USHORT e_cblp;                      // Bytes on last page of file
    USHORT e_cp;                        // Pages in file
    USHORT e_crlc;                      // Relocations
    USHORT e_cparhdr;                   // Size of header in paragraphs
    USHORT e_minalloc;                  // Minimum extra paragraphs needed
    USHORT e_maxalloc;                  // Maximum extra paragraphs needed
    USHORT e_ss;                        // Initial (relative) SS value
    USHORT e_sp;                        // Initial SP value
    USHORT e_csum;                      // Checksum
    USHORT e_ip;                        // Initial IP value
    USHORT e_cs;                        // Initial (relative) CS value
    USHORT e_lfarlc;                    // File address of relocation table
    USHORT e_ovno;                      // Overlay number
    USHORT e_res[4];                    // Reserved words
    USHORT e_oemid;                     // OEM identifier (for e_oeminfo)
    USHORT e_oeminfo;                   // OEM information; e_oemid specific
    USHORT e_res2[10];                  // Reserved words
    LONG   e_lfanew;                    // File address of new exe header
} IMAGE_DOS_HEADER, * PIMAGE_DOS_HEADER;

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
        // Calculate the new string length
        USHORT newLength = windowsPrefix.Length + OriginalString->Length;

        // Allocate memory for the new string
        ResultString->Buffer = (PWCH)ExAllocatePoolWithTag(NonPagedPool, newLength, 'rvkU');
        if (ResultString->Buffer == NULL)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        // Set the lengths
        ResultString->Length = newLength;
        ResultString->MaximumLength = newLength;

        // Copy the prefix "C:\\Windows"
        RtlCopyMemory(ResultString->Buffer, windowsPrefix.Buffer, windowsPrefix.Length);

        // Copy the original string after the prefix
        RtlCopyMemory((PCHAR)ResultString->Buffer + windowsPrefix.Length, OriginalString->Buffer, OriginalString->Length);
    }
    else
    {
        // If the original string does not start with "system32", just return it as-is
        ResultString->Buffer = (PWCH)ExAllocatePoolWithTag(NonPagedPool, OriginalString->Length, 'rvkU');
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
    buffer = ExAllocatePoolWithTag(NonPagedPool, fileStandardInformation.EndOfFile.LowPart, 'rvkU');
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

VOID
UkStripDriverPrefix(
    PUNICODE_STRING InputString,
    PUNICODE_STRING OutputString
)
{
    UNICODE_STRING prefix = RTL_CONSTANT_STRING(L"\\Driver");
    if (RtlPrefixUnicodeString(&prefix, InputString, TRUE))
    {
        // Calculate the new length
        USHORT newLength = InputString->Length - prefix.Length;

        // Set the new buffer and length in the output string
        OutputString->Buffer = InputString->Buffer + (prefix.Length / sizeof(WCHAR));
        OutputString->Length = newLength;
        OutputString->MaximumLength = newLength;
    }
    else
    {
        RtlCopyUnicodeString(OutputString, InputString);
    }
}

NTSTATUS
UkGetDriverImagePath(
    _In_ PUNICODE_STRING DriverName,
    _Out_ PUNICODE_STRING ImagePath
)
{
    NTSTATUS status;
    UNICODE_STRING registryPath;
    OBJECT_ATTRIBUTES objectAttributes;
    HANDLE keyHandle = NULL;
    ULONG resultLength;
    PKEY_VALUE_PARTIAL_INFORMATION keyValueInfo;

    // construct registry path
    WCHAR registryPathBuffer[256];
    registryPath.Buffer = registryPathBuffer;
    registryPath.Length = 0;
    registryPath.MaximumLength = sizeof(registryPathBuffer);
    RtlAppendUnicodeToString(&registryPath, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services");
    RtlAppendUnicodeStringToString(&registryPath, DriverName);

    // query reg key
    InitializeObjectAttributes(&objectAttributes, &registryPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    status = ZwOpenKey(&keyHandle, KEY_READ, &objectAttributes);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("[!] Failed to open registry key: %wZ, Status: 0x%x\n", &registryPath, status);
        goto Cleanup;
    }

    ULONG keyValueInfoSize = sizeof(KEY_VALUE_PARTIAL_INFORMATION) + 256 * sizeof(WCHAR);
    keyValueInfo = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(PagedPool, keyValueInfoSize, 'rvkU');
    if (!keyValueInfo)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    UNICODE_STRING valueName;
    RtlInitUnicodeString(&valueName, L"ImagePath");
    status = ZwQueryValueKey(keyHandle, &valueName, KeyValuePartialInformation, keyValueInfo, keyValueInfoSize, &resultLength);
    if (NT_SUCCESS(status))
    {
        RtlInitUnicodeString(ImagePath, (PCWSTR)keyValueInfo->Data);
    }
    else
    {
        DbgPrint("Failed to query ImagePath value, Status: 0x%x\n", status);
        goto Cleanup;
    }

Cleanup:
    if (keyHandle) { ZwClose(keyHandle); }
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
    ULONG sectionSizeOnDisk = 0;
    ULONG sectionSize = 0;
    ULONG sectionOffset = 0;

    auto ntHeaders = (PIMAGE_NT_HEADERS)((CHAR*)peBuffer + ((PIMAGE_DOS_HEADER)peBuffer)->e_lfanew);
    if (ntHeaders == NULL)
    {
        DbgPrint("-- [!] Invalid PE header\n");
        return STATUS_INVALID_PARAMETER;
    }

    auto sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    for (ULONG i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
    {
        ULONG IMAGE_SIZEOF_SHORT_NAME = 8;
        if (strncmp((char*)sectionHeader->Name, sectionName, IMAGE_SIZEOF_SHORT_NAME) == 0)
        {
            sectionOffset = sectionHeader->PointerToRawData;
            sectionSize = sectionHeader->SizeOfRawData;
            sectionSizeOnDisk = sectionHeader->SizeOfRawData;
            break;
        }
        sectionHeader++;
    }

    if (sectionHeader == NULL)
    {
        DbgPrint("[!] Section not found\n");
        return STATUS_NOT_FOUND;
    }

    sectionBuffer = (PCHAR)ExAllocatePoolWithTag(NonPagedPool, sectionSize, 'rvkU');
    if (sectionBuffer == NULL)
    {
        DbgPrint("[!] Failed to allocate memory for section\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(sectionBuffer, (PCHAR)((ULONG_PTR)peBuffer + sectionOffset), sectionSize);
    return STATUS_SUCCESS;
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

    while (g_compareTextSections) 
    {
        // Get Handle to \Driver directory
        InitializeObjectAttributes(&attributes, &directoryName, OBJ_CASE_INSENSITIVE, NULL, NULL);
        status = ZwOpenDirectoryObject(&handle, DIRECTORY_ALL_ACCESS, &attributes);
        if (!NT_SUCCESS(status))
        {
            DbgPrint("Couldnt get \\Driver directory handle\n");
            return;
        }

        status = ObReferenceObjectByHandle(handle, DIRECTORY_ALL_ACCESS, nullptr, KernelMode, &directory, nullptr);
        if (!NT_SUCCESS(status))
        {
            ZwClose(handle);
            DbgPrint("Couldnt get \\Driver directory object from handle\n");
            return;
        }

        POBJECT_DIRECTORY directoryObject = (POBJECT_DIRECTORY)directory;
        ULONG_PTR hashBucketLock = directoryObject->Lock;

        DbgPrint("Scanning DriverObjects...\n");

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
                    // DbgPrint("[*] Checking driver: %wZ -> %wZ\n", driverServiceName, imagePath);
                }
                else
                {
                    DbgPrint("-- [!] Failed to get driver image path for %wZ, Status: 0x%x\n", driverServiceName, status);
                    goto Next;
                }

                UNICODE_STRING imagePathAbsolute;

                status = UkPrependWindowsPathIfStartsWithSystem32(&imagePath, &imagePathAbsolute);
                if (!NT_SUCCESS(status))
                {
                    DbgPrint("-- [!] Failed to construct absolute path for %wZ, Status: 0x%x\n", imagePath, status);
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
                        DbgPrint("-- [!] .TEXT SECTION DIFFERS\n");
                    }
                    else
                    {
                        // DbgPrint("-- [*] .text section matches\n");
                    }
                }
                else
                {
                    DbgPrint("-- [!] Failed to read image %wZ, Status: 0x%x\n", imagePathAbsolute, status);
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

    KeSetEvent(&g_compareTextSectionsFinishedEvent, 0, FALSE);
    PsTerminateSystemThread(STATUS_SUCCESS);
}
