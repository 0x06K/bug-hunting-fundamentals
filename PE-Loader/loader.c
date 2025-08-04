#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdint.h>

// ============================================================================
// TYPE DEFINITIONS AND FUNCTION POINTERS
// ============================================================================

typedef NTSTATUS (WINAPI *pNtCreateFile)(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength
);

typedef NTSTATUS (WINAPI *pNtReadFile)(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key
);

typedef NTSTATUS (WINAPI *pNtClose)(
    HANDLE Handle
);

typedef NTSTATUS (WINAPI *pNtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

typedef NTSTATUS (WINAPI *pNtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);

typedef NTSTATUS (WINAPI *pNtQueryInformationFile)(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass
);

typedef NTSTATUS (WINAPI *pNtFlushInstructionCache)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    SIZE_T Length
);

typedef PVOID (WINAPI *pRtlAllocateHeap)(
    PVOID HeapHandle,
    ULONG Flags,
    SIZE_T Size
);

typedef VOID (WINAPI *pRtlInitUnicodeString)(
    PUNICODE_STRING DestinationString,
    PCWSTR SourceString
);

typedef VOID (WINAPI *pRtlZeroMemory)(
    PVOID Destination,
    SIZE_T Length
);

// ============================================================================
// GLOBAL CONSTANTS AND VARIABLES
// ============================================================================

const char* g_functionsToResolve[] = {
    "NtCreateFile",
    "NtReadFile", 
    "NtClose",
    "NtAllocateVirtualMemory",
    "NtProtectVirtualMemory",
    "NtQueryInformationFile",
    "NtFlushInstructionCache",
    "RtlAllocateHeap",
    "RtlInitUnicodeString",
    "RtlZeroMemory"
};

#define FUNCTION_COUNT (sizeof(g_functionsToResolve) / sizeof(g_functionsToResolve[0]))

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Converts PE section characteristics to memory protection flags
 * @param characteristics Section characteristics from PE header
 * @return Corresponding PAGE_* protection constant
 */
DWORD ConvertSectionCharacteristicsToProtection(DWORD characteristics) {
    if (characteristics & IMAGE_SCN_MEM_EXECUTE) {
        if (characteristics & IMAGE_SCN_MEM_WRITE)
            return PAGE_EXECUTE_READWRITE;
        else if (characteristics & IMAGE_SCN_MEM_READ)
            return PAGE_EXECUTE_READ;
        else
            return PAGE_EXECUTE;
    } else {
        if (characteristics & IMAGE_SCN_MEM_WRITE)
            return PAGE_READWRITE;
        else if (characteristics & IMAGE_SCN_MEM_READ)
            return PAGE_READONLY;
        else
            return PAGE_NOACCESS;
    }
}

/**
 * @brief Finds the .CRT section in a loaded PE image
 * @param base Base address of the loaded PE image
 * @return Pointer to .CRT section or NULL if not found
 */
uint8_t* FindCRTSection(uint8_t* base) {
    // Validate DOS header
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) 
        return NULL;

    // Locate NT headers
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) 
        return NULL;

    // Access file and optional headers
    IMAGE_FILE_HEADER* fileHeader = &nt->FileHeader;
    IMAGE_OPTIONAL_HEADER* optionalHeader = &nt->OptionalHeader;

    // Section headers follow the optional header
    IMAGE_SECTION_HEADER* section = (IMAGE_SECTION_HEADER*)((uint8_t*)optionalHeader + fileHeader->SizeOfOptionalHeader);

    // Search for .CRT section
    for (int i = 0; i < fileHeader->NumberOfSections; i++) {
        if (strncmp((char*)section[i].Name, ".CRT", 8) == 0) {
            return base + section[i].PointerToRawData;
        }
    }

    return NULL; // Section not found
}

/**
 * @brief Validates PE DOS and NT headers
 * @param base Base address of PE image
 * @return TRUE if headers are valid, FALSE otherwise
 */
BOOL ValidatePEHeaders(BYTE* base) {
    // Validate DOS header
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)base;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[-] Invalid DOS signature\n");
        return FALSE;
    }

    // Validate NT header
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((BYTE*)base + dosHeader->e_lfanew);
    if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
        printf("[-] Invalid NT signature\n");
        return FALSE;
    }

    return TRUE;
}

// ============================================================================
// NTDLL FUNCTION RESOLUTION
// ============================================================================

/**
 * @brief Gets NTDLL base address from PEB
 * @return Base address of NTDLL module
 */
PVOID GetNTDLLBase() {
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    PLDR_DATA_TABLE_ENTRY pEntry = 
        (PLDR_DATA_TABLE_ENTRY)((BYTE*)pPeb->Ldr->InMemoryOrderModuleList.Flink->Flink - 0x10);
    return pEntry->DllBase;
}

/**
 * @brief Resolves NTDLL functions by parsing export table manually
 * @param resolvedFuncs Array to store resolved function addresses
 * @return TRUE if all functions resolved successfully, FALSE otherwise
 */
BOOL ResolveNTDLLFunctions(FARPROC resolvedFuncs[FUNCTION_COUNT]) {
    // Get NTDLL base address
    PVOID ntdllBase = GetNTDLLBase();

    // Parse PE headers
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)ntdllBase;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((BYTE*)ntdllBase + dos->e_lfanew);
    
    // Get export directory
    IMAGE_DATA_DIRECTORY exportDirData = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    IMAGE_EXPORT_DIRECTORY* exportDir = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)ntdllBase + exportDirData.VirtualAddress);

    // Get export table arrays
    DWORD* nameRVAs = (DWORD*)((BYTE*)ntdllBase + exportDir->AddressOfNames);
    WORD* ordinals  = (WORD*)((BYTE*)ntdllBase + exportDir->AddressOfNameOrdinals);
    DWORD* funcRVAs = (DWORD*)((BYTE*)ntdllBase + exportDir->AddressOfFunctions);

    // Initialize resolved functions array
    memset(resolvedFuncs, 0, sizeof(FARPROC) * FUNCTION_COUNT);

    // Resolve all required functions
    for (int i = 0; i < exportDir->NumberOfNames; i++) {
        const char* functionName = (const char*)ntdllBase + nameRVAs[i];

        // Check if this function is in our required list
        for (int j = 0; j < FUNCTION_COUNT; j++) {
            if (strcmp(functionName, g_functionsToResolve[j]) == 0) {
                WORD ordinal = ordinals[i];
                DWORD funcRVA = funcRVAs[ordinal];
                resolvedFuncs[j] = (FARPROC)((BYTE*)ntdllBase + funcRVA);
                printf("[+] Resolved %s at 0x%p\n", functionName, resolvedFuncs[j]);
                break;
            }
        }
    }

    // Verify all functions were resolved
    for (int i = 0; i < FUNCTION_COUNT; i++) {
        if (!resolvedFuncs[i]) {
            printf("[-] Failed to resolve %s\n", g_functionsToResolve[i]);
            return FALSE;
        }
    }

    return TRUE;
}

// ============================================================================
// FILE OPERATIONS
// ============================================================================

/**
 * @brief Prepares file path for NTDLL functions
 * @param inputPath Input file path from command line
 * @param finalPath Output buffer for formatted path
 * @return TRUE if path prepared successfully, FALSE otherwise
 */
BOOL PrepareFilePath(const char* inputPath, wchar_t* finalPath) {
    wchar_t widePath[MAX_PATH];

    // Convert to wide char
    MultiByteToWideChar(CP_UTF8, 0, inputPath, -1, widePath, MAX_PATH);
    printf("[DEBUG] Converted path: %ls\n", widePath);

    // Format for NTDLL functions
    swprintf(finalPath, MAX_PATH, L"\\??\\%ls", widePath);
    wprintf(L"[DEBUG] Final path: %ls\n", finalPath);

    return TRUE;
}

/**
 * @brief Opens file using NtCreateFile
 * @param NtCreateFile Resolved NtCreateFile function pointer
 * @param RtlInitUnicodeString Resolved RtlInitUnicodeString function pointer
 * @param filePath Path to file
 * @param hFile Output file handle
 * @return TRUE if file opened successfully, FALSE otherwise
 */
BOOL OpenFileWithNtAPI(pNtCreateFile NtCreateFile, pRtlInitUnicodeString RtlInitUnicodeString, 
                       const wchar_t* filePath, HANDLE* hFile) {
    // Initialize UNICODE_STRING
    UNICODE_STRING uPath;
    RtlInitUnicodeString(&uPath, filePath);

    // Setup object attributes
    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &uPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    // Setup IO status block
    IO_STATUS_BLOCK ioStatus;

    // Open file
    NTSTATUS status = NtCreateFile(
        hFile,
        GENERIC_READ | SYNCHRONIZE,
        &objAttr,
        &ioStatus,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );

    if (status != 0) {
        printf("[-] NtCreateFile failed with status: 0x%08X\n", status);
        return FALSE;
    }

    printf("[+] File opened successfully\n");
    return TRUE;
}

/**
 * @brief Gets file size using NtQueryInformationFile
 * @param NtQueryInformationFile Resolved function pointer
 * @param hFile File handle
 * @param fileSize Output file size
 * @return TRUE if successful, FALSE otherwise
 */
BOOL GetFileSizeNt(pNtQueryInformationFile NtQueryInformationFile, HANDLE hFile, SIZE_T* fileSize) {
    FILE_STANDARD_INFORMATION fileInfo;
    IO_STATUS_BLOCK queryIoStatus;

    NTSTATUS status = NtQueryInformationFile(
        hFile,
        &queryIoStatus,
        &fileInfo,
        sizeof(fileInfo),
        FileStandardInformation
    );

    if (status != 0) {
        printf("[-] NtQueryInformationFile failed with status: 0x%08X\n", status);
        return FALSE;
    }

    *fileSize = fileInfo.EndOfFile.LowPart;
    printf("[+] File size: %zu bytes\n", *fileSize);
    return TRUE;
}

/**
 * @brief Reads file content using NtReadFile
 * @param NtReadFile Resolved function pointer
 * @param hFile File handle
 * @param buffer Buffer to read into
 * @param fileSize Size to read
 * @return TRUE if successful, FALSE otherwise
 */
BOOL ReadFileContent(pNtReadFile NtReadFile, HANDLE hFile, PVOID buffer, SIZE_T fileSize) {
    IO_STATUS_BLOCK readIoStatus;
    
    NTSTATUS status = NtReadFile(
        hFile,
        NULL,
        NULL,
        NULL,
        &readIoStatus,
        buffer,
        (ULONG)fileSize,
        NULL,
        NULL
    );

    if (status != 0) {
        printf("[-] NtReadFile failed with status: 0x%08X\n", status);
        return FALSE;
    }

    printf("[+] Successfully read %lu bytes from file\n", readIoStatus.Information);
    
    // Display first few bytes as hex for verification
    printf("[+] First 16 bytes: ");
    unsigned char* byteBuffer = (unsigned char*)buffer;
    for (int i = 0; i < 16 && i < fileSize; i++) {
        printf("%02X ", byteBuffer[i]);
    }
    printf("\n");

    return TRUE;
}

// ============================================================================
// PE LOADING FUNCTIONS
// ============================================================================

/**
 * @brief Allocates memory for PE image and copies sections
 * @param NtAllocateVirtualMemory Resolved function pointer
 * @param fileBuffer Raw file content
 * @param base Output base address
 * @return TRUE if successful, FALSE otherwise
 */
BOOL AllocateAndMapSections(pNtAllocateVirtualMemory NtAllocateVirtualMemory, 
                           PVOID fileBuffer, PVOID* base) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileBuffer;
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((BYTE*)fileBuffer + dosHeader->e_lfanew);

    // Allocate memory for the image
    PVOID imageBase = NULL;
    SIZE_T imageSize = ntHeader->OptionalHeader.SizeOfImage;

    NTSTATUS status = NtAllocateVirtualMemory(
        (HANDLE)-1,
        &imageBase,
        0,
        &imageSize,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE
    );

    if (status != 0) {
        printf("[-] Failed to allocate memory for PE image\n");
        return FALSE;
    }

    printf("[+] Allocated %zu bytes at 0x%p for PE image\n", imageSize, imageBase);

    // Copy headers
    SIZE_T sizeOfHeaders = ntHeader->OptionalHeader.SizeOfHeaders;
    memcpy(imageBase, fileBuffer, sizeOfHeaders);

    // Copy sections
    IMAGE_NT_HEADERS* ntBaseHeader = (IMAGE_NT_HEADERS*)((BYTE*)imageBase + dosHeader->e_lfanew);
    IMAGE_SECTION_HEADER* sectionHeader = IMAGE_FIRST_SECTION(ntBaseHeader);

    for (int i = 0; i < ntBaseHeader->FileHeader.NumberOfSections; i++, sectionHeader++) {
        memcpy((BYTE*)imageBase + sectionHeader->VirtualAddress,
               (BYTE*)fileBuffer + sectionHeader->PointerToRawData,
               sectionHeader->SizeOfRawData);
        printf("[+] Copied section %s to RVA 0x%08X\n", sectionHeader->Name, sectionHeader->VirtualAddress);
    }

    *base = imageBase;
    return TRUE;
}

/**
 * @brief Processes base relocations for PE image
 * @param base Base address of loaded PE image
 * @return TRUE if successful, FALSE otherwise
 */
BOOL ProcessBaseRelocations(BYTE* base) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(base + dosHeader->e_lfanew);

    // Check if relocation is needed
    if (ntHeader->OptionalHeader.ImageBase == (DWORD_PTR)base) {
        printf("[+] No base relocation needed\n");
        return TRUE;
    }

    printf("[+] Base relocation needed (loaded at 0x%p, preferred 0x%llX)\n", 
           base, ntHeader->OptionalHeader.ImageBase);

    // Calculate delta
    ptrdiff_t delta = (BYTE*)base - (BYTE*)(ntHeader->OptionalHeader.ImageBase);
    
    // Get relocation directory
    DWORD relocRVA = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    DWORD relocSize = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    
    if (relocRVA == 0 || relocSize == 0) {
        printf("[-] No relocation data available\n");
        return FALSE;
    }

    IMAGE_BASE_RELOCATION* relocBase = (IMAGE_BASE_RELOCATION*)((BYTE*)base + relocRVA);
    
    // Process relocation blocks
    while (relocSize > 0) {
        WORD* relocEntries = (WORD*)((BYTE*)relocBase + 8); // Skip header
        int entryCount = (relocBase->SizeOfBlock - 8) / 2;
        
        printf("[+] Processing relocation block at RVA 0x%08X (%d entries)\n", 
               relocBase->VirtualAddress, entryCount);

        for (DWORD i = 0; i < entryCount; i++) {
            WORD entry = relocEntries[i];
            WORD type = (entry >> 12) & 0xF;
            WORD offset = entry & 0xFFF;
            
            BYTE* relocAddr = base + relocBase->VirtualAddress + offset;

            switch (type) {
                case IMAGE_REL_BASED_ABSOLUTE:
                    // No relocation needed
                    break;
                case IMAGE_REL_BASED_HIGH:
                    *(WORD*)relocAddr += HIWORD(delta);
                    break;
                case IMAGE_REL_BASED_LOW:
                    *(WORD*)relocAddr += LOWORD(delta);
                    break;
                case IMAGE_REL_BASED_HIGHLOW:
                    *(DWORD*)relocAddr += (DWORD)delta;
                    break;
                case IMAGE_REL_BASED_HIGHADJ:
                    {
                        WORD highPart = *(WORD*)relocAddr;
                        WORD lowPart = relocEntries[++i] & 0xFFFF;
                        DWORD fullAddr = (highPart << 16) + lowPart + (DWORD)delta;
                        *(WORD*)relocAddr = HIWORD(fullAddr);
                    }
                    break;
                case IMAGE_REL_BASED_MIPS_JMPADDR:
                    *(DWORD*)relocAddr += (DWORD)delta;
                    break;
                case 6: // Observed type 6 (likely DIR64 on some systems)
                case IMAGE_REL_BASED_DIR64:
                    *(ULONGLONG*)relocAddr += delta;
                    break;
                case IMAGE_REL_BASED_THUMB_MOV32:
                    *(DWORD*)relocAddr += (DWORD)delta;
                    break;
                case IMAGE_REL_BASED_MIPS_JMPADDR16:
                    *(ULONGLONG*)relocAddr += delta;
                    break;
                default:
                    printf("[-] Unsupported relocation type: %d\n", type);
                    return FALSE;
            }
        }
        
        relocSize -= relocBase->SizeOfBlock;
        if (!relocSize) break;
        relocBase = (IMAGE_BASE_RELOCATION*)((BYTE*)relocBase + relocBase->SizeOfBlock);
    }

    printf("[+] Base relocations applied successfully\n");
    return TRUE;
}

/**
 * @brief Finds module in PEB loader data
 * @param dllName Name of DLL to find
 * @param hMod Output module handle
 * @return TRUE if found, FALSE otherwise
 */
BOOL FindModuleInPEB(const char* dllName, HMODULE* hMod) {
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    
    // Validate PEB access
    if (!pPeb || IsBadReadPtr(pPeb, sizeof(PEB)) || 
        !pPeb->Ldr || IsBadReadPtr(pPeb->Ldr, sizeof(PEB_LDR_DATA))) {
        return FALSE;
    }

    PLIST_ENTRY head = &pPeb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY current = head->Flink;
    int moduleCount = 0;
    const int MAX_MODULES = 1000;
    
    // Walk the module list
    while (current && current != head && moduleCount < MAX_MODULES &&
           !IsBadReadPtr(current, sizeof(LIST_ENTRY))) {
        
        PLDR_DATA_TABLE_ENTRY entry = (PLDR_DATA_TABLE_ENTRY)((BYTE*)current - 0x10);
        
        if (!IsBadReadPtr(entry, sizeof(LDR_DATA_TABLE_ENTRY)) &&
            entry->FullDllName.Buffer &&
            entry->FullDllName.Length > 0 &&
            entry->FullDllName.Length < MAX_PATH * sizeof(WCHAR) &&
            !IsBadReadPtr(entry->FullDllName.Buffer, entry->FullDllName.Length)) {
            
            char modName[MAX_PATH] = {0};
            int result = WideCharToMultiByte(CP_ACP, 0, 
                                           entry->FullDllName.Buffer, 
                                           entry->FullDllName.Length / sizeof(WCHAR),
                                           modName, sizeof(modName) - 1, 
                                           NULL, NULL);
            
            if (result > 0) {
                // Extract filename from full path
                char* fileName = strrchr(modName, '\\');
                fileName = fileName ? (fileName + 1) : modName;
                
                // Case-insensitive comparison
                if (lstrcmpiA(fileName, dllName) == 0) {
                    *hMod = (HMODULE)entry->DllBase;
                    printf("[+] Found %s already loaded at 0x%p\n", dllName, *hMod);
                    return TRUE;
                }
            }
        }
        
        current = current->Flink;
        moduleCount++;
    }

    return FALSE;
}

/**
 * @brief Resolves a single function import
 * @param hMod Module handle
 * @param import Import information
 * @param isOrdinal Whether import is by ordinal
 * @param procAddr Output procedure address
 * @return TRUE if successful, FALSE otherwise
 */
BOOL ResolveSingleImport(HMODULE hMod, PIMAGE_IMPORT_BY_NAME import, BOOL isOrdinal, 
                        ULONGLONG ordinalValue, FARPROC* procAddr) {
    char functionName[256] = {0};

    if (isOrdinal) {
        WORD ordinal = IMAGE_ORDINAL(ordinalValue);
        *procAddr = GetProcAddress(hMod, (LPCSTR)(uintptr_t)ordinal);
        _snprintf_s(functionName, sizeof(functionName), _TRUNCATE, "Ordinal#%d", ordinal);
    } else {
        if (IsBadReadPtr(import, sizeof(IMAGE_IMPORT_BY_NAME)) ||
            IsBadStringPtrA(import->Name, 256)) {
            printf("[-] Invalid import name structure\n");
            return FALSE;
        }

        strncpy_s(functionName, sizeof(functionName), import->Name, _TRUNCATE);
        *procAddr = GetProcAddress(hMod, import->Name);
    }

    if (!*procAddr) {
        DWORD error = GetLastError();
        printf("[-] Failed to resolve %s (Error: %d)\n", functionName, error);
        return FALSE;
    }

    printf("[+] Resolved %s -> 0x%p\n", functionName, *procAddr);
    return TRUE;
}

/**
 * @brief Resolves imports for PE image
 * @param base Base address of loaded PE image
 */
void ResolveImports(BYTE* base) {
    if (!base) {
        printf("[-] Invalid base address\n");
        return;
    }

    // Validate PE headers
    if (!ValidatePEHeaders(base)) {
        return;
    }

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS64 ntHeader = (PIMAGE_NT_HEADERS64)(base + dosHeader->e_lfanew);

    // Get import directory info
    DWORD importDirRVA = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    DWORD importDirSize = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    DWORD imageSize = ntHeader->OptionalHeader.SizeOfImage;

    if (!importDirRVA || !importDirSize) {
        printf("[-] No Import Directory Found\n");
        return;
    }

    if (importDirRVA >= imageSize || (importDirRVA + importDirSize) > imageSize) {
        printf("[-] Invalid import directory RVA or size\n");
        return;
    }

    printf("[+] Starting import resolution...\n");
    printf("[+] Image size: 0x%X, Import dir RVA: 0x%X, Size: 0x%X\n", 
           imageSize, importDirRVA, importDirSize);

    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)(base + importDirRVA);
    DWORD maxImportDescs = importDirSize / sizeof(IMAGE_IMPORT_DESCRIPTOR);
    DWORD currentImportDesc = 0;

    // Process each import descriptor
    while (importDesc && 
           currentImportDesc < maxImportDescs &&
           (BYTE*)importDesc >= base && 
           (BYTE*)importDesc < (base + imageSize) &&
           importDesc->Name) {
        
        printf("[+] Processing import descriptor %d\n", currentImportDesc);

        // Validate DLL name RVA
        if (importDesc->Name >= imageSize) {
            printf("[-] Invalid DLL name RVA: 0x%X\n", importDesc->Name);
            importDesc++;
            currentImportDesc++;
            continue;
        }

        char* dllName = (char*)(base + importDesc->Name);
        
        // Validate DLL name string
        if (IsBadStringPtrA(dllName, MAX_PATH)) {
            printf("[-] Invalid DLL name string\n");
            importDesc++;
            currentImportDesc++;
            continue;
        }

        printf("[+] Processing DLL: %s\n", dllName);

        HMODULE hMod = NULL;
        BOOL found = FALSE;

        // Try to find module in PEB first
        found = FindModuleInPEB(dllName, &hMod);

        // If not found in PEB, try to load it
        if (!found) {
            printf("[+] Loading %s...\n", dllName);
            hMod = LoadLibraryA(dllName);
            if (!hMod) {
                DWORD error = GetLastError();
                printf("[-] Failed to load DLL: %s (Error: %d)\n", dllName, error);
                importDesc++;
                currentImportDesc++;
                continue;
            }
            printf("[+] Loaded %s at 0x%p\n", dllName, hMod);
        }

        // Resolve function imports
        DWORD origThunkRVA = importDesc->OriginalFirstThunk ? 
                            importDesc->OriginalFirstThunk : importDesc->FirstThunk;
        DWORD firstThunkRVA = importDesc->FirstThunk;

        // Validate thunk RVAs
        if (origThunkRVA >= imageSize || firstThunkRVA >= imageSize) {
            printf("[-] Invalid thunk RVAs for %s\n", dllName);
            importDesc++;
            currentImportDesc++;
            continue;
        }

        PIMAGE_THUNK_DATA origThunk = (PIMAGE_THUNK_DATA)(base + origThunkRVA);
        PIMAGE_THUNK_DATA firstThunk = (PIMAGE_THUNK_DATA)(base + firstThunkRVA);
        DWORD thunkCount = 0;
        const DWORD MAX_THUNKS = 10000;

        // Process each import thunk
        while (thunkCount < MAX_THUNKS &&
               (BYTE*)origThunk >= base && 
               (BYTE*)origThunk < (base + imageSize) &&
               (BYTE*)firstThunk >= base && 
               (BYTE*)firstThunk < (base + imageSize) &&
               !IsBadReadPtr(origThunk, sizeof(IMAGE_THUNK_DATA)) &&
               !IsBadReadPtr(firstThunk, sizeof(IMAGE_THUNK_DATA)) &&
               origThunk->u1.AddressOfData) {

            FARPROC procAddr = NULL;

            // Check if import is by ordinal
#ifdef _WIN64
            BOOL isOrdinal = (origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) != 0;
#else
            BOOL isOrdinal = (origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32) != 0;
#endif

            if (isOrdinal) {
                if (!ResolveSingleImport(hMod, NULL, TRUE, origThunk->u1.Ordinal, &procAddr)) {
                    break;
                }
            } else {
                // Validate import name RVA
                if (origThunk->u1.AddressOfData >= imageSize) {
                    printf("[-] Invalid import name RVA: 0x%llX\n", origThunk->u1.AddressOfData);
                    break;
                }

                PIMAGE_IMPORT_BY_NAME import = (PIMAGE_IMPORT_BY_NAME)(base + origThunk->u1.AddressOfData);
                if (!ResolveSingleImport(hMod, import, FALSE, 0, &procAddr)) {
                    break;
                }
            }

            // Update the import address table
            if (procAddr) {
                firstThunk->u1.Function = (uintptr_t)procAddr;
            }

            origThunk++;
            firstThunk++;
            thunkCount++;
        }

        if (thunkCount >= MAX_THUNKS) {
            printf("[-] Warning: Thunk processing limit reached for %s\n", dllName);
        }

        printf("[+] Completed processing %s (%d functions)\n", dllName, thunkCount);
        
        importDesc++;
        currentImportDesc++;
    }

    if (currentImportDesc >= maxImportDescs) {
        printf("[-] Warning: Import descriptor limit reached\n");
    }

    printf("[+] Import resolving complete. Processed %d DLLs.\n", currentImportDesc);
}

/**
 * @brief Resolves TLS (Thread Local Storage) callbacks
 * @param base Base address of loaded PE image
 */
void ResolveTLS(BYTE* base) {
    // Parse DOS and NT headers
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[!] Invalid DOS header.\n");
        return;
    }

    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        printf("[!] Invalid NT header.\n");
        return;
    }

    // Get TLS Directory RVA
    DWORD tlsRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    if (tlsRVA == 0) {
        printf("[*] No TLS directory present.\n");
        return;
    }

    // Convert RVA to pointer in mapped image
    PIMAGE_TLS_DIRECTORY64 tlsDir = (PIMAGE_TLS_DIRECTORY64)(base + tlsRVA);

    if (tlsDir->AddressOfCallBacks == 0) {
        printf("[*] TLS directory present, but no callbacks.\n");
        return;
    }

    // Convert AddressOfCallBacks (VA) to pointer in manually mapped memory
    ULONG_PTR imageBaseVA = nt->OptionalHeader.ImageBase;
    ULONG_PTR imageBaseMapped = (ULONG_PTR)base;

    ULONG_PTR rawCallbackVA = tlsDir->AddressOfCallBacks;
    PIMAGE_TLS_CALLBACK* callbackList = (PIMAGE_TLS_CALLBACK*)(
        imageBaseMapped + (rawCallbackVA - imageBaseVA)
    );

    printf("[+] Executing TLS callbacks...\n");

    int i = 0;
    while (*callbackList != NULL) {
        printf("    [%d] TLS callback at: 0x%p\n", i, *callbackList);

        // Optional: validate pointer and set execute permission
        MEMORY_BASIC_INFORMATION mbi;
        SIZE_T regionSize = 0x1000; // one page
        DWORD oldProtect;
        PVOID callbackAddr = *callbackList;

        if (VirtualQuery(callbackAddr, &mbi, sizeof(mbi))) {
            if (!(mbi.Protect & PAGE_EXECUTE)) {
                if (VirtualProtect(callbackAddr, regionSize, PAGE_EXECUTE_READ, &oldProtect)) {
                    printf("    [+] Temporarily set execute permission on TLS callback.\n");
                } else {
                    printf("    [!] Failed to set execute permission. GetLastError: %lu\n", GetLastError());
                }
            }
        }

        callbackList++;
        i++;
    }
    printf("[+] TLS callbacks complete.\n");
}

/**
 * @brief Applies proper memory protection to PE sections
 * @param base Base address of loaded PE image
 * @param NtProtectVirtualMemory Resolved function pointer
 */
void ApplySectionProtections(BYTE* base, pNtProtectVirtualMemory NtProtectVirtualMemory) {
    if (!base || !NtProtectVirtualMemory) {
        printf("[-] Invalid parameters for section protection\n");
        return;
    }

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(base + dosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeader);

    printf("[+] Applying section protections...\n");

    // Process each section
    for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++, section++) {
        PVOID sectionAddress = base + section->VirtualAddress;
        SIZE_T sectionSize = section->Misc.VirtualSize;
        DWORD newProtect = ConvertSectionCharacteristicsToProtection(section->Characteristics);
        DWORD oldProtect;

        NTSTATUS status = NtProtectVirtualMemory(
            (HANDLE)-1,
            &sectionAddress,
            &sectionSize,
            newProtect,
            &oldProtect
        );

        if (status == 0) {
            printf("[+] Protection set for section: %s -> 0x%08X\n", section->Name, newProtect);
        } else {
            printf("[-] Failed to set protection for section: %s (status: 0x%08X)\n", section->Name, status);
        }
    }

    // Find and log CRT section if present
    uint8_t* crtSection = FindCRTSection(base);
    if (crtSection) {
        printf("[+] .CRT section found at: %p\n", crtSection);
    } else {
        printf("[*] .CRT section not found\n");
    }

    printf("[+] Section protections applied successfully\n");
}

/**
 * @brief Jumps to the PE entry point to execute the loaded image
 * @param base Base address of loaded PE image
 */
void JumpToEntryPoint(BYTE* base) {
    if (!base) {
        printf("[-] Invalid base address for entry point\n");
        return;
    }

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(base + dosHeader->e_lfanew);

    DWORD entryRVA = ntHeaders->OptionalHeader.AddressOfEntryPoint;
    void* entryPoint = (void*)(base + entryRVA);

    printf("[+] Entry Point Address: 0x%p\n", entryPoint);

    // Optional: Create thread if you don't want to block current thread
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)entryPoint, NULL, 0, NULL);
    if (hThread) {
        printf("[+] Created new thread for execution\n");
        CloseHandle(hThread);
    }

    // Direct call (transfers control to loaded PE)
    printf("[+] Jumping to entry point...\n");
    ((void(*)())entryPoint)();
}

// ============================================================================
// MAIN FUNCTION
// ============================================================================

/**
 * @brief Main function - PE Loader entry point
 * @param argc Argument count
 * @param argv Argument values
 * @return Exit code
 */
int main(int argc, char* argv[]) {
    printf("[+] Manual PE Loader Starting...\n");

    // ========================================================================
    // ARGUMENT VALIDATION AND PATH PREPARATION
    // ========================================================================

    if (argc < 2) {
        printf("Usage: %s <file_path>\n", argv[0]);
        return -1;
    }

    wchar_t finalPath[MAX_PATH];
    if (!PrepareFilePath(argv[1], finalPath)) {
        printf("[-] Failed to prepare file path\n");
        return -1;
    }

    // ========================================================================
    // NTDLL FUNCTION RESOLUTION
    // ========================================================================

    printf("[+] Resolving NTDLL functions...\n");
    FARPROC resolvedFuncs[FUNCTION_COUNT] = {0};
    
    if (!ResolveNTDLLFunctions(resolvedFuncs)) {
        printf("[-] Failed to resolve required NTDLL functions\n");
        return -1;
    }

    // Cast resolved functions to proper types
    pNtCreateFile NtCreateFile = (pNtCreateFile)resolvedFuncs[0];
    pNtReadFile NtReadFile = (pNtReadFile)resolvedFuncs[1];
    pNtClose NtClose = (pNtClose)resolvedFuncs[2];
    pNtAllocateVirtualMemory NtAllocateVirtualMemory = (pNtAllocateVirtualMemory)resolvedFuncs[3];
    pNtProtectVirtualMemory NtProtectVirtualMemory = (pNtProtectVirtualMemory)resolvedFuncs[4];
    pNtQueryInformationFile NtQueryInformationFile = (pNtQueryInformationFile)resolvedFuncs[5];
    pNtFlushInstructionCache NtFlushInstructionCache = (pNtFlushInstructionCache)resolvedFuncs[6];
    pRtlAllocateHeap RtlAllocateHeap = (pRtlAllocateHeap)resolvedFuncs[7];
    pRtlInitUnicodeString RtlInitUnicodeString = (pRtlInitUnicodeString)resolvedFuncs[8];
    pRtlZeroMemory RtlZeroMemory = (pRtlZeroMemory)resolvedFuncs[9];

    // ========================================================================
    // FILE OPERATIONS
    // ========================================================================

    printf("[+] Opening target PE file...\n");
    HANDLE hFile;
    if (!OpenFileWithNtAPI(NtCreateFile, RtlInitUnicodeString, finalPath, &hFile)) {
        return -1;
    }

    // Get file size
    SIZE_T fileSize;
    if (!GetFileSizeNt(NtQueryInformationFile, hFile, &fileSize)) {
        NtClose(hFile);
        return -1;
    }

    // Allocate buffer for file content
    PVOID fileBuffer = NULL;
    SIZE_T bufferSize = fileSize;
    NTSTATUS status = NtAllocateVirtualMemory(
        (HANDLE)-1,
        &fileBuffer,
        0,
        &bufferSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (status != 0) {
        printf("[-] Failed to allocate file buffer\n");
        NtClose(hFile);
        return -1;
    }
    printf("[+] Allocated %zu bytes at 0x%p for file buffer\n", fileSize, fileBuffer);

    // Read file content
    if (!ReadFileContent(NtReadFile, hFile, fileBuffer, fileSize)) {
        NtClose(hFile);
        return -1;
    }

    // Close file handle
    NtClose(hFile);
    printf("[+] File closed successfully\n");

    // ========================================================================
    // PE VALIDATION AND LOADING
    // ========================================================================

    printf("[+] Validating PE file...\n");
    if (!ValidatePEHeaders(fileBuffer)) {
        return -1;
    }

    // Allocate memory and map PE sections
    printf("[+] Mapping PE sections...\n");
    PVOID peBase = NULL;
    if (!AllocateAndMapSections(NtAllocateVirtualMemory, fileBuffer, &peBase)) {
        return -1;
    }

    // ========================================================================
    // PE PROCESSING
    // ========================================================================

    printf("[+] Processing base relocations...\n");
    if (!ProcessBaseRelocations((BYTE*)peBase)) {
        printf("[-] Failed to process relocations\n");
        return -1;
    }

    printf("[+] Resolving imports...\n");
    ResolveImports((BYTE*)peBase);

    printf("[+] Applying section protections...\n");
    ApplySectionProtections((BYTE*)peBase, NtProtectVirtualMemory);

    printf("[+] Processing TLS callbacks...\n");
    ResolveTLS((BYTE*)peBase);

    // ========================================================================
    // EXECUTION
    // ========================================================================

    printf("[+] Starting PE execution...\n");
    JumpToEntryPoint((BYTE*)peBase);

    printf("[+] PE Loader completed successfully\n");
    return 0;
}

// ============================================================================
// ADDITIONAL HELPER FUNCTIONS (Future Extensions)
// ============================================================================

/*
 * Future PE loader enhancements that can be implemented:
 * 
 * 1. ProcessExceptionDirectory() - Register SEH handlers
 * 2. InitializeSecurityCookie() - Set stack canary
 * 3. ProcessDelayImports() - Handle delay-loaded DLLs
 * 4. LoadResources() - Extract embedded resources
 * 5. ProcessDebugInfo() - Load debug symbols
 * 6. VerifyDigitalSignature() - Check Authenticode
 * 7. InitializeCFG() - Control Flow Guard setup
 * 8. ProcessLoadConfig() - Handle load configuration
 * 9. ProcessBoundImports() - Optimize pre-bound imports
 * 10. InitializeCOMRuntime() - .NET CLR initialization
 */

/**
 * @brief Cleanup function for proper resource management
 * @param peBase Base address of loaded PE
 * @param fileBuffer File buffer to free
 */
void CleanupResources(PVOID peBase, PVOID fileBuffer) {
    if (peBase) {
        // Note: In a real implementation, you might want to keep PE loaded
        // or properly unload with VirtualFree/NtFreeVirtualMemory
        printf("[+] PE remains loaded at 0x%p\n", peBase);
    }
    
    if (fileBuffer) {
        // Note: Original code didn't free file buffer
        // Keeping same behavior as original
        printf("[+] File buffer at 0x%p (not freed - same as original)\n", fileBuffer);
    }
}