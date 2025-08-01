#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdint.h>
DWORD ConvertSectionCharacteristicsToProtection(DWORD characteristics);

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

        // Optional: validate pointer
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
                callbackList++;
                i++;
            }
        }
    }
    printf("[+] TLS callbacks complete.\n");
}

void ResolveImports(BYTE* base) {
    if (!base) {
        printf("[-] Invalid base address\n");
        return;
    }

    // Validate DOS header
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)base;
    if (IsBadReadPtr(dosHeader, sizeof(IMAGE_DOS_HEADER)) || 
        dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[-] Invalid DOS header\n");
        return;
    }

    // Validate NT header offset
    if (dosHeader->e_lfanew < sizeof(IMAGE_DOS_HEADER) || 
        dosHeader->e_lfanew > 0x1000) {
        printf("[-] Invalid NT header offset\n");
        return;
    }

    // Validate NT header
    PIMAGE_NT_HEADERS64 ntHeader = (PIMAGE_NT_HEADERS64)(base + dosHeader->e_lfanew);
    if (IsBadReadPtr(ntHeader, sizeof(IMAGE_NT_HEADERS64)) || 
        ntHeader->Signature != IMAGE_NT_SIGNATURE) {
        printf("[-] Invalid NT header\n");
        return;
    }

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

    // Main import descriptor loop
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

        // Try to find module in current process first (via PEB)
        PPEB pPeb = (PPEB)__readgsqword(0x60);
        
        if (!IsBadReadPtr(pPeb, sizeof(PEB)) && pPeb && 
            !IsBadReadPtr(pPeb->Ldr, sizeof(PEB_LDR_DATA)) && pPeb->Ldr && 
            !IsBadReadPtr(&pPeb->Ldr->InMemoryOrderModuleList, sizeof(LIST_ENTRY)) &&
            pPeb->Ldr->InMemoryOrderModuleList.Flink) {
            
            PLIST_ENTRY head = &pPeb->Ldr->InMemoryOrderModuleList;
            PLIST_ENTRY current = head->Flink;
            int moduleCount = 0;
            const int MAX_MODULES = 1000;
            
            while (current && 
                   current != head && 
                   moduleCount < MAX_MODULES &&
                   !IsBadReadPtr(current, sizeof(LIST_ENTRY))) {
                
                PLDR_DATA_TABLE_ENTRY entry = (PLDR_DATA_TABLE_ENTRY)
                    ((BYTE*)current - 0x10);
                
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
                            hMod = (HMODULE)entry->DllBase;
                            found = TRUE;
                            printf("[+] Found %s already loaded at 0x%p\n", dllName, hMod);
                            break;
                        }
                    }
                }
                
                current = current->Flink;
                moduleCount++;
            }
            
            if (moduleCount >= MAX_MODULES) {
                printf("[-] Warning: Module enumeration limit reached\n");
            }
        } else {
            printf("[-] Cannot access PEB safely, falling back to LoadLibrary\n");
        }

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

        // Import thunk resolution loop
        while (thunkCount < MAX_THUNKS &&
               (BYTE*)origThunk >= base && 
               (BYTE*)origThunk < (base + imageSize) &&
               (BYTE*)firstThunk >= base && 
               (BYTE*)firstThunk < (base + imageSize) &&
               !IsBadReadPtr(origThunk, sizeof(IMAGE_THUNK_DATA)) &&
               !IsBadReadPtr(firstThunk, sizeof(IMAGE_THUNK_DATA)) &&
               origThunk->u1.AddressOfData) {

            FARPROC procAddr = NULL;
            char functionName[256] = {0};

            // Check if import is by ordinal
#ifdef _WIN64
            BOOL isOrdinal = (origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) != 0;
#else
            BOOL isOrdinal = (origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32) != 0;
#endif

            if (isOrdinal) {
                WORD ordinal = IMAGE_ORDINAL(origThunk->u1.Ordinal);
                procAddr = GetProcAddress(hMod, (LPCSTR)(uintptr_t)ordinal);
                _snprintf_s(functionName, sizeof(functionName), _TRUNCATE, "Ordinal#%d", ordinal);
            } else {
                // Validate import name RVA
                if (origThunk->u1.AddressOfData >= imageSize) {
                    printf("[-] Invalid import name RVA: 0x%llX\n", origThunk->u1.AddressOfData);
                    break;
                }

                PIMAGE_IMPORT_BY_NAME import = (PIMAGE_IMPORT_BY_NAME)(base + origThunk->u1.AddressOfData);
                
                if (IsBadReadPtr(import, sizeof(IMAGE_IMPORT_BY_NAME)) ||
                    IsBadStringPtrA(import->Name, 256)) {
                    printf("[-] Invalid import name structure\n");
                    break;
                }

                strncpy_s(functionName, sizeof(functionName), import->Name, _TRUNCATE);
                procAddr = GetProcAddress(hMod, import->Name);
            }

            if (!procAddr) {
                DWORD error = GetLastError();
                printf("[-] Failed to resolve %s from %s (Error: %d)\n", 
                       functionName, dllName, error);
            } else {
                firstThunk->u1.Function = (uintptr_t)procAddr;
                printf("[+] Resolved %s from %s -> 0x%p\n", 
                       functionName, dllName, procAddr);
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

// Function pointer typedefs for all resolved functions
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

const char* functionsToResolve[] = {
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

#define FUNCTION_COUNT (sizeof(functionsToResolve) / sizeof(functionsToResolve[0]))
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

void JumpToEntryPoint(BYTE* base) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(base + dosHeader->e_lfanew);

    DWORD entryRVA = ntHeaders->OptionalHeader.AddressOfEntryPoint;
    void* entryPoint = (void*)(base + entryRVA);

    printf("[+] Entry Point Address: 0x%p\n", entryPoint);

    // Optional: Create thread if you don't want to block
    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)entryPoint, NULL, 0, NULL);

    // Direct call (you take over execution)
    ((void(*)())entryPoint)();
}

void ApplySectionProtections(BYTE* base, pNtProtectVirtualMemory NtProtectVirtualMemory);
uint8_t* findCRTSection(uint8_t* base) {
    // Step 1: Read IMAGE_DOS_HEADER
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    // Step 2: Locate NT Headers
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    // Step 3: Access Section Headers
    IMAGE_FILE_HEADER* fileHeader = &nt->FileHeader;
    IMAGE_OPTIONAL_HEADER* optionalHeader = &nt->OptionalHeader;

    // Section headers come immediately after Optional Header
    IMAGE_SECTION_HEADER* section = (IMAGE_SECTION_HEADER*)((uint8_t*)optionalHeader + fileHeader->SizeOfOptionalHeader);

    // Step 4: Loop through sections to find .CRT
    for (int i = 0; i < fileHeader->NumberOfSections; i++) {
        if (strncmp((char*)section[i].Name, ".CRT", 8) == 0) {
            // Return pointer to the .CRT section in memory
            return base + section[i].PointerToRawData;
        }
    }

    return NULL; // Not found
}
int main(int argc, char* argv[]) {
   wchar_t widePath[MAX_PATH];
    wchar_t finalPath[MAX_PATH];

    if (argc < 2) {
        printf("Usage: %s <file_path>\n", argv[0]);
        return -1;
    } else {
        MultiByteToWideChar(CP_UTF8, 0, argv[1], -1, widePath, MAX_PATH);
        printf("[DEBUG] Converted path: %ls\n", widePath);

        swprintf(finalPath, MAX_PATH, L"\\??\\%ls", widePath);
        wprintf(L"[DEBUG] Final path: %ls\n", finalPath);  // ← FIXED HERE
    }


    // Get PEB and resolve NTDLL base
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    PLDR_DATA_TABLE_ENTRY pEntry = 
        (PLDR_DATA_TABLE_ENTRY)((BYTE*)pPeb->Ldr->InMemoryOrderModuleList.Flink->Flink - 0x10);
    PVOID ntdllBase = pEntry->DllBase;

    // Parse PE headers and get export directory
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)ntdllBase;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((BYTE*)ntdllBase + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY exportDirData = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    IMAGE_EXPORT_DIRECTORY* exportDir = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)ntdllBase + exportDirData.VirtualAddress);

    // Arrays to store resolved function addresses
    FARPROC resolvedFuncs[FUNCTION_COUNT] = {0};

    // Get export table arrays
    DWORD* nameRVAs = (DWORD*)((BYTE*)ntdllBase + exportDir->AddressOfNames);
    WORD* ordinals  = (WORD*)((BYTE*)ntdllBase + exportDir->AddressOfNameOrdinals);
    DWORD* funcRVAs = (DWORD*)((BYTE*)ntdllBase + exportDir->AddressOfFunctions);

    // Resolve all functions
    for (int i = 0; i < exportDir->NumberOfNames; i++) {
        const char* functionName = (const char*)ntdllBase + nameRVAs[i];

        for (int j = 0; j < FUNCTION_COUNT; j++) {
            if (strcmp(functionName, functionsToResolve[j]) == 0) {
                WORD ordinal = ordinals[i];
                DWORD funcRVA = funcRVAs[ordinal];
                resolvedFuncs[j] = (FARPROC)((BYTE*)ntdllBase + funcRVA);
                printf("[+] Resolved %s at 0x%p\n", functionName, resolvedFuncs[j]);
                break;
            }
        }
    }

    // === MANUAL CASTING OF RESOLVED FUNCTIONS ===
    
    // Cast each resolved function to its proper type
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

    // Verify functions were resolved
    if (!NtCreateFile || !NtReadFile || !NtClose || !NtAllocateVirtualMemory || 
        !NtQueryInformationFile || !RtlInitUnicodeString) {
        printf("[-] Failed to resolve required functions\n");
        return -1;
    }

    // === NOW USE THE CAST FUNCTIONS ===

    // Initialize UNICODE_STRING using resolved RtlInitUnicodeString
    UNICODE_STRING uPath;
    RtlInitUnicodeString(&uPath, finalPath);

    // Setup object attributes
    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(
        &objAttr,
        &uPath,
        OBJ_CASE_INSENSITIVE,
        NULL,
        NULL
    );

    // Setup IO_STATUS_BLOCK
    IO_STATUS_BLOCK ioStatus;
    HANDLE hFile;

    // Call NtCreateFile using our resolved function
    NTSTATUS status = NtCreateFile(
        &hFile,
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
        return -1;
    }
    printf("[+] File opened successfully\n");

    // Get file size using resolved NtQueryInformationFile
    FILE_STANDARD_INFORMATION fileInfo;
    IO_STATUS_BLOCK queryIoStatus;

    status = NtQueryInformationFile(
        hFile,
        &queryIoStatus,
        &fileInfo,
        sizeof(fileInfo),
        FileStandardInformation
    );

    if (status != 0) {
        printf("[-] NtQueryInformationFile failed with status: 0x%08X\n", status);
        NtClose(hFile);
        return -1;
    }

    SIZE_T fileSize = fileInfo.EndOfFile.LowPart;
    printf("[+] File size: %zu bytes\n", fileSize);

    // Allocate memory using resolved NtAllocateVirtualMemory
    PVOID fileBuffer = NULL;
    status = NtAllocateVirtualMemory(
        (HANDLE)-1,
        &fileBuffer,
        0,
        &fileSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (status != 0) {
        printf("[-] NtAllocateVirtualMemory failed with status: 0x%08X\n", status);
        return -1;
    }
    printf("[+] Allocated %zu bytes at 0x%p\n", fileSize, fileBuffer);

    // Read file using resolved NtReadFile
    IO_STATUS_BLOCK readIoStatus;
    status = NtReadFile(
        hFile,
        NULL,
        NULL,
        NULL,
        &readIoStatus,
        fileBuffer,
        (ULONG)fileSize,
        NULL,
        NULL
    );

    if (status != 0) {
        printf("[-] NtReadFile failed with status: 0x%08X\n", status);
        // Clean up using resolved NtClose
        NtClose(hFile);
        return -1;
    } else {
        printf("[+] Successfully read %lu bytes from file\n", readIoStatus.Information);
        // Display first few bytes as hex
        printf("[+] First 16 bytes: ");
        unsigned char* buffer = (unsigned char*)fileBuffer;
        for (int i = 0; i < 16 && i < fileSize; i++) {
            printf("%02X ", buffer[i]);
        }
        printf("\n");
    }
    // Clean up using resolved NtClose
    NtClose(hFile);
    printf("[+] File closed successfully\n");
    
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileBuffer;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[-] Invalid DOS signature\n");
        return -1;
    }
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((BYTE*)fileBuffer + dosHeader->e_lfanew);

    if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
        printf("[-] Invalid NT signature\n");
        return -1;
    }
    PVOID base = NULL;
    SIZE_T size = ntHeader->OptionalHeader.SizeOfImage;

    NtAllocateVirtualMemory(
        (HANDLE)-1,
        &base,
        0,
        &size,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE
    );
    SIZE_T sizeOfHeaders = ntHeader->OptionalHeader.SizeOfHeaders;
    memcpy(base, fileBuffer, sizeOfHeaders);
    IMAGE_DOS_HEADER* basedosHeader = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS* ntBaseHeader = (IMAGE_NT_HEADERS*)((BYTE*)base + dosHeader->e_lfanew);
    IMAGE_SECTION_HEADER* sectionHeader = IMAGE_FIRST_SECTION(ntBaseHeader);

    for (int i = 0; i < ntBaseHeader->FileHeader.NumberOfSections; i++, sectionHeader++)
        memcpy((BYTE*)base + sectionHeader->VirtualAddress,
       (BYTE*)fileBuffer + sectionHeader->PointerToRawData,
       sectionHeader->SizeOfRawData);
    if (ntBaseHeader->OptionalHeader.ImageBase != (DWORD_PTR)base){
        printf("[-] Base(%p) Relocation needed.\n",base);
        ptrdiff_t delta = (BYTE*)base - (BYTE*)(ntBaseHeader->OptionalHeader.ImageBase);
        DWORD relocRVA = ntBaseHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        DWORD relocSize = ntBaseHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
        IMAGE_BASE_RELOCATION* relocBase = (IMAGE_BASE_RELOCATION*)((BYTE*)base + relocRVA);
        
        while(relocSize > 0){
            printf("[+] Size of Block: %d\n",relocSize);
            WORD* relocEntries = (WORD*)((BYTE*)relocBase + 8); // Skip header
            int entryCount = (relocBase->SizeOfBlock-8)/2;
            for(DWORD i = 0; i < entryCount; i++) {
                WORD entry = relocEntries[i];  // Get the i-th entry
                WORD type = (entry >> 12) & 0xF;
                WORD offset = entry & 0xFFF;
                // we need to add base because these offsets are not relative to .reloc section but base.
                    switch(type){
                        case IMAGE_REL_BASED_ABSOLUTE: 
                            // No relocation needed
                            break;
                        case IMAGE_REL_BASED_HIGH:
                            // High 16 bits of 32-bit address
                            *(WORD*)((BYTE*)base + relocBase->VirtualAddress + offset) += HIWORD(delta);
                            break;
                        case IMAGE_REL_BASED_LOW:
                            // Low 16 bits of 32-bit address  
                            *(WORD*)((BYTE*)base + relocBase->VirtualAddress + offset) += LOWORD(delta);
                            break;
                        case IMAGE_REL_BASED_HIGHLOW:
                            // Full 32-bit address
                            *(DWORD*)((BYTE*)base + relocBase->VirtualAddress + offset) += (DWORD)delta;
                            break;
                        case IMAGE_REL_BASED_HIGHADJ:
                            // 32-bit high-adjusted
                            {
                                WORD* relocEntries = (WORD*)((BYTE*)relocBase + 8);
                                WORD highPart = *(WORD*)((BYTE*)base + relocBase->VirtualAddress + offset);
                                WORD lowPart = relocEntries[++i] & 0xFFFF;
                                DWORD fullAddr = (highPart << 16) + lowPart + (DWORD)delta;
                                *(WORD*)((BYTE*)base + relocBase->VirtualAddress + offset) = HIWORD(fullAddr);
                            }
                            break;
                        case IMAGE_REL_BASED_MIPS_JMPADDR:
                            // MIPS/ARM 32-bit
                            *(DWORD*)((BYTE*)base + relocBase->VirtualAddress + offset) += (DWORD)delta;
                            break;
                        case 6:
                            // Your observed type 6
                            *(ULONGLONG*)((BYTE*)base + relocBase->VirtualAddress + offset) += delta;
                            break;
                        case IMAGE_REL_BASED_THUMB_MOV32:
                            // ARM Thumb MOV32
                            *(DWORD*)((BYTE*)base + relocBase->VirtualAddress + offset) += (DWORD)delta;
                            break;
                        case IMAGE_REL_BASED_MIPS_JMPADDR16:
                            // MIPS16 or IA64 64-bit
                            *(ULONGLONG*)((BYTE*)base + relocBase->VirtualAddress + offset) += delta;
                            break;
                        case IMAGE_REL_BASED_DIR64:
                            // 64-bit address
                            *(ULONGLONG*)((BYTE*)base + relocBase->VirtualAddress + offset) += delta;
                            break;
                        default:
                            printf("[-] Unsupported relocation type: %d\n", type);
                            return -1;
                    }
                }
                relocSize -= relocBase->SizeOfBlock;
                if(!relocSize) break;
                relocBase = (IMAGE_BASE_RELOCATION*)((BYTE*)relocBase + relocBase->SizeOfBlock);
            }
            printf("[+] Relocations Applied.\n");
    } else {
        printf("[+] No base relocation needed.");
    }
    
// -------------------------------------------------------------------------------------------------------------
    // whilepPeb->Ldr->InMemoryOrderModuleList.Flink;
    ResolveImports((BYTE*)base);
    ApplySectionProtections((BYTE*)base, NtProtectVirtualMemory);
    ResolveTLS((BYTE*)base);
    findCRTSection((BYTE*)base);
    JumpToEntryPoint((BYTE*)base);

    return 0;

}
/*

User clicks → Explorer → ShellExecute → CreateProcess → NtCreateUserProcess →
    ↳ Object Manager opens file
    ↳ PE image mapped via section
    ↳ Kernel parses PE headers
    ↳ Thread, memory, and stack created
    ↳ Transition to user-mode stub in NTDLL
        ↳ Loads DLLs via LdrLoadDll
        ↳ Resolves imports
        ↳ Calls entry point


PE file reading → NtCreateFile() + NtReadFile() for target executable
PE header validation → DOS/NT headers and signature checks
Image memory allocation → NtAllocateVirtualMemory() at preferred base
Section mapping → Copy PE sections to virtual addresses
Import resolution → Load DLLs and resolve function addresses
Relocation processing → Fix addresses if base changed
Memory protection → NtProtectVirtualMemory() for section permissions
TLS initialization → Thread Local Storage callbacks
DLL entry points → DllMain() calls in dependency order
Thread scheduling → Add to scheduler ready queue
Context switch → Jump to executable entry point
Program execution → Your main() function runs

Result: Your program runs exactly as if Windows loaded it, but you control every step of the process.

FLow is like this {PEB} has member pointer of type PEB_LDR_DATA named
Ldr which points to -> member of PEB_LDR_DATA InMemoryOrderModuleList of
type LIST_ENTRY(circullar double linked list) that points to -> a an object
of PLDR_DATA_TABLE_ENTRY which contains the information of one module it has
a pointer (LIST_ENTRY InMemoryOrderLinks) it points to other table entries

think of it like you have a main class PEB which contains the pointer 
of clas PEB_LDR_DATA to store the addr of its object that pointer points 
to that object and now that object has a member of type LIST_ENTRY which 
is a circular doubly linked list now this list points to another data structure
named PEB_LDR_DATA_TABLE_ENTRY which contains information of one module
it has a pointer (LIST_ENTRY InMemoryOrderLinks) that points to other 
PLDR_DATA_TABLE_ENTRIES. So in simple terms flow is like this:

PEB -> PEB_LDR_DATA* -> PEB_LDR_DATA -> LIST_ENTRY(circulardoublylinkedlist).Flink*
-> PLDR_DATA_TABLE_ENTRIES

when we perform pointer airthmetic in the end it depends on pointer that how much byte it points to original
like: (BYTE*)ntdllBase + exportDirData.VirtualAddress will return a pointer to a byte. but int* ptr = &a;ptr++ will give pointer to 
integer means 4 bytes. (BYTE*)ntdllBase + 0xsomething in the end a pointer to a byte will be returned.
Here are all the remaining PE loader steps as one-line summaries:
Complete PE Loader Steps (After Imports + TLS):
*/
// 1. Base Relocations - Fix addresses if not loaded at preferred base
void ProcessRelocations(BYTE* base) { /* Parse relocation table, apply fixups for new base address */ }

// 2. Memory Protection - Set correct section permissions (RX, RW, etc.)
void SetSectionProtections(BYTE* base) { /* VirtualProtect each section with proper flags */ }

// 3. Exception Directory - Register structured exception handlers
void RegisterExceptionHandlers(BYTE* base) { /* Add function table entries for x64 SEH */ }

// 4. Security Cookie - Initialize stack canary for buffer overflow protection
void InitializeSecurityCookie(BYTE* base) { /* Set __security_cookie with random value */ }

// 5. DLL Entry Point - Call DllMain with DLL_PROCESS_ATTACH
BOOL CallDllMain(HMODULE hMod) { /* Execute entry point for module initialization */ }

// 6. Export Directory - Process exported functions (if module exports APIs)
void ProcessExports(BYTE* base) { /* Parse export table, set up function forwarding */ }

// 7. Delay Load Imports - Handle delay-loaded DLLs on first function call
void SetupDelayImports(BYTE* base) { /* Set up delay import descriptors and thunks */ }

// 8. Resource Directory - Load embedded resources (icons, strings, etc.)
void LoadResources(BYTE* base) { /* Parse resource tree, extract data */ }

// 9. Debug Directory - Process debug information and PDB loading
void ProcessDebugInfo(BYTE* base) { /* Handle debug directories, load symbols */ }

// 10. Digital Signature - Verify Authenticode signature validity
BOOL VerifySignature(BYTE* base) { /* Check certificate chain and signature */ }

// 11. Control Flow Guard - Initialize CFG if enabled
void InitializeCFG(BYTE* base) { /* Set up CFG bitmap and valid call targets */ }

// 12. Load Config - Process load configuration directory
void ProcessLoadConfig(BYTE* base) { /* Handle GFIDS, CFG, SEH settings */ }

// 13. Bound Imports - Handle pre-bound import optimization
void ProcessBoundImports(BYTE* base) { /* Check timestamps, validate bound addresses */ }

// 14. COM+ Runtime - Initialize .NET metadata if managed code
void InitializeCOMRuntime(BYTE* base) { /* Set up CLR metadata and JIT */ }

// 15. Cleanup - Free temporary allocations and handle errors
void FinalizeLoading(BYTE* base) { /* Clean up, set loaded flag, return handle */ }

void ApplySectionProtections(BYTE* base,  pNtProtectVirtualMemory NtProtectVirtualMemory) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(base + dosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeader);

    // Resolve NtProtectVirtualMemory
    // pNtProtectVirtualMemory NtProtectVirtualMemory =  (pNtProtectVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtProtectVirtualMemory");

    // if (!NtProtectVirtualMemory) {
    //     printf("[-] Failed to resolve NtProtectVirtualMemory\n");
    //     return;
    // }

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
    uint8_t* crt_section = findCRTSection(base);
    if (crt_section) {
        printf(".CRT section found at: %p\n", crt_section);
    } else {
        printf(".CRT section not found.\n");
    }

}

