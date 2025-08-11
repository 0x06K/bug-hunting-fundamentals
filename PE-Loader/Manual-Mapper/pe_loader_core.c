#include "pe_loader.h"

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
BOOL ProcessBaseRelocations(BYTE* base)
{
    if (!base) return FALSE;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;

    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    ULONG_PTR preferredBase = (ULONG_PTR)nt->OptionalHeader.ImageBase;
    ULONG_PTR actualBase    = (ULONG_PTR)base;

    if (preferredBase == actualBase) {
        printf("[+] No base relocation needed (loaded at preferred image base)\n");
        return TRUE;
    }

    INT64 delta = (INT64)actualBase - (INT64)preferredBase;
    printf("[+] Need relocations: preferred=0x%llx actual=0x%llx delta=0x%llx\n",
           (unsigned long long)preferredBase, (unsigned long long)actualBase, (long long)delta);

    DWORD relocRVA  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    DWORD relocSize = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    if (relocRVA == 0 || relocSize == 0) {
        printf("[-] No relocation directory found\n");
        return FALSE;
    }

    BYTE* relocBasePtr = base + relocRVA;
    BYTE* relocEnd     = relocBasePtr + relocSize;
    IMAGE_BASE_RELOCATION* block = (IMAGE_BASE_RELOCATION*)relocBasePtr;

    while ((BYTE*)block < relocEnd && block->SizeOfBlock) {
        DWORD blockVA = block->VirtualAddress;
        DWORD blockSize = block->SizeOfBlock;
        if (blockSize < sizeof(IMAGE_BASE_RELOCATION)) {
            printf("[-] Malformed relocation block (size too small)\n");
            return FALSE;
        }

        WORD* entries = (WORD*)((BYTE*)block + sizeof(IMAGE_BASE_RELOCATION));
        int entryCount = (blockSize - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        printf("[+] Reloc block: VA=0x%08X entries=%d\n", blockVA, entryCount);

        for (int i = 0; i < entryCount; ++i) {
            WORD entry = entries[i];
            WORD type = entry >> 12;
            WORD offset = entry & 0x0FFF;
            BYTE* relocAddr = base + blockVA + offset;

            // Make page writable if necessary
            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQuery(relocAddr, &mbi, sizeof(mbi))) {
                DWORD oldProt;
                BOOL changed = FALSE;
                DWORD prot = mbi.Protect & ~PAGE_GUARD; // mask out guard
                if (!(prot & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY))) {
                    // make it writable
                    if (VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_READWRITE, &oldProt)) {
                        changed = TRUE;
                    } else {
                        printf("    [!] VirtualProtect failed for %p: %lu\n", mbi.BaseAddress, GetLastError());
                    }
                }

                switch (type) {
                    case IMAGE_REL_BASED_ABSOLUTE:
                        // no-op
                        break;
                    case IMAGE_REL_BASED_HIGH:
                    {
                        WORD orig = *(WORD*)relocAddr;
                        WORD newv = (WORD)(orig + HIWORD((LONG_PTR)delta));
                        *(WORD*)relocAddr = newv;
                    }
                    break;
                    case IMAGE_REL_BASED_LOW:
                    {
                        WORD orig = *(WORD*)relocAddr;
                        WORD newv = (WORD)(orig + LOWORD((LONG_PTR)delta));
                        *(WORD*)relocAddr = newv;
                    }
                    break;
                    case IMAGE_REL_BASED_HIGHLOW:
                    {
                        DWORD orig = *(DWORD*)relocAddr;
                        *(DWORD*)relocAddr = (DWORD)(orig + (DWORD)delta);
                    }
                    break;
                    case IMAGE_REL_BASED_DIR64:
                    {
                        unsigned long long orig = *(unsigned long long*)relocAddr;
                        *(unsigned long long*)relocAddr = (unsigned long long)(orig + (unsigned long long)delta);
                    }
                    break;
                    case IMAGE_REL_BASED_HIGHADJ:
                        // complex legacy x86 case; not implemented here
                        printf("    [!] HIGHADJ relocation encountered - unsupported in this implementation\n");
                        break;
                    default:
                        printf("    [!] Unsupported relocation type: %u\n", type);
                        break;
                }

                // restore old protection if we changed it
                if (changed) {
                    DWORD discard;
                    VirtualProtect(mbi.BaseAddress, mbi.RegionSize, oldProt, &discard);
                }
            } else {
                printf("    [!] VirtualQuery failed for %p (GetLastError=%lu)\n", relocAddr, GetLastError());
            }
        }

        // move to next block
        block = (IMAGE_BASE_RELOCATION*)((BYTE*)block + block->SizeOfBlock);
    }

    printf("[+] Relocations applied\n");
    return TRUE;
}

// ============================================================================
// IMPORT RESOLUTION HELPER FUNCTIONS
// ============================================================================

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
 * @param ordinalValue Ordinal value if import is by ordinal
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

    printf("[+] Section protections applied successfully\n");
}