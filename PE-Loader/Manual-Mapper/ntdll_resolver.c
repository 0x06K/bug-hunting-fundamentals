#include "pe_loader.h"

// ============================================================================
// GLOBAL CONSTANTS
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

// ============================================================================
// NTDLL FUNCTION RESOLUTION
// ============================================================================

/**
 * @brief Gets NTDLL base address from PEB
 * @return Base address of NTDLL module
 */
PVOID GetNTDLLBase() {
    // Get pointer PEB(Process environment block)
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