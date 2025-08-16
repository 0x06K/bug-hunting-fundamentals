#include "pe_loader.h"

// ============================================================================
// EXECUTION FUNCTIONS
// ============================================================================

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
    
    ((void(*)())entryPoint

}