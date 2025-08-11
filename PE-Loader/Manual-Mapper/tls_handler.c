#include "pe_loader.h"

// ============================================================================
// TLS CALLBACK HANDLING
// ============================================================================

/**
 * @brief Resolves and executes TLS (Thread Local Storage) callbacks
 * @param base Base address of loaded PE image
 */
void ResolveTLS(BYTE* base) {
    if (!base) {
        printf("[!] Invalid base address for TLS processing.\n");
        return;
    }
    
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

    // Get TLS Directory RVA and size
    DWORD tlsRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    DWORD tlsSize = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size;
    
    if (tlsRVA == 0 || tlsSize == 0) {
        printf("[*] No TLS directory present.\n");
        return;
    }

    // Validate TLS directory RVA
    if (tlsRVA >= nt->OptionalHeader.SizeOfImage) {
        printf("[!] Invalid TLS directory RVA: 0x%X\n", tlsRVA);
        return;
    }

    // Get TLS directory from mapped image (RVA to pointer)
    PIMAGE_TLS_DIRECTORY64 tlsDir = (PIMAGE_TLS_DIRECTORY64)(base + tlsRVA);

    // Validate TLS directory structure
    if (IsBadReadPtr(tlsDir, sizeof(IMAGE_TLS_DIRECTORY64))) {
        printf("[!] Invalid TLS directory structure.\n");
        return;
    }

    if (tlsDir->AddressOfCallBacks == 0) {
        printf("[*] TLS directory present, but no callbacks.\n");
        return;
    }

    printf("[+] TLS Directory found:\n");
    printf("    StartAddressOfRawData: 0x%llX\n", tlsDir->StartAddressOfRawData);
    printf("    EndAddressOfRawData: 0x%llX\n", tlsDir->EndAddressOfRawData);
    printf("    AddressOfIndex: 0x%llX\n", tlsDir->AddressOfIndex);
    printf("    AddressOfCallBacks: 0x%llX\n", tlsDir->AddressOfCallBacks);
    printf("    SizeOfZeroFill: 0x%X\n", tlsDir->SizeOfZeroFill);
    printf("    Characteristics: 0x%X\n", tlsDir->Characteristics);

    // Convert AddressOfCallBacks (VA) to RVA, then to mapped pointer
    ULONG_PTR imageBaseVA = nt->OptionalHeader.ImageBase;
    ULONG_PTR imageBaseMapped = (ULONG_PTR)base;
    
    // Convert VA to RVA
    ULONG_PTR callbacksVA = tlsDir->AddressOfCallBacks;
    if (callbacksVA < imageBaseVA) {
        printf("[!] Invalid callback VA: 0x%llX < ImageBase: 0x%llX\n", callbacksVA, imageBaseVA);
        return;
    }
    
    ULONG_PTR callbacksRVA = callbacksVA - imageBaseVA;
    if (callbacksRVA >= nt->OptionalHeader.SizeOfImage) {
        printf("[!] Callback RVA out of bounds: 0x%llX\n", callbacksRVA);
        return;
    }

    // Get pointer to callback array in mapped memory
    PIMAGE_TLS_CALLBACK* callbackList = (PIMAGE_TLS_CALLBACK*)(base + callbacksRVA);

    // Validate callback list pointer
    if (IsBadReadPtr(callbackList, sizeof(PIMAGE_TLS_CALLBACK))) {
        printf("[!] Invalid TLS callback list pointer.\n");
        return;
    }

    printf("[+] Executing TLS callbacks...\n");

    int callbackCount = 0;
    const int MAX_CALLBACKS = 100; // Safety limit

    // Execute each callback
    while (callbackCount < MAX_CALLBACKS && *callbackList != NULL) {
        PIMAGE_TLS_CALLBACK callback = *callbackList;
        
        // Convert callback VA to mapped address
        ULONG_PTR callbackVA = (ULONG_PTR)callback;
        if (callbackVA < imageBaseVA) {
            printf("[!] Invalid callback VA: 0x%p\n", callback);
            break;
        }
        
        ULONG_PTR callbackRVA = callbackVA - imageBaseVA;
        if (callbackRVA >= nt->OptionalHeader.SizeOfImage) {
            printf("[!] Callback RVA out of bounds: 0x%llX\n", callbackRVA);
            break;
        }
        
        // Get actual callback function pointer in mapped memory
        PIMAGE_TLS_CALLBACK actualCallback = (PIMAGE_TLS_CALLBACK)(base + callbackRVA);
        
        printf("    [%d] TLS callback at: 0x%p (mapped: 0x%p)\n", callbackCount, callback, actualCallback);

        // Ensure the callback memory is executable
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(actualCallback, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            if (!(mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {
                DWORD oldProtect;
                SIZE_T regionSize = mbi.RegionSize;
                if (VirtualProtect(mbi.BaseAddress, regionSize, PAGE_EXECUTE_READ, &oldProtect)) {
                    printf("    [+] Set execute permission for TLS callback region.\n");
                } else {
                    printf("    [!] Failed to set execute permission. Error: %lu\n", GetLastError());
                    break;
                }
            }
        } else {
            printf("    [!] VirtualQuery failed for callback. Error: %lu\n", GetLastError());
            break;
        }

        // Execute the TLS callback
        printf("    [+] Calling TLS callback %d...\n", callbackCount);
        actualCallback((PVOID)base, DLL_PROCESS_ATTACH, NULL);
        printf("    [+] TLS callback %d completed successfully.\n", callbackCount);
        callbackList++;
        callbackCount++;
    }

    if (callbackCount >= MAX_CALLBACKS) {
        printf("[!] Warning: Maximum callback limit reached.\n");
    }
    
    printf("[+] TLS processing complete. Executed %d callbacks.\n", callbackCount);
}

/**
 * @brief Alternative TLS processing for 32-bit PE files
 * @param base Base address of loaded PE image
 */
void ResolveTLS32(BYTE* base) {
    if (!base) {
        printf("[!] Invalid base address for TLS processing.\n");
        return;
    }
    
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS32 nt = (PIMAGE_NT_HEADERS32)(base + dos->e_lfanew);
    
    DWORD tlsRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    if (tlsRVA == 0) {
        printf("[*] No TLS directory present (32-bit).\n");
        return;
    }

    PIMAGE_TLS_DIRECTORY32 tlsDir = (PIMAGE_TLS_DIRECTORY32)(base + tlsRVA);
    if (tlsDir->AddressOfCallBacks == 0) {
        printf("[*] TLS directory present, but no callbacks (32-bit).\n");
        return;
    }

    // Similar logic as 64-bit version but with 32-bit structures
    ULONG imageBaseVA = nt->OptionalHeader.ImageBase;
    ULONG callbacksRVA = tlsDir->AddressOfCallBacks - imageBaseVA;
    
    PIMAGE_TLS_CALLBACK* callbackList = (PIMAGE_TLS_CALLBACK*)(base + callbacksRVA);

    printf("[+] Executing TLS callbacks (32-bit)...\n");
    
    int callbackCount = 0;
    while (*callbackList != NULL && callbackCount < 100) {
        PIMAGE_TLS_CALLBACK callback = *callbackList;
        ULONG callbackRVA = (ULONG)callback - imageBaseVA;
        PIMAGE_TLS_CALLBACK actualCallback = (PIMAGE_TLS_CALLBACK)(base + callbackRVA);
        
        printf("    [%d] TLS callback (32-bit) at: 0x%p\n", callbackCount, actualCallback);
        
        
        actualCallback((PVOID)base, DLL_PROCESS_ATTACH, NULL);

        callbackList++;
        callbackCount++;
    }
    
    printf("[+] TLS processing complete (32-bit). Executed %d callbacks.\n", callbackCount);
}