#include "pe_loader.h"

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

    // ========================================================================
    // ARGUMENT VALIDATION AND PATH PREPARATION
    // ========================================================================

    if (argc < 2) {
        printf("Usage: %s <file_path>\n", argv[0]);
        return -1;
    }
    printf("[+] Manual PE Loader Starting...\n");
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
    
    printf("[+] Calling CRT initializers...\n");
    CallCRTInitializers((BYTE*)peBase);
    
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