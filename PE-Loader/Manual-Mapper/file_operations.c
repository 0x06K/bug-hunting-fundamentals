#include "pe_loader.h"

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