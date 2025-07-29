#include <windows.h>
#include <winternl.h>
#include <stdio.h>

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
        PAGE_READWRITE
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
        printf("[-] Base Relocation needed.\n");
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
    
    IMAGE_IMPORT_DESCRIPTOR* IT = (IMAGE_IMPORT_DESCRIPTOR*)((BYTE*)base +
    ntBaseHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    int i = 0;
    while (IT->Name != 0) {
        char* dllName = (char*)((BYTE*)base + IT->Name);

        // Use FirstThunk instead of OriginalFirstThunk if OFT is zero
        DWORD thunkRVA = IT->OriginalFirstThunk ? IT->OriginalFirstThunk : IT->FirstThunk;
        PIMAGE_THUNK_DATA origThunk = (PIMAGE_THUNK_DATA)((BYTE*)base + thunkRVA);
        PIMAGE_IMPORT_BY_NAME import;
        WORD ordinal;
        while (origThunk->u1.AddressOfData != 0) {
            if (origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32) {
                ordinal = IMAGE_ORDINAL(origThunk->u1.Ordinal);
            } else {
                import = (PIMAGE_IMPORT_BY_NAME)((BYTE*)base + origThunk->u1.AddressOfData);

                // Safe guard
                if (IsBadReadPtr(import, sizeof(IMAGE_IMPORT_BY_NAME))) break;
            }
            char mName[256];
            do {
                int result = WideCharToMultiByte(
                    CP_ACP,            // Code page (CP_UTF8 for UTF-8)
                    0,                 // Flags
                    ((PLDR_DATA_TABLE_ENTRY)((BYTE*)pPeb->Ldr->InMemoryOrderModuleList.Flink->Flink - 0x10))->FullDllName.Buffer,           // Source wide string
                    -1,                // Null-terminated
                    mName,           // Destination buffer
                    sizeof(mName),   // Buffer size
                    NULL,              // Default char
                    NULL               // Used default char?
                );
                if (result > 0) {
                    printf("ANSI String: %s\n", mName);
                } else {
                    printf("Conversion failed.\n");
                }
            } while((strcmp(mName, (char*)import->Name) != 0));

            
            origThunk++;
        }
        IT++;
    }
// -------------------------------------------------------------------------------------------------------------
    // whilepPeb->Ldr->InMemoryOrderModuleList.Flink;
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

*/