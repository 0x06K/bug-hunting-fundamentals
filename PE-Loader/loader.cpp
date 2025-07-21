#include <windows.h>
#include <stdio.h>
using namespace std;

BYTE* LoadFileToMemory(const char* filePath, DWORD* outSize) {
    HANDLE hFile = CreateFileA(filePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to open file: %s\n", filePath);
        return NULL;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE || fileSize == 0) {
        printf("[-] Invalid file size.\n");
        CloseHandle(hFile);
        return NULL;
    }

    BYTE* buffer = (BYTE*)malloc(fileSize);
    if (!buffer) {
        printf("[-] Memory allocation failed.\n");
        CloseHandle(hFile);
        return NULL;
    }

    DWORD bytesRead = 0;
    if (!ReadFile(hFile, buffer, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        printf("[-] Failed to read the full file.\n");
        free(buffer);
        CloseHandle(hFile);
        return NULL;
    }

    CloseHandle(hFile);
    *outSize = fileSize;
    return buffer;
}

int main(int argc, char* argv[]) {
    
    if (argc != 2) {
        printf("Usage: %s <target.exe>\n", argv[0]);
        return 1;
    }
    
    DWORD fileSize = 0;
    BYTE* peBuffer = LoadFileToMemory(argv[1], &fileSize);
    
    if (!peBuffer) {
        printf("[-] Could not load file into memory.\n");
        return -1;
    }

    printf("[+] PE file loaded. Size: %lu bytes\n", fileSize);

    // 🔜 Next step: parse headers
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)peBuffer;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[-] Invalid DOS signature.\n");
        return -1;
    }

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(peBuffer + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        printf("[-] Invalid NT signature.\n");
        return -1;
    }

    printf("[+] Valid PE file. Entry point RVA: 0x%X\n", ntHeaders->OptionalHeader.AddressOfEntryPoint);
    LPVOID imageBase = VirtualAlloc(
        (LPVOID)ntHeaders->OptionalHeader.ImageBase,
        ntHeaders->OptionalHeader.SizeOfImage,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_EXECUTE_READWRITE
    );

    if (!imageBase) {
        // If preferred base is taken, allocate anywhere
        imageBase = VirtualAlloc(
            NULL,
            ntHeaders->OptionalHeader.SizeOfImage,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_EXECUTE_READWRITE
        );

        if (!imageBase) {
            printf("[-] Memory allocation failed.\n");
            return -1;
        }
    }
    // Copy headers
    memcpy(imageBase, peBuffer, ntHeaders->OptionalHeader.SizeOfHeaders);

    // Copy sections
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, section++) {
        LPVOID dest = (LPVOID)((DWORD_PTR)imageBase + section->VirtualAddress);
        LPVOID src  = (LPVOID)(peBuffer + section->PointerToRawData);
        memcpy(dest, src, section->SizeOfRawData);
    }
    DWORD_PTR delta = (DWORD_PTR)imageBase - ntHeaders->OptionalHeader.ImageBase;

    if (delta != 0 && ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > 0) {
        PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)imageBase +
            ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

        DWORD relocSize = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
        DWORD bytesProcessed = 0;

        while (bytesProcessed < relocSize && reloc->SizeOfBlock > 0) {
            DWORD relocCount = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD* relocData = (WORD*)((DWORD_PTR)reloc + sizeof(IMAGE_BASE_RELOCATION));

            for (DWORD i = 0; i < relocCount; i++) {
                WORD entry = relocData[i];
                DWORD type = entry >> 12;         // upper 4 bits
                DWORD offset = entry & 0x0FFF;    // lower 12 bits

                if (type == IMAGE_REL_BASED_DIR64) {
                    // 64-bit relocation
                    DWORD_PTR* patchAddr = (DWORD_PTR*)((DWORD_PTR)imageBase + reloc->VirtualAddress + offset);
                    *patchAddr += delta;
                } else if (type == IMAGE_REL_BASED_HIGHLOW) {
                    // 32-bit relocation
                    DWORD* patchAddr = (DWORD*)((DWORD_PTR)imageBase + reloc->VirtualAddress + offset);
                    *patchAddr += (DWORD)delta;
                } else if (type == IMAGE_REL_BASED_ABSOLUTE) {
                    // No relocation needed
                } else {
                    printf("[-] Unknown relocation type: %d\n", type);
                }
            }

            bytesProcessed += reloc->SizeOfBlock;
            reloc = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)reloc + reloc->SizeOfBlock);
        }

        printf("[+] Base relocations applied.\n");
    } else {
        printf("[=] No base relocations needed.\n");
    }
    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)(
        (DWORD_PTR)imageBase + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress
    );

    while (importDesc->Name) {
        const char* dllName = (const char*)((DWORD_PTR)imageBase + importDesc->Name);
        HMODULE hDll = LoadLibraryA(dllName);

        if (!hDll) {
            printf("[-] Failed to load dependency: %s\n", dllName);
            return -1;
        }

        // OriginalFirstThunk = names (for resolving)
        // FirstThunk = where resolved addresses go (IAT)
        PIMAGE_THUNK_DATA origFirstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)imageBase + importDesc->OriginalFirstThunk);
        PIMAGE_THUNK_DATA firstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)imageBase + importDesc->FirstThunk);

        while (origFirstThunk->u1.AddressOfData) {
            FARPROC funcAddr = NULL;

            if (origFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                // Import by ordinal
                WORD ordinal = IMAGE_ORDINAL(origFirstThunk->u1.Ordinal);
                funcAddr = GetProcAddress(hDll, (LPCSTR)ordinal);
            } else {
                // Import by name
                PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)imageBase + origFirstThunk->u1.AddressOfData);
                funcAddr = GetProcAddress(hDll, (LPCSTR)importByName->Name);
            }

            if (!funcAddr) {
                printf("[-] Failed to resolve import.\n");
                return -1;
            }

            // Write resolved address into IAT
            firstThunk->u1.Function = (DWORD_PTR)funcAddr;

            origFirstThunk++;
            firstThunk++;
        }

        importDesc++;
    }

    printf("[+] Imports resolved.\n");

    DWORD entryPointRVA = ntHeaders->OptionalHeader.AddressOfEntryPoint;
    void (*exeEntryPoint)() = (void (*)())((DWORD_PTR)imageBase + entryPointRVA);

    printf("[*] Jumping to entry point at: %p\n", exeEntryPoint);
    exeEntryPoint();  // 🚀 control transferred to loaded image

    free(peBuffer);
    return 0;
}
