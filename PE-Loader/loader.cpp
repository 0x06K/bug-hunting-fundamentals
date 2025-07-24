#include <windows.h>
#include <winternl.h>
#include <stdio.h>
using namespace std;

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
*/

/*
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
*/
FARPROC GetProcAddressManual(PVOID ntdllBase, const char* targetName) {
    
    return NULL;
}

int main(int argc, char* argv[]) {

    /* FLow is like this {PEB} has member pointer of type PEB_LDR_DATA named
     Ldr which points to -> member of PEB_LDR_DATA InMemoryOrderModuleList of
      type LIST_ENTRY(circullar double linked list) that points to -> a an object
       of PLDR_DATA_TABLE_ENTRY which contains the information of one module it has
        a pointer (LIST_ENTRY InMemoryOrderLinks) it points to other table entries */
    /* think of it like you have a main class PEB which contains the pointer 
    of clas PEB_LDR_DATA to store the addr of its object that pointer points 
    to that object and now that object has a member of type LIST_ENTRY which 
    is a circular doubly linked list now this list points to another data structure
     named PEB_LDR_DATA_TABLE_ENTRY which contains information of one module
      it has a pointer (LIST_ENTRY InMemoryOrderLinks) that points to other 
      PLDR_DATA_TABLE_ENTRIES. So in simple terms flow is like this:

    PEB -> PEB_LDR_DATA* -> PEB_LDR_DATA -> LIST_ENTRY(circulardoublylinkedlist).Flink*
     -> PLDR_DATA_TABLE_ENTRIES

    */
    // Gets the pointer to the Process Environment Block (PEB) in 64-bit user-mode.
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    // realigns the pointer to structure PLDR_DATA_TABLE_ENTRY which contains the module information
    PLDR_DATA_TABLE_ENTRY pEntry = 
    (PLDR_DATA_TABLE_ENTRY)((BYTE*)pPeb->Ldr->InMemoryOrderModuleList.Flink->Flink - 0x10);
    // just stored the module base addr
    PVOID ntdllBase = pEntry->DllBase;

    // Parse Headers
    // Dos headers
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)ntdllBase;
    // NT headers
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((BYTE*)ntdllBase + dos->e_lfanew);
    // get to export directory
    IMAGE_DATA_DIRECTORY exportDirData = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    IMAGE_EXPORT_DIRECTORY* exportDir = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)ntdllBase + exportDirData.VirtualAddress);
    /* when we perform pointer airthmetic in the end it depends on pointer that how much byte it points to original
    like: (BYTE*)ntdllBase + exportDirData.VirtualAddress will return a pointer to a byte. but int* ptr = &a;ptr++ will give pointer to 
    integer means 4 bytes. (BYTE*)ntdllBase + 0xsomething in the end a pointer to a byte will be returned. */
    DWORD* nameRvas = (DWORD*)((BYTE*)ntdllBase + exportDir->AddressOfNames);
    WORD* ordinals = (WORD*)((BYTE*)ntdllBase + exportDir->AddressOfNameOrdinals);
    DWORD* funcRvas = (DWORD*)((BYTE*)ntdllBase + exportDir->AddressOfFunctions);
    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        char* funcName = (char*)(ntdllBase + nameRvas[i]);
        if (strcmp(funcName, "NtCreateFile") == 0) {
            WORD ordinal = ordinals[i];
            DWORD funcRVA = funcRvas[ordinal];
            void* ntCreateFileAddr = (BYTE*)ntdllBase + funcRVA;
            break;
        }
    }
    
    return 0;
}

/*
=== Basic Signature of NtCreateFile() ===
    NTSTATUS NtCreateFile(
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
=== IMAGE_DOS_HEADER ===
typedef struct _IMAGE_DOS_HEADER {
    WORD   e_magic;     // "MZ"
    WORD   e_cblp;
    WORD   e_cp;
    WORD   e_crlc;
    WORD   e_cparhdr;
    WORD   e_minalloc;
    WORD   e_maxalloc;
    WORD   e_ss;
    WORD   e_sp;
    WORD   e_csum;
    WORD   e_ip;
    WORD   e_cs;
    WORD   e_lfarlc;
    WORD   e_ovno;
    WORD   e_res[4];
    WORD   e_oemid;
    WORD   e_oeminfo;
    WORD   e_res2[10];
    LONG   e_lfanew;    // File offset to PE header
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

=== IMAGE_NT_HEADERS64 ===
typedef struct _IMAGE_NT_HEADERS64 {
    DWORD Signature;  // "PE\0\0"
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

=== IMAGE_OPTIONAL_HEADER64 ===
typedef struct _IMAGE_OPTIONAL_HEADER64 {
    ...
    IMAGE_DATA_DIRECTORY DataDirectory[16];       // Array of directories
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

=== IMAGE_DATA_DIRECTORY ===
typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD VirtualAddress;     // RVA to the structure
    DWORD Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

=== IMAGE_EXPORT_DIRECTORY ===
typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD Characteristics;
    DWORD TimeDateStamp;
    WORD  MajorVersion;
    WORD  MinorVersion;
    DWORD Name;                       // RVA of DLL name
    DWORD Base;
    DWORD NumberOfFunctions;
    DWORD NumberOfNames;
    DWORD AddressOfFunctions;        // RVA to DWORD array of function RVAs
    DWORD AddressOfNames;            // RVA to DWORD array of names (RVA to ASCII strings)
    DWORD AddressOfNameOrdinals;     // RVA to WORD array of ordinals
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;

*/
/*
    PEB structure blueprint
    typedef struct _PEB {
        BYTE                          InheritedAddressSpace;
        BYTE                          ReadImageFileExecOptions;
        BYTE                          BeingDebugged;
        BYTE                          BitField;
        PVOID                         Mutant;
        PVOID                         ImageBaseAddress;
        struct _PEB_LDR_DATA*         Ldr; --> [we are concerened with this for now]
        struct _RTL_USER_PROCESS_PARAMETERS* ProcessParameters;
        PVOID                         SubSystemData;
        PVOID                         ProcessHeap;
        PVOID                         FastPebLock;
        PVOID                         AtlThunkSListPtr;
        PVOID                         IFEOKey;
        // ... many more fields
    } PEB, *PPEB;
_____________________________________________________________________________________________________

    typedef struct _PEB_LDR_DATA {
        ULONG Length;
        BOOLEAN Initialized;
        PVOID SsHandle;

        LIST_ENTRY InLoadOrderModuleList;        // Points to InLoadOrderLinks in each module
        LIST_ENTRY InMemoryOrderModuleList;      // Points to InMemoryOrderLinks in each module
        LIST_ENTRY InInitializationOrderModuleList; // Points to InInitializationOrderLinks

        // Other internal fields may follow
    } PEB_LDR_DATA, *PPEB_LDR_DATA;
_____________________________________________________________________________________________________
    
    typedef struct _LIST_ENTRY {
        struct _LIST_ENTRY* Flink;  // Next node
        struct _LIST_ENTRY* Blink;  // Previous node
    } LIST_ENTRY, *PLIST_ENTRY;
    
    points to the struct below
_____________________________________________________________________________________________________

    typedef struct _LDR_DATA_TABLE_ENTRY {
        LIST_ENTRY InLoadOrderLinks;          // Next/Prev in load order
        LIST_ENTRY InMemoryOrderLinks;        // Next/Prev in memory order
        LIST_ENTRY InInitializationOrderLinks;// Next/Prev in init order
        PVOID DllBase;                        // Base address of module
        PVOID EntryPoint;                     // Entry point of module
        ULONG SizeOfImage;                    // Size of the image
        UNICODE_STRING FullDllName;           // Full path of the DLL
        UNICODE_STRING BaseDllName;           // Just the name (e.g. "kernel32.dll")
        ...
    } LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

    PEB
    └── Ldr (PEB_LDR_DATA)
        └── InMemoryOrderModuleList (LIST_ENTRY)   ← list head (not a module)
            └── Flink → [module1]->InMemoryOrderLinks
                        └── Flink → [module2]->InMemoryOrderLinks
                                    ...
                        └── Blink ← prev module


*/
