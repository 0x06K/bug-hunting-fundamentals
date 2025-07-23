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
int main(int argc, char* argv[]) {
    // Gets the pointer to the Process Environment Block (PEB) in 64-bit user-mode.
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    PLDR_DATA_TABLE_ENTRY pEntry = (PLDR_DATA_TABLE_ENTRY)pPeb->Ldr->InMemoryOrderModuleList.Flink;
    PVOID ntdllBase = pEntry->DllBase;
    // Parse its PE headers to find export directory



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
