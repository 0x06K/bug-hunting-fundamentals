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
