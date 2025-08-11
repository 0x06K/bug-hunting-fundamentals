#ifndef PE_LOADER_H
#define PE_LOADER_H

#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdint.h>

// ============================================================================
// TYPE DEFINITIONS AND FUNCTION POINTERS
// ============================================================================

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

// ============================================================================
// GLOBAL CONSTANTS
// ============================================================================

extern const char* g_functionsToResolve[];
#define FUNCTION_COUNT 10

// ============================================================================
// FUNCTION DECLARATIONS
// ============================================================================

// ntdll_resolver.c
PVOID GetNTDLLBase(void);
BOOL ResolveNTDLLFunctions(FARPROC resolvedFuncs[FUNCTION_COUNT]);

// file_operations.c
BOOL PrepareFilePath(const char* inputPath, wchar_t* finalPath);
BOOL OpenFileWithNtAPI(pNtCreateFile NtCreateFile, pRtlInitUnicodeString RtlInitUnicodeString, 
                       const wchar_t* filePath, HANDLE* hFile);
BOOL GetFileSizeNt(pNtQueryInformationFile NtQueryInformationFile, HANDLE hFile, SIZE_T* fileSize);
BOOL ReadFileContent(pNtReadFile NtReadFile, HANDLE hFile, PVOID buffer, SIZE_T fileSize);

// pe_utils.c
DWORD ConvertSectionCharacteristicsToProtection(DWORD characteristics);
BOOL ValidatePEHeaders(BYTE* base);
typedef void (__cdecl *CRT_INIT_FUNC)(void);
void CallCRTInitializers(LPBYTE moduleBase);

// pe_loader_core.c
BOOL AllocateAndMapSections(pNtAllocateVirtualMemory NtAllocateVirtualMemory, 
                           PVOID fileBuffer, PVOID* base);
BOOL ProcessBaseRelocations(BYTE* base);
void ResolveImports(BYTE* base);
void ApplySectionProtections(BYTE* base, pNtProtectVirtualMemory NtProtectVirtualMemory);

// tls_handler.c
void ResolveTLS(BYTE* base);
void ResolveTLS32(BYTE* base);

// execution.c
void JumpToEntryPoint(BYTE* base);

// cleanup.c
void CleanupResources(PVOID peBase, PVOID fileBuffer);

#endif // PE_LOADER_H