#include "pe_loader.h"

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Converts PE section characteristics to memory protection flags
 * @param characteristics Section characteristics from PE header
 * @return Corresponding PAGE_* protection constant
 */
DWORD ConvertSectionCharacteristicsToProtection(DWORD characteristics) {
    if (characteristics & IMAGE_SCN_MEM_EXECUTE) {
        if (characteristics & IMAGE_SCN_MEM_WRITE)
            return PAGE_EXECUTE_READWRITE;
        else if (characteristics & IMAGE_SCN_MEM_READ)
            return PAGE_EXECUTE_READ;
        else
            return PAGE_EXECUTE;
    } else {
        if (characteristics & IMAGE_SCN_MEM_WRITE)
            return PAGE_READWRITE;
        else if (characteristics & IMAGE_SCN_MEM_READ)
            return PAGE_READONLY;
        else
            return PAGE_NOACCESS;
    }
}

/**
 * @brief Validates PE DOS and NT headers
 * @param base Base address of PE image
 * @return TRUE if headers are valid, FALSE otherwise
 */
BOOL ValidatePEHeaders(BYTE* base) {
    // Validate DOS header
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)base;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[-] Invalid DOS signature\n");
        return FALSE;
    }

    // Validate NT header
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((BYTE*)base + dosHeader->e_lfanew);
    if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
        printf("[-] Invalid NT signature\n");
        return FALSE;
    }

    return TRUE;
}

/**
 * @brief Calls CRT initializers from .CRT section
 * @param moduleBase Base address of the loaded PE image
 */
void CallCRTInitializers(LPBYTE moduleBase)
{
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)moduleBase;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(moduleBase + dos->e_lfanew);

    PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(nt);
    DWORD numberOfSections = nt->FileHeader.NumberOfSections;

    // Loop through each section to find .CRT
    for (DWORD i = 0; i < numberOfSections; ++i) {
        if (strcmp((char*)sections[i].Name, ".CRT") == 0) {
            LPBYTE crtStart = moduleBase + sections[i].VirtualAddress;
            DWORD size = sections[i].Misc.VirtualSize;

            // Go through the section as an array of function pointers
            CRT_INIT_FUNC* initArray = (CRT_INIT_FUNC*)crtStart;
            DWORD count = size / sizeof(CRT_INIT_FUNC);

            for (DWORD j = 0; j < count; ++j) {
                if (initArray[j]) {
                    initArray[j](); // Call the constructor
                }
            }

            printf(".CRT section processed.\n");
            return;
        }
    }

    printf(".CRT section not found.\n");
}