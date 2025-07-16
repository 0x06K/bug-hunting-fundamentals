#include <iostream>
#include <fstream>
#include <windows.h>
#include <ctime>
#include <iomanip> // for std::hex and formatting
#include <vector>      // for std::vector
#include <cstdint>     // for uint8_t

using namespace std;

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cout << "Usage: " << argv[0] << " <pe_file.exe>\n";
        return 1;
    }

    std::ifstream file(argv[1], std::ios::binary);
    if (!file) {
        std::cerr << "[-] Failed to open file.\n";
        return 1;
    }

    IMAGE_DOS_HEADER dosHeader;
    file.read(reinterpret_cast<char*>(&dosHeader), sizeof(dosHeader));

    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) { // 'MZ'
        std::cerr << "[-] Invalid DOS signature.\n";
        return 1;
    }

    std::cout << std::hex << std::showbase;
    std::cout << "=== IMAGE_DOS_HEADER ===\n";
    std::cout << "e_magic    : " << dosHeader.e_magic    << " ('MZ' signature)\n";
    std::cout << "e_cblp     : " << dosHeader.e_cblp     << " (Bytes on last page of file)\n";
    std::cout << "e_cp       : " << dosHeader.e_cp       << " (Pages in file)\n";
    std::cout << "e_crlc     : " << dosHeader.e_crlc     << " (Relocations)\n";
    std::cout << "e_cparhdr  : " << dosHeader.e_cparhdr  << " (Size of header in paragraphs)\n";
    std::cout << "e_minalloc : " << dosHeader.e_minalloc << " (Minimum extra paragraphs needed)\n";
    std::cout << "e_maxalloc : " << dosHeader.e_maxalloc << " (Maximum extra paragraphs needed)\n";
    std::cout << "e_ss       : " << dosHeader.e_ss       << " (Initial SS value)\n";
    std::cout << "e_sp       : " << dosHeader.e_sp       << " (Initial SP value)\n";
    std::cout << "e_csum     : " << dosHeader.e_csum     << " (Checksum)\n";
    std::cout << "e_ip       : " << dosHeader.e_ip       << " (Initial IP value)\n";
    std::cout << "e_cs       : " << dosHeader.e_cs       << " (Initial CS value)\n";
    std::cout << "e_lfarlc   : " << dosHeader.e_lfarlc   << " (File address of relocation table)\n";
    std::cout << "e_ovno     : " << dosHeader.e_ovno     << " (Overlay number)\n";

    std::cout << "e_res[4]   : ";
    for (int i = 0; i < 4; ++i) std::cout << dosHeader.e_res[i] << " ";
    std::cout << "(Reserved)\n";

    std::cout << "e_oemid    : " << dosHeader.e_oemid    << " (OEM identifier)\n";
    std::cout << "e_oeminfo  : " << dosHeader.e_oeminfo  << " (OEM info)\n";

    std::cout << "e_res2[10] : ";
    for (int i = 0; i < 10; ++i) std::cout << dosHeader.e_res2[i] << " ";
    std::cout << "(Reserved)\n";

    std::cout << "e_lfanew   : " << dosHeader.e_lfanew   << " (Offset to PE header)\n";
    
    // Step 2: Calculate stub + padding size
    DWORD peOffset = dosHeader.e_lfanew;
    DWORD stubAndPaddingSize = peOffset - sizeof(dosHeader);

    // Step 3: Read the bytes between DOS header and PE header
    char* stubAndPadding = new char[stubAndPaddingSize];
    file.read(stubAndPadding, stubAndPaddingSize);

    // Step 4: Print Dos Stub in hex
    std::cout << "\n===== DOS Stub (Hex Dump) =====\n";
    for (DWORD i = 0; i < stubAndPaddingSize; ++i) {
        printf("%02X ", static_cast<unsigned char>(stubAndPadding[i]));
        if ((i + 1) % 16 == 0) std::cout << "\n";
    }
    std::cout << std::endl;
    delete[] stubAndPadding;

    // Move to PE header offset
    file.seekg(dosHeader.e_lfanew, std::ios::beg);

    // Read 4-byte PE signature from there
    DWORD peSignature;
    file.read(reinterpret_cast<char*>(&peSignature), sizeof(peSignature));

    if (peSignature != 0x00004550) {
        std::cerr << "[-] Invalid PE signature.\n";
    } else {
        unsigned char* sigBytes = reinterpret_cast<unsigned char*>(&peSignature);
        std::cout << "PE Signature: ";
        for (int i = 3; i >= 0; --i) {
            printf("%02X ", sigBytes[i]);
        }
        std::cout << std::endl;
    }
    // Move to PE header (already done)
    file.seekg(dosHeader.e_lfanew + 4, std::ios::beg); // Skip the 4-byte PE signature

    IMAGE_FILE_HEADER fileHeader;
    file.read(reinterpret_cast<char*>(&fileHeader), sizeof(fileHeader));
    std::cout << std::endl;
    std::cout << "=== IMAGE_FILE_HEADER ===\n";
    std::cout << "Machine              : " << std::hex << fileHeader.Machine << "\n";
    std::cout << "NumberOfSections     : " << std::dec << fileHeader.NumberOfSections << "\n";
    std::time_t rawTime = static_cast<time_t>(fileHeader.TimeDateStamp);
    std::tm* timeInfo = std::gmtime(&rawTime);
    char timeStr[64];
    std::strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S UTC", timeInfo);
    std::cout << "TimeDateStamp        : " << timeStr << "\n";
    std::cout << "SizeOfOptionalHeader : " << fileHeader.SizeOfOptionalHeader << "\n";
    std::cout << "Characteristics      : " << fileHeader.Characteristics << "\n";
    std::cout << "PointerToSymbolTable : " << std::hex << fileHeader.PointerToSymbolTable << "\n";
    std::cout << "NumberOfSymbols      : " << std::dec << fileHeader.NumberOfSymbols << "\n";

    WORD magic;
    file.read(reinterpret_cast<char*>(&magic), sizeof(magic));
    file.seekg(-static_cast<int>(sizeof(magic)), std::ios::cur); // rewind

    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        IMAGE_OPTIONAL_HEADER64 optionalHeader;
        file.read(reinterpret_cast<char*>(&optionalHeader), sizeof(optionalHeader));

        std::cout << "\n=== IMAGE_OPTIONAL_HEADER64 ===\n";
        std::cout << "Magic                    : " << optionalHeader.Magic << "\n";
        std::cout << "MajorLinkerVersion       : " << std::dec << (int)optionalHeader.MajorLinkerVersion << "\n";
        std::cout << "MinorLinkerVersion       : " << (int)optionalHeader.MinorLinkerVersion << "\n";
        std::cout << "SizeOfCode               : " << std::hex << optionalHeader.SizeOfCode << "\n";
        std::cout << "SizeOfInitializedData    : " << optionalHeader.SizeOfInitializedData << "\n";
        std::cout << "SizeOfUninitializedData  : " << optionalHeader.SizeOfUninitializedData << "\n";
        std::cout << "AddressOfEntryPoint      : " << optionalHeader.AddressOfEntryPoint << "\n";
        std::cout << "BaseOfCode               : " << optionalHeader.BaseOfCode << "\n";
        std::cout << "ImageBase                : " << optionalHeader.ImageBase << "\n";
        std::cout << "SectionAlignment         : " << optionalHeader.SectionAlignment << "\n";
        std::cout << "FileAlignment            : " << optionalHeader.FileAlignment << "\n";
        std::cout << "MajorOperatingSystemVersion : " << optionalHeader.MajorOperatingSystemVersion << "\n";
        std::cout << "MinorOperatingSystemVersion : " << optionalHeader.MinorOperatingSystemVersion << "\n";
        std::cout << "MajorSubsystemVersion    : " << optionalHeader.MajorSubsystemVersion << "\n";
        std::cout << "MinorSubsystemVersion    : " << optionalHeader.MinorSubsystemVersion << "\n";
        std::cout << "Win32VersionValue        : " << optionalHeader.Win32VersionValue << "\n";
        std::cout << "SizeOfImage              : " << optionalHeader.SizeOfImage << "\n";
        std::cout << "SizeOfHeaders            : " << optionalHeader.SizeOfHeaders << "\n";
        std::cout << "Subsystem                : " << optionalHeader.Subsystem << "\n";
        std::cout << "DllCharacteristics       : " << optionalHeader.DllCharacteristics << "\n";
        std::cout << "NumberOfRvaAndSizes      : " << optionalHeader.NumberOfRvaAndSizes << "\n";

        std::cout << "\n=== Data Directories ===\n";
        for (int i = 0; i < optionalHeader.NumberOfRvaAndSizes && i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++i) {
            std::cout << "[" << i << "] RVA: " << optionalHeader.DataDirectory[i].VirtualAddress
                      << ", Size: " << optionalHeader.DataDirectory[i].Size << "\n";
        }

    } else {
        std::cerr << "[-] Only 64-bit PE files are supported in this example.\n";
        return 1;
    }
    // Section headers start right after Optional Header
    IMAGE_SECTION_HEADER sectionHeader;
    std::cout << "\n=== Section Headers ===\n";
    for (int i = 0; i < fileHeader.NumberOfSections; ++i) {
        file.read(reinterpret_cast<char*>(&sectionHeader), sizeof(sectionHeader));
        
        std::cout << "Section Name: ";
        for (int j = 0; j < 8 && sectionHeader.Name[j] != 0; ++j)
            std::cout << sectionHeader.Name[j];
            std::cout << "\n";
            std::cout << "  Misc.VirtualSize     : "  << sectionHeader.Misc.VirtualSize << "\n";
            std::cout << "  VirtualAddress       : "  << sectionHeader.VirtualAddress << "\n";
            std::cout << "  SizeOfRawData        : "  << sectionHeader.SizeOfRawData << "\n";
            std::cout << "  PointerToRawData     : "  << sectionHeader.PointerToRawData << "\n";
            std::cout << "  PointerToRelocations : "  << sectionHeader.PointerToRelocations << "\n";
            std::cout << "  PointerToLinenumbers : "  << sectionHeader.PointerToLinenumbers << "\n";
            std::cout << "  NumberOfRelocations  : "  << sectionHeader.NumberOfRelocations << "\n";
            std::cout << "  NumberOfLinenumbers  : "  << sectionHeader.NumberOfLinenumbers << "\n";
            std::cout << "  Characteristics      : "  << sectionHeader.Characteristics << "\n";

            std::cout << "------------------------------------\n";
    }
    return 0;
}
