#include <iostream>
#include <fstream>
#include <windows.h>
#include <iomanip> // for std::hex and formatting

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

    file.close();
    return 0;
}
