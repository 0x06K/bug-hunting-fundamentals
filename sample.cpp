#include <iostream>
#include <fstream>
#include <windows.h>

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: pe_zero_offset.exe <target_exe>" << std::endl;
        return 1;
    }

    const char* filename = argv[1];

    std::fstream file(filename, std::ios::in | std::ios::out | std::ios::binary);
    if (!file) {
        std::cerr << "Failed to open file: " << filename << std::endl;
        return 1;
    }

    // IMAGE_DOS_HEADER is always at the beginning
    IMAGE_DOS_HEADER dosHeader;
    file.read(reinterpret_cast<char*>(&dosHeader), sizeof(dosHeader));

    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        std::cerr << "Not a valid MZ/PE file." << std::endl;
        return 1;
    }

    std::cout << "[+] Original e_lfanew: 0x" << std::hex << dosHeader.e_lfanew << std::endl;

    // Seek to e_lfanew offset (0x3C)
    file.seekp(0x3C, std::ios::beg);
    DWORD zero = 0;
    file.write(reinterpret_cast<char*>(&zero), sizeof(zero));
    file.close();

    std::cout << "[+] e_lfanew field zeroed. PE header is now unreachable." << std::endl;
    return 0;
}
