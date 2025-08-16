# Manual PE Loader

A modular, low-level PE (Portable Executable) loader implementation that manually loads and executes Windows PE files using direct NTDLL API calls instead of standard Windows loader functions.

## Features

- **Manual NTDLL Function Resolution**: Resolves NTDLL functions by parsing the export table manually
- **Direct File I/O**: Uses NTDLL APIs (NtCreateFile, NtReadFile) for file operations
- **Complete PE Processing**: 
  - Section mapping and memory allocation
  - Base relocations processing
  - Import resolution (IAT patching)
  - TLS callback execution
  - CRT initialization
  - Memory protection application
- **Modular Architecture**: Clean separation of concerns across multiple source files
- **Cross-Compiler Support**: Works with both GCC/MinGW and MSVC

## Project Structure

```
pe_loader/
├── pe_loader.h           # Main header with type definitions and function declarations
├── main.c                # Main program entry point and orchestration logic
├── ntdll_resolver.c      # NTDLL function resolution via PEB parsing
├── file_operations.c     # File I/O operations using NTDLL APIs
├── pe_utils.c            # PE utility functions (validation, protection conversion)
├── pe_loader_core.c      # Core PE loading (mapping, relocations, imports)
├── tls_handler.c         # TLS callback processing
├── execution.c           # PE execution and entry point jumping
├── cleanup.c             # Resource cleanup and future extensions
├── Makefile              # Build configuration for GCC and MSVC
└── README.md             # This documentation
```

## Module Responsibilities

### Core Modules

- **`pe_loader.h`**: Central header containing all type definitions, function pointers, and declarations
- **`main.c`**: Program entry point, argument handling, and orchestrates the entire loading process
- **`ntdll_resolver.c`**: Resolves NTDLL functions by walking the PEB and parsing export tables manually

### File Operations
- **`file_operations.c`**: Handles all file I/O using NTDLL APIs instead of standard C library functions

### PE Processing
- **`pe_utils.c`**: Utility functions for PE validation, section protection conversion, and CRT initialization
- **`pe_loader_core.c`**: Core PE loading functionality including section mapping, relocations, and import resolution
- **`tls_handler.c`**: Processes and executes TLS (Thread Local Storage) callbacks

### Execution & Cleanup
- **`execution.c`**: Handles jumping to the PE entry point for execution
- **`cleanup.c`**: Resource cleanup and placeholder for future enhancements

## Building

### Prerequisites

**For GCC/MinGW:**
- MinGW-w64 or similar GCC toolchain for Windows
- Make utility

**For MSVC:**
- Microsoft Visual Studio or Build Tools
- NMAKE (included with Visual Studio)

### Build Commands

```bash
gcc *.c -o manual-mapper.exe
```

## Usage

```bash
# Basic usage
pe_loader.exe <path_to_pe_file>

# Examples
pe_loader.exe C:\Windows\System32\calc.exe
pe_loader.exe malware_sample.exe
pe_loader.exe "C:\Program Files\MyApp\app.exe"
```

## Technical Details

### NTDLL Function Resolution
The loader manually resolves NTDLL functions by:
1. Accessing the Process Environment Block (PEB) via GS register
2. Walking the module list to find NTDLL
3. Parsing the export table to resolve function addresses
4. Avoiding dependency on kernel32.dll or other high-level APIs

### PE Loading Process
1. **File Operations**: Open and read PE file using NtCreateFile/NtReadFile
2. **Validation**: Validate DOS and NT headers
3. **Memory Allocation**: Allocate memory for the PE image using NtAllocateVirtualMemory
4. **Section Mapping**: Copy PE sections from file to memory
5. **Base Relocations**: Process relocation table if loaded at different base address
6. **Import Resolution**: Resolve imported functions and patch Import Address Table (IAT)
7. **Memory Protection**: Apply appropriate memory protections to sections
8. **CRT Initialization**: Execute C Runtime initialization functions
9. **TLS Processing**: Execute Thread Local Storage callbacks
10. **Execution**: Jump to PE entry point

### Security Considerations

This tool is designed for:
- Malware analysis and reverse engineering
- Educational purposes
- Security research
- Understanding PE file format internals

⚠️ **Warning**: This tool can execute malicious code. Use only in controlled environments (VMs, sandboxes) and never on production systems.

## Advanced Features

### Exception Handling
The loader includes structured exception handling (SEH) for:
- TLS callback execution
- Entry point execution
- Critical operations that might fail

### Memory Management
- Uses NTDLL APIs for all memory operations
- Proper section permission handling
- Base relocation processing for ASLR compatibility

### Import Resolution
- Supports both name-based and ordinal-based imports
- Handles forwarder exports
- Validates import structures before processing

## Future Enhancements

The codebase is designed to support additional features:
- Exception directory processing
- Security cookie initialization
- Delay import processing
- Resource extraction
- Debug information loading
- Digital signature verification
- Control Flow Guard (CFG) setup
- Load configuration processing
- Bound import optimization
- .NET CLR initialization

## Error Handling

The loader includes comprehensive error handling:
- NTSTATUS code reporting
- Win32 error code translation
- Validation of all PE structures
- Safe handling of malformed files

## Debugging

For debugging builds:
```bash
make debug
```

This enables:
- Debug symbols
- Additional logging
- Assertion checks
- Memory leak detection helpers

## License

This project is provided for educational and research purposes. Users are responsible for complying with applicable laws and regulations when using this software.

## Contributing

Contributions are welcome, particularly:
- Additional PE feature support
- Bug fixes and improvements
- Documentation enhancements
- Cross-platform compatibility
- Additional error handling

## References

- Microsoft PE/COFF Specification
- Windows Internals books by Mark Russinovich
- NTDLL documentation and reverse engineering resources
- Malware analysis and reverse engineering literature