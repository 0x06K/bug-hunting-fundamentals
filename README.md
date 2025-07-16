# PE Parser

A simple tool that reads and displays detailed information from a Windows PE file (like `.exe`).

## What I Learned
- How the PE file format is structured (DOS header, NT headers, sections).
- How to read binary files using C++ and WinAPI structures.
- How to work with offsets, memory alignment, and hex data.
- The role of section headers and data directories in executable loading.

## What It Does

- Shows DOS header (with hex dump of the stub).
- Validates and prints PE signature.
- Reads File and Optional headers (64-bit only).
- Lists all section headers and data directories.

## How to Use

```bash
extractor.exe yourfile.exe
````

## Requirements

* Windows.
* C++ compiler.

## Notes

* Only supports **64-bit PE files** for now.
* Great for learning how executables are structured.

Made for fun and learning.

