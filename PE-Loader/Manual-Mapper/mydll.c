#define WIN32_LEAN_AND_MEAN
#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hMod, DWORD reason) {
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hMod);
        OutputDebugStringA("[mydll] DLL_PROCESS_ATTACH\n");
        break;
    case DLL_PROCESS_DETACH:
        OutputDebugStringA("[mydll] DLL_PROCESS_DETACH\n");
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    HelloFromDLL();
    return TRUE; // return FALSE to fail loading
}

// Example exported function (cdecl for easy call from many tools)
__declspec(dllexport) void __cdecl HelloFromDLL(void) {
    MessageBoxA(NULL, "Hello from my DLL!", "mydll", MB_OK | MB_ICONINFORMATION);
}

// Another export with a return value
__declspec(dllexport) int __cdecl AddInts(int a, int b) {
    return a + b;
}
