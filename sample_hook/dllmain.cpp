// dllmain.cpp : Defines the entry point for the DLL application.
// ref: http://ruffnex.oc.to/kenji/text/api_hook/
#include "stdafx.h"
void ReplaceIATEntryInAModule(PCSTR pszModuleName, PROC pfnCurrent, PROC pfnNew,
                              HMODULE hmodCaller);
void ReplaceIATEntryInAllModules(PCSTR pszModuleName, PROC pfnCurrent,
                                 PROC pfnNew);

// original functions
typedef HWND (*fnCreateWindowExW)(
    _In_ DWORD dwExStyle, _In_opt_ LPCWSTR lpClassName,
    _In_opt_ LPCWSTR lpWindowName, _In_ DWORD dwStyle, _In_ int x, _In_ int y,
    _In_ int nWidth, _In_ int nHeight, _In_opt_ HWND hWndParent,
    _In_opt_ HMENU hMenu, _In_opt_ HINSTANCE hInstance,
    _In_opt_ LPVOID lpParam);
fnCreateWindowExW org_CreateWindowExW;

// detoured functions
HWND WINAPI
    detoured_CreateWindowExW(_In_ DWORD dwExStyle, _In_opt_ LPCWSTR lpClassName,
                             _In_opt_ LPCWSTR lpWindowName, _In_ DWORD dwStyle,
                             _In_ int x, _In_ int y, _In_ int nWidth,
                             _In_ int nHeight, _In_opt_ HWND hWndParent,
                             _In_opt_ HMENU hMenu, _In_opt_ HINSTANCE hInstance,
                             _In_opt_ LPVOID lpParam);

// DllMain
BOOL APIENTRY
    DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
  switch (ul_reason_for_call) {
  case DLL_PROCESS_ATTACH:
    ::OutputDebugString(_T("* sample_hook injected.\n"));
    ::DisableThreadLibraryCalls(hModule);

    org_CreateWindowExW = (fnCreateWindowExW)::GetProcAddress(
        GetModuleHandleA("user32.dll"), "CreateWindowExW");
    ReplaceIATEntryInAllModules("user32.dll", (PROC)org_CreateWindowExW,
                                (PROC)detoured_CreateWindowExW);
    break;
  case DLL_THREAD_ATTACH:
  case DLL_THREAD_DETACH:
  case DLL_PROCESS_DETACH:
    break;
  }
  return TRUE;
}

HWND WINAPI
    detoured_CreateWindowExW(_In_ DWORD dwExStyle, _In_opt_ LPCWSTR lpClassName,
                             _In_opt_ LPCWSTR lpWindowName, _In_ DWORD dwStyle,
                             _In_ int x, _In_ int y, _In_ int nWidth,
                             _In_ int nHeight, _In_opt_ HWND hWndParent,
                             _In_opt_ HMENU hMenu, _In_opt_ HINSTANCE hInstance,
                             _In_opt_ LPVOID lpParam) {
  ::OutputDebugString(
      _T("* detoured_CreateWindowExW called. Calling original function.\n"));
  return (*org_CreateWindowExW)(dwExStyle, lpClassName, lpWindowName, dwStyle,
                                x, y, nWidth, nHeight, hWndParent, hMenu,
                                hInstance, lpParam);
}

// Replace IAT entry in a module
void ReplaceIATEntryInAModule(PCSTR pszModuleName, PROC pfnCurrent, PROC pfnNew,
                              HMODULE hmodCaller) {
  ULONG ulSize;
  PIMAGE_IMPORT_DESCRIPTOR pImportDesc;
  pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData(
      hmodCaller, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &ulSize);

  if (pImportDesc == NULL)
    return;

  while (pImportDesc->Name) {
    PSTR pszModName = (PSTR)((PBYTE)hmodCaller + pImportDesc->Name);
    if (lstrcmpiA(pszModName, pszModuleName) == 0)
      break;
    pImportDesc++;
  }

  if (pImportDesc->Name == 0)
    return;

  PIMAGE_THUNK_DATA pThunk =
      (PIMAGE_THUNK_DATA)((PBYTE)hmodCaller + pImportDesc->FirstThunk);

  while (pThunk->u1.Function) {
    PROC *ppfn = (PROC *)&pThunk->u1.Function;
    BOOL fFound = (*ppfn == pfnCurrent);
    if (fFound) {
      DWORD dwDummy;
      VirtualProtect(ppfn, sizeof(ppfn), PAGE_EXECUTE_READWRITE, &dwDummy);
      WriteProcessMemory(GetCurrentProcess(), ppfn, &pfnNew, sizeof(pfnNew),
                         NULL);
      return;
    }
    pThunk++;
  }
  return;
}

// Replace IAT entry in all modules
void ReplaceIATEntryInAllModules(PCSTR pszModuleName, PROC pfnCurrent,
                                 PROC pfnNew) {
  HANDLE hModuleSnap =
      CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
  if (hModuleSnap == INVALID_HANDLE_VALUE)
    return;

  MODULEENTRY32 me;
  me.dwSize = sizeof(me);
  BOOL bModuleResult = Module32First(hModuleSnap, &me);
  while (bModuleResult) {
    ReplaceIATEntryInAModule(pszModuleName, pfnCurrent, pfnNew, me.hModule);
    bModuleResult = Module32Next(hModuleSnap, &me);
  }
  CloseHandle(hModuleSnap);
}
