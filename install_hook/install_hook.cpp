// install_hook.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

using namespace std;
void usage();

void usage() {
  cout << "install_hook.exe full-path-of-dll-to-inject pid" << endl;
  cout << "samples:" << endl;
  cout << "install_hook.exe c:\\users\\sokoide\\foo\\bar\\sample_hook.dll 1234"
       << endl;
  cout << "DWORD: " << sizeof(DWORD) << endl;
  cout << "LPVOID: " << sizeof(LPVOID) << endl;
}

int _tmain(int argc, _TCHAR *argv[]) {
  HANDLE hProcess = NULL;
  HANDLE hThread = NULL;
  char szDllPath[_MAX_PATH]; // full path of a hook dll to inject
  void *pDllRemote = NULL;   // dll entry address in the remote process
  DWORD hDll = NULL;         // dll handle
  DWORD pid;
  DWORD err;

  if (argc != 3) {
    usage();
    return 1;
  }

  pid = _ttol(argv[2]);

  if (sizeof(TCHAR) != sizeof(char)) {
    std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
    // const std::wstring wide_string = L"This is a double byte string";
    const std::string utf8_string = converter.to_bytes((wchar_t *)argv[1]);
    strcpy_s(szDllPath, utf8_string.c_str());
  } else {
    strcpy_s(szDllPath, (char *)argv[1]);
  }
  cout << "dll path: " << szDllPath << endl;

  // get process handle
  hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
  if (NULL == hProcess) {
    err = ::GetLastError();
    cout << "OpenProcess failed. Error Code: " << err << endl;
    goto CLEANUP;
  }

  // allocate memory in remote process for dll full path used by LoadLibraryA
  pDllRemote = ::VirtualAllocEx(hProcess, NULL, sizeof(szDllPath), MEM_COMMIT,
                                PAGE_READWRITE);
  if (NULL == pDllRemote) {
    err = ::GetLastError();
    cout << "VirtualAllocEx failed. Error Code: " << err << endl;
    goto CLEANUP;
  }

  if (!::WriteProcessMemory(hProcess, pDllRemote, (void *)szDllPath,
                            sizeof(szDllPath), NULL)) {
    err = ::GetLastError();
    cout << "WriteProcessMemory failed. Error Code: " << err << endl;

    goto CLEANUP;
  }

  // run LoadLibraryA in the remote process using remote thread
  hThread = ::CreateRemoteThread(
      hProcess, NULL, 0,
      (LPTHREAD_START_ROUTINE)::GetProcAddress(
          ::GetModuleHandle(_T("kernel32.dll")), "LoadLibraryA"),
      pDllRemote, 0, NULL);
  if (NULL == hThread) {
    err = ::GetLastError();
    cout << "CreateRemoteThread failed. Error Code: " << err << endl;

    goto CLEANUP;
  }
  ::WaitForSingleObject(hThread, INFINITE);
  // get dll handle as hDll
  ::GetExitCodeThread(hThread, &hDll);

  ::CloseHandle(hThread);
  hThread = NULL;

  ::VirtualFreeEx(hProcess, pDllRemote, sizeof(szDllPath), MEM_RELEASE);
  pDllRemote = NULL;

  // FeeLibrary
  hThread = ::CreateRemoteThread(
      hProcess, NULL, 0,
      (LPTHREAD_START_ROUTINE)::GetProcAddress(
          ::GetModuleHandle(_T("kernel32.dll")), "FreeLibrary"),
      (void *)hDll, 0, NULL);
  if (NULL == hThread) {
    err = ::GetLastError();
    cout << "CreateRemoteThread failed. Error Code: " << err << endl;

    goto CLEANUP;
  }
  ::WaitForSingleObject(hThread, INFINITE);
  ::CloseHandle(hThread);
  hThread = NULL;

CLEANUP:
  if (NULL != pDllRemote) {
    ::VirtualFreeEx(hProcess, pDllRemote, sizeof(szDllPath), MEM_RELEASE);
  }
  if (NULL != hThread) {
    ::CloseHandle(hThread);
  }
  if (NULL != hProcess) {
    ::CloseHandle(hProcess);
  }
  return 0;
}
