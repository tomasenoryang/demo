#include <Windows.h>  
#include <iostream>  
#include <ip2string.h>
#include <in6addr.h>
#include <vector>
#pragma comment( lib, "ntdll.lib" )
#include "winternl.h"

bool EnableDebugPrivilege()
{
  HANDLE hToken = NULL;
  LUID debugPrivilegeValueLuid = { 0 };
  TOKEN_PRIVILEGES tokenPrivilege = { 0 };

  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    return false;

  if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &debugPrivilegeValueLuid))
  {
    CloseHandle(hToken);
    return false;
  }

  tokenPrivilege.PrivilegeCount = 1;
  tokenPrivilege.Privileges[0].Luid = debugPrivilegeValueLuid;
  tokenPrivilege.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
  if (!AdjustTokenPrivileges(hToken, FALSE, &tokenPrivilege, sizeof(tokenPrivilege), NULL, NULL))
  {
    CloseHandle(hToken);
    return false;
  }

  return true;
}

typedef NTSTATUS(__cdecl* RTLSETPROCESSISCRITICAL)(IN BOOLEAN NewValue, OUT PBOOLEAN OldValue OPTIONAL, IN BOOLEAN NeedBreaks);

typedef NTSTATUS(__stdcall* FNtSetInformationProcess)(
  HANDLE               ProcessHandle,
  PROCESSINFOCLASS     ProcessInformationClass,
  PVOID                ProcessInformation,
  ULONG                ProcessInformationLength
  );


FARPROC GetSysProcessAddressEx(const wchar_t* lpszModuleName, const char* lpszFuncName)
{
  auto handle = ::GetModuleHandle(lpszModuleName);
  if (handle == nullptr)
    handle = ::LoadLibraryEx(lpszModuleName, NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);

  if (handle == nullptr) return nullptr;
  return ::GetProcAddress(handle, lpszFuncName);
}


#define CoutWrap(_x) std::cout << _x << std::endl; 

using pIsWow64Process = BOOL(WINAPI*) (
  HANDLE hProcess,
  PBOOL  Wow64Process
  );

static inline pIsWow64Process _getIsWow64Process()
{
  auto handle = GetModuleHandle(L"kernel32.dll");
  if (handle == nullptr) {
		std::cout << "GetModuleHandle Error!" << std::endl;
    return nullptr;
  }
  return (pIsWow64Process)GetProcAddress(handle, "IsWow64Process");
}

int wmain(int argc, wchar_t* wargv[])
{
  std::locale::global(std::locale("chs"));

  if (__argc <= 1) {
    std::cout << u8"Param Invaild, pid pid ...";
    return -1;
  }

  if (!EnableDebugPrivilege())
    std::cout << u8"EnableDebugPrivilege Error! lerr:" << GetLastError() << std::endl;

  auto pfnNtSetInformationProcess = (FNtSetInformationProcess)GetSysProcessAddressEx(L"ntdll.dll", "NtSetInformationProcess");

  std::vector<int32_t> pidArr;
  for (size_t i = 1; i < __argc; ++i) {
    int32_t pid = _wtoll(wargv[i]);
    std::cout << u8"Target proc pid : " << pid << std::endl;
    pidArr.push_back(pid);
  }

  for (auto& it : pidArr) {
    auto proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, it);
    if (nullptr == proc) {
      std::cout << u8"OpenProcess Error!" << std::endl;
    }

    DWORD isCritical = 1;
    auto ret = pfnNtSetInformationProcess(proc, ProcessBreakOnTermination, &isCritical, sizeof(isCritical));
    std::cout << u8"Target proc pid[" << it << u8"], oper result: " << ret << std::endl;
  }

  return 0;
}
