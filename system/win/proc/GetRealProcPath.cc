#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <iostream>

// 获取进程 ID
DWORD GetProcessIdByPath(const std::wstring& processName) {
  HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

  PROCESSENTRY32W pe;
  pe.dwSize = sizeof(pe);
  DWORD processId = 0;

  if (Process32FirstW(hSnapshot, &pe)) {
    do {
      if (_wcsicmp(pe.szExeFile, processName.c_str()) == 0) {
        processId = pe.th32ProcessID;
        break;
      }
    } while (Process32NextW(hSnapshot, &pe));
  }
  CloseHandle(hSnapshot);
  return processId;
}

// 读取 PEB 信息
bool GetPEBImagePath(HANDLE hProcess) {
  PROCESS_BASIC_INFORMATION pbi;
  ZeroMemory(&pbi, sizeof(pbi));

  // 获取 `NtQueryInformationProcess` 函数指针
  typedef NTSTATUS(WINAPI* NtQueryInformationProcessFunc)(
    HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

  auto NtQueryInformationProcess = (NtQueryInformationProcessFunc)GetProcAddress(
    GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");

  if (!NtQueryInformationProcess) {
    std::wcerr << L"无法获取 NtQueryInformationProcess" << std::endl;
    return false;
  }

  // 获取 PEB 地址
  NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), nullptr);
  if (status != 0) {
    std::wcerr << L"NtQueryInformationProcess 失败，状态: " << std::hex << status << std::endl;
    return false;
  }

  // 读取 PEB 结构
  PEB peb;
  SIZE_T bytesRead;
  if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead)) {
    std::wcerr << L"无法读取 PEB" << std::endl;
    return false;
  }

  // 读取 ProcessParameters 地址
  RTL_USER_PROCESS_PARAMETERS processParameters;
  if (!ReadProcessMemory(hProcess, peb.ProcessParameters, &processParameters, sizeof(processParameters), &bytesRead)) {
    std::wcerr << L"无法读取 ProcessParameters" << std::endl;
    return false;
  }

  // 读取 ImagePathName
  WCHAR imagePath[MAX_PATH] = { 0 };
  if (!ReadProcessMemory(hProcess, processParameters.ImagePathName.Buffer, imagePath, processParameters.ImagePathName.Length, &bytesRead)) {
    std::wcerr << L"无法读取 ImagePathName" << std::endl;
    return false;
  }

  std::wcout << L"进程 ImagePathName: " << imagePath << std::endl;
  return true;
}

int main() {
  //std::wstring processName = L"notepad.exe"; // 目标进程名

  //DWORD pid = GetProcessIdByPath(processName);
  //if (pid == 0) {
  //  std::wcerr << L"找不到进程：" << processName << std::endl;
  //  return 1;
  //}
  DWORD pid = 6392;
  HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
  if (!hProcess) {
    std::wcerr << L"无法打开进程，错误码: " << GetLastError() << std::endl;
    return 1;
  }

  std::wcout << L"目标进程 PID: " << pid << std::endl;

  if (!GetPEBImagePath(hProcess)) {
    std::wcerr << L"获取 PEB ImagePathName 失败" << std::endl;
  }

  CloseHandle(hProcess);
  return 0;
}
