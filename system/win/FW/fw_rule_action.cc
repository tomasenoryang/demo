#include <iostream>
#include <windows.h>
#include <netfw.h>
#include <comutil.h>
#include <string>
#include <vector>
#include <optional>
#include <cstdlib>
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "comsuppw.lib")

struct FWRuleParams {
  std::wstring name;
  std::wstring description;
  long protocol;
  std::wstring localPorts;
  NET_FW_RULE_DIRECTION direction;
  NET_FW_ACTION action;
  VARIANT_BOOL enabled;
  std::wstring applicationName; // 新增字段
};

int32_t AddFWRule(const FWRuleParams& params) {
  HRESULT hrComInit = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
  if (FAILED(hrComInit)) {
    std::cerr << "CoInitializeEx failed: " << hrComInit << std::endl;
    return hrComInit;
  }

  INetFwPolicy2* pNetFwPolicy2 = nullptr;
  HRESULT hr = CoCreateInstance(
    __uuidof(NetFwPolicy2),
    nullptr,
    CLSCTX_INPROC_SERVER,
    __uuidof(INetFwPolicy2),
    (void**)&pNetFwPolicy2
  );

  if (FAILED(hr)) {
    std::cerr << "CoCreateInstance for INetFwPolicy2 failed: " << hr << std::endl;
    CoUninitialize();
    return hr;
  }

  INetFwRule* pFwRule = nullptr;
  hr = CoCreateInstance(
    __uuidof(NetFwRule),
    nullptr,
    CLSCTX_INPROC_SERVER,
    __uuidof(INetFwRule),
    (void**)&pFwRule
  );

  if (FAILED(hr)) {
    std::cerr << "CoCreateInstance for INetFwRule failed: " << hr << std::endl;
    pNetFwPolicy2->Release();
    CoUninitialize();
    return hr;
  }

  pFwRule->put_Name(_bstr_t(params.name.c_str()));
  pFwRule->put_Description(_bstr_t(params.description.c_str()));
  pFwRule->put_Protocol(params.protocol);
  pFwRule->put_LocalPorts(_bstr_t(params.localPorts.c_str()));
  pFwRule->put_Direction(params.direction);
  pFwRule->put_Action(params.action);
  pFwRule->put_Enabled(params.enabled);
  pFwRule->put_ApplicationName(_bstr_t(params.applicationName.c_str())); // 设置应用程序名称

  INetFwRules* pFwRules = nullptr;
  hr = pNetFwPolicy2->get_Rules(&pFwRules);
  if (FAILED(hr)) {
    std::cerr << "Failed to get firewall rules: " << hr << std::endl;
    pFwRule->Release();
    pNetFwPolicy2->Release();
    CoUninitialize();
    return hr;
  }

  hr = pFwRules->Add(pFwRule);
  if (FAILED(hr)) {
    std::cerr << "Failed to add firewall rule: " << hr << std::endl;
  }

  pFwRules->Release();
  pFwRule->Release();
  pNetFwPolicy2->Release();
  CoUninitialize();

  return hr;
}

int32_t RemoveFWRule(const std::wstring& ruleName) {
  HRESULT hrComInit = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
  if (FAILED(hrComInit)) {
    std::cerr << "CoInitializeEx failed: " << hrComInit << std::endl;
    return hrComInit;
  }

  INetFwPolicy2* pNetFwPolicy2 = nullptr;
  HRESULT hr = CoCreateInstance(
    __uuidof(NetFwPolicy2),
    nullptr,
    CLSCTX_INPROC_SERVER,
    __uuidof(INetFwPolicy2),
    (void**)&pNetFwPolicy2
  );

  if (FAILED(hr)) {
    std::cerr << "CoCreateInstance for INetFwPolicy2 failed: " << hr << std::endl;
    CoUninitialize();
    return hr;
  }

  INetFwRules* pFwRules = nullptr;
  hr = pNetFwPolicy2->get_Rules(&pFwRules);
  if (FAILED(hr)) {
    std::cerr << "Failed to get firewall rules: " << hr << std::endl;
    pNetFwPolicy2->Release();
    CoUninitialize();
    return hr;
  }

  long ruleCount = 0;
  hr = pFwRules->get_Count(&ruleCount);
  if (FAILED(hr)) {
    std::cerr << "Failed to get firewall rule count: " << hr << std::endl;
    pFwRules->Release();
    pNetFwPolicy2->Release();
    CoUninitialize();
    return hr;
  }

  IUnknown* pEnumerator = nullptr;
  hr = pFwRules->get__NewEnum(&pEnumerator);
  if (FAILED(hr)) {
    std::cerr << "Failed to get firewall rule enumerator: " << hr << std::endl;
    pFwRules->Release();
    pNetFwPolicy2->Release();
    CoUninitialize();
    return hr;
  }

  IEnumVARIANT* pVariant = nullptr;
  hr = pEnumerator->QueryInterface(__uuidof(IEnumVARIANT), (void**)&pVariant);
  pEnumerator->Release();
  if (FAILED(hr)) {
    std::cerr << "Failed to get IEnumVARIANT interface: " << hr << std::endl;
    pFwRules->Release();
    pNetFwPolicy2->Release();
    CoUninitialize();
    return hr;
  }

  VARIANT var;
  VariantInit(&var);
  while (pVariant->Next(1, &var, nullptr) == S_OK) {
    if (var.vt == VT_DISPATCH) {
      INetFwRule* pFwRule = nullptr;
      hr = var.pdispVal->QueryInterface(__uuidof(INetFwRule), (void**)&pFwRule);
      if (SUCCEEDED(hr)) {
        BSTR bstrName;
        pFwRule->get_Name(&bstrName);
        if (ruleName == bstrName) {
          hr = pFwRules->Remove(bstrName);
          if (FAILED(hr)) {
            std::cerr << "Failed to remove firewall rule: " << hr << std::endl;
          }
        }
        SysFreeString(bstrName);
        pFwRule->Release();
      }
    }
    VariantClear(&var);
  }

  pVariant->Release();
  pFwRules->Release();
  pNetFwPolicy2->Release();
  CoUninitialize();

  return S_OK;
}

std::optional<std::wstring> GetArgValue(const std::vector<std::wstring>& args, const std::wstring& argName) {
  auto it = std::find(args.begin(), args.end(), argName);
  if (it != args.end() && ++it != args.end()) {
    return *it;
  }
  return std::nullopt;
}

void PrintHelp() {
  std::wcout << L"Usage: FW_WIN32.exe <add|remove> [options]\n"
    << L"Options:\n"
    << L"  --name <name>               Name of the firewall rule\n"
    << L"  --description <description> Description of the firewall rule\n"
    << L"  --protocol <protocol>       Protocol (e.g., 6 for TCP, 17 for UDP)\n"
    << L"  --localPorts <ports>        Local ports (e.g., \"80,443\")\n"
    << L"  --direction <direction>     Direction (1 for IN, 2 for OUT)\n"
    << L"  --action <action>           Action (0 for BLOCK, 1 for ALLOW)\n"
    << L"  --enabled <enabled>         Enabled (-1 for TRUE, 0 for FALSE)\n"
    << L"  --applicationName <path>    Path to the application\n"
    << L"  -h, --help                  Show this help message\n"
    << L"\nExamples:\n"
    << L"  FW_WIN32.exe remove --name \"Sample Rule\"\n"
    << L"  FW_WIN32.exe add --name \"Sample Rule\" --description \"Allow inbound traffic on port 12345\" --protocol 6 --localPorts \"12345\" --direction 1 --action 1 --enabled -1 --applicationName \"C:\\Path\\To\\YourApplication.exe\"\n";
}

int wmain(int argc, wchar_t* argv[]) {
  std::vector<std::wstring> args(argv, argv + argc);

  if (args.size() < 2 || args[1] == L"-h" || args[1] == L"--help") {
    PrintHelp();
    return 0;
  }

  std::wstring command = args[1];
  FWRuleParams params;
  params.name = GetArgValue(args, L"--name").value_or(L"");
  params.description = GetArgValue(args, L"--description").value_or(L"");
  params.protocol = GetArgValue(args, L"--protocol").has_value() ? std::wcstol(GetArgValue(args, L"--protocol")->c_str(), nullptr, 10) : 0;
  params.localPorts = GetArgValue(args, L"--localPorts").value_or(L"");
  params.direction = GetArgValue(args, L"--direction").has_value() ? static_cast<NET_FW_RULE_DIRECTION>(std::wcstol(GetArgValue(args, L"--direction")->c_str(), nullptr, 10)) : NET_FW_RULE_DIR_IN;
  params.action = GetArgValue(args, L"--action").has_value() ? static_cast<NET_FW_ACTION>(std::wcstol(GetArgValue(args, L"--action")->c_str(), nullptr, 10)) : NET_FW_ACTION_ALLOW;

  // 处理 --enabled 参数
  if (auto enabledStr = GetArgValue(args, L"--enabled")) {
    int enabledValue = std::wcstol(enabledStr->c_str(), nullptr, 10);
    if (enabledValue == VARIANT_TRUE) {
      params.enabled = VARIANT_TRUE;
    }
    else if (enabledValue == VARIANT_FALSE) {
      params.enabled = VARIANT_FALSE;
    }
    else {
      std::wcerr << L"Invalid value for --enabled. Use " << VARIANT_FALSE << L" for FALSE or " << VARIANT_TRUE << L" for TRUE." << std::endl;
      return 1;
    }
  }
  else {
    params.enabled = VARIANT_TRUE; // 默认值
  }

  params.applicationName = GetArgValue(args, L"--applicationName").value_or(L"");

  int32_t result = 0;
  if (command == L"add") {
    result = AddFWRule(params);
    if (FAILED(result)) {
      std::cerr << "AddFWRule failed with error: " << result << std::endl;
    }
    else {
      std::cout << "Firewall rule added successfully." << std::endl;
    }
  }
  else if (command == L"remove") {
    result = RemoveFWRule(params.name);
    if (FAILED(result)) {
      std::cerr << "RemoveFWRule failed with error: " << result << std::endl;
    }
    else {
      std::cout << "Firewall rule removed successfully." << std::endl;
    }
  }
  else {
    std::wcerr << L"Unknown command: " << command << std::endl;
    PrintHelp();
    return 1;
  }

  return 0;
}
