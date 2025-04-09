#include<iostream>
#include<windows.h>
#include <netfw.h>
#include <comutil.h>
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

int main() {
  FWRuleParams params = {
      L"Sample Rule",
      L"Allow inbound traffic on port 12345",
      NET_FW_IP_PROTOCOL_ANY,
      L"",
      NET_FW_RULE_DIR_OUT,
      NET_FW_ACTION_ALLOW,
      VARIANT_TRUE,
      L"C:\\Path\\To\\YourApplication.exe" // 设置应用程序路径
  };

  int32_t result = AddFWRule(params);
  if (FAILED(result)) {
    std::cerr << "AddFWRule failed with error: " << result << std::endl;
  }
  else {
    std::cout << "Firewall rule added successfully." << std::endl;
  }
  return 0;
}
