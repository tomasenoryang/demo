#include <iostream>
#include <cstdlib>
#include <string>
#include <unistd.h>
#include <pwd.h>

// 封装 popen 和 fgets 逻辑的通用函数
std::string ExecuteCommand(const std::string& command) {
    char buffer[128];
    std::string result;
    FILE* fp = popen(command.c_str(), "r");
    if (fp == nullptr) {
        std::cerr << "Failed to execute command: " << command << std::endl;
        return result;
    }

    while (fgets(buffer, sizeof(buffer), fp) != nullptr) {
        result += buffer;
    }

    pclose(fp);

    // 移除末尾的换行符
    if (!result.empty() && result.back() == '\n') {
        result.pop_back();
    }

    return result;
}

// 检查 gsettings 是否存在
bool IsGSettingsAvailable() {
    std::string check = ExecuteCommand("command -v gsettings");
    return !check.empty();  // 若命令返回非空，说明 gsettings 存在
}

// 使用 ExecuteCommand 获取 gsettings 字符串值，并去除单引号
std::string GetGSettingsString(const std::string& schema, const std::string& key, const std::string& user) {
    if (!IsGSettingsAvailable()) {
        std::cerr << "Error: gsettings command not found!" << std::endl;
        return "";
    }

    std::string command = "sudo -u " + user + " gsettings get " + schema + " " + key;
    std::string result = ExecuteCommand(command);

    // 去掉开始和结束的单引号
    if (!result.empty() && result.front() == '\'' && result.back() == '\'') {
        result = result.substr(1, result.size() - 2);
    }

    return result;
}

// 使用 ExecuteCommand 获取 gsettings 整数值
int GetGSettingsInt(const std::string& schema, const std::string& key, const std::string& user) {
    if (!IsGSettingsAvailable()) {
        std::cerr << "Error: gsettings command not found!" << std::endl;
        return -1; // 返回一个无效值
    }

    std::string command = "sudo -u " + user + " gsettings get " + schema + " " + key;
    std::string result = ExecuteCommand(command);

    if (result.empty()) {
        return -1; // 返回一个无效值
    }

    return std::stoi(result);
}

// 获取代理设置
void GetProxySettings(const std::string& user) {
/*
    if (!IsGSettingsAvailable()) {
        std::cerr << "Error: gsettings is not available on this system!" << std::endl;
        return;
    }
*/
    std::string proxy_status = GetGSettingsString("org.gnome.system.proxy", "mode", user);
    std::string httpHost = GetGSettingsString("org.gnome.system.proxy.http", "host", user);
    int httpPort = GetGSettingsInt("org.gnome.system.proxy.http", "port", user);
    std::string httpsHost = GetGSettingsString("org.gnome.system.proxy.https", "host", user);
    int httpsPort = GetGSettingsInt("org.gnome.system.proxy.https", "port", user);

    std::cout << "Proxy Status: " << proxy_status << std::endl;
    std::cout << "HTTP Proxy Host: " << httpHost << std::endl;
    std::cout << "HTTP Proxy Port: " << httpPort << std::endl;
    std::cout << "HTTPS Proxy Host: " << httpsHost << std::endl;
    std::cout << "HTTPS Proxy Port: " << httpsPort << std::endl;
}

// 使用 ExecuteCommand 获取当前登录用户名
std::string GetUsername() {
    return ExecuteCommand("w -h | awk '{print $1}' | head -n 1");
}

int main() {
    std::cout << "User: " << GetUsername() << std::endl;

    const char* sudo_user = std::getenv("SUDO_USER");
    if (!sudo_user) {
        std::cerr << "未找到 SUDO_USER 环境变量，请使用 sudo 运行程序" << std::endl;
        return 1;
    }
/*
    // 检查 gsettings 是否可用
    if (!IsGSettingsAvailable()) {
        std::cerr << "gsettings is not installed on this system. Exiting." << std::endl;
        return 1;
    }
*/
    // 通过 sudo 用户获取设置
    GetProxySettings(sudo_user);

    return 0;
}
