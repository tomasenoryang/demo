#include <iostream>
#include <cstdlib>
#include <string>
#include <unistd.h>
#include <pwd.h>

// 封装 popen 和 fgets 逻辑的通用函数
std::string executeCommand(const std::string& command) {
    char buffer[128];
    std::string result = "";
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

// 使用 executeCommand 获取 gsettings 字符串值，并去除单引号
std::string getGSettingsString(const std::string& schema, const std::string& key, const std::string& user) {
    std::string command = "sudo -u " + user + " gsettings get " + schema + " " + key;
    std::string result = executeCommand(command);

    // 去掉开始和结束的单引号
    if (!result.empty() && result.front() == '\'' && result.back() == '\'') {
        result = result.substr(1, result.size() - 2);
    }

    return result;
}

// 使用 executeCommand 获取 gsettings 整数值
int getGSettingsInt(const std::string& schema, const std::string& key, const std::string& user) {
    std::string command = "sudo -u " + user + " gsettings get " + schema + " " + key;
    std::string result = executeCommand(command);

    if (result.empty()) {
        return -1; // 返回一个无效值
    }

    return std::stoi(result);
}

// 获取代理设置
void getProxySettings(const std::string& user) {
    std::string proxy_status = getGSettingsString("org.gnome.system.proxy", "mode", user);
    std::string httpHost = getGSettingsString("org.gnome.system.proxy.http", "host", user);
    int httpPort = getGSettingsInt("org.gnome.system.proxy.http", "port", user);
    std::string httpsHost = getGSettingsString("org.gnome.system.proxy.https", "host", user);
    int httpsPort = getGSettingsInt("org.gnome.system.proxy.https", "port", user);

    std::cout << "Proxy Status: " << proxy_status << std::endl;
    std::cout << "HTTP Proxy Host: " << httpHost << std::endl;
    std::cout << "HTTP Proxy Port: " << httpPort << std::endl;
    std::cout << "HTTPS Proxy Host: " << httpsHost << std::endl;
    std::cout << "HTTPS Proxy Port: " << httpsPort << std::endl;
}

int main() {
    const char* sudo_user = std::getenv("SUDO_USER");
    if (!sudo_user) {
        std::cerr << "未找到 SUDO_USER 环境变量，请使用 sudo 运行程序" << std::endl;
        return 1;
    }

    // 通过 sudo 用户获取设置
    getProxySettings(sudo_user);

    int i = 0;
    while (true) {
        std::cout << "========" << i << "========" << std::endl;
        getProxySettings("yangsen");
        sleep(1);
        i++;
    }

    return 0;
}
// g++ get_proxy_settings_by_gsettings.cc -o get_proxy_settings_by_gsettings