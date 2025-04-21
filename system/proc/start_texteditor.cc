#ifdef _WIN32
#include <windows.h>
typedef DWORD pid_t;
#elif __APPLE__
#include <unistd.h>
#include <spawn.h>
#include <sys/types.h>
extern char** environ;
#elif __linux__
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#endif
#ifndef _WIN32
static pid_t GetProcessPIDByName(const std::string& processName) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "pgrep -x %s", processName.c_str());

    FILE* fp = popen(cmd, "r");
    if (!fp) return 0;

    char buffer[128];
    if (fgets(buffer, sizeof(buffer), fp) != nullptr) {
        pid_t pid = atoi(buffer);
        pclose(fp);
        return pid;
    }

    pclose(fp);
    return 0;
}

#endif // !_WIN32
static pid_t StartTextEditor() {
#ifdef _WIN32
    STARTUPINFOA si = { sizeof(STARTUPINFO) };
    PROCESS_INFORMATION pi;
    BOOL result = CreateProcessA(
        "C:\\Windows\\System32\\notepad.exe",
        NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi
    );

    if (result) {
        pid_t pid = pi.dwProcessId;
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return pid;
    } else {
        std::cerr << "Failed to start Notepad." << std::endl;
        return 0;
    }

#elif __APPLE__
    pid_t spawnPid;
    char* argv[] = { (char*)"open", (char*)"-a", (char*)"TextEdit", NULL };
    int status = posix_spawn(&spawnPid, "/usr/bin/open", NULL, NULL, argv, environ);
    if (status != 0) {
        std::cerr << "Failed to start TextEdit." << std::endl;
        return 0;
    }

    // 等待 TextEdit 启动
    sleep(1);

    // 获取 TextEdit 的 PID
    return GetProcessPIDByName("TextEdit");

#elif __linux__
    pid_t pid = fork();
    if (pid == 0) {
        execlp("gedit", "gedit", NULL); // 或其他文本编辑器：kate、leafpad等
        _exit(1);
    } else if (pid > 0) {
        return pid;
    } else {
        std::cerr << "Failed to fork." << std::endl;
        return 0;
    }
#endif
}