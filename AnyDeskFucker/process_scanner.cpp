#include "process_scanner.h"
#include <algorithm>
#include <thread>
#include <chrono>
#include <shlwapi.h>
#pragma comment(lib, "shlwapi.lib")

ProcessScanner::ProcessScanner() {
}

void ProcessScanner::setConsoleVisible(bool visible) {
    if (visible) {
        AllocConsole();
        FILE* f;
        freopen_s(&f, "CONOUT$", "w", stdout);
        freopen_s(&f, "CONOUT$", "w", stderr);
        freopen_s(&f, "CONIN$", "r", stdin);
    }
    else {
        FreeConsole();
    }
}

std::string ProcessScanner::toLower(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::tolower);
    return result;
}

std::vector<DWORD> ProcessScanner::getAllProcesses() {
    std::vector<DWORD> processes;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(snapshot, &pe32)) {
            do {
                processes.push_back(pe32.th32ProcessID);
            } while (Process32Next(snapshot, &pe32));
        }
        CloseHandle(snapshot);
    }
    return processes;
}

std::string ProcessScanner::getProcessName(DWORD pid) {
    HANDLE hProcess = openProcessWithDebugPrivilege(pid);
    if (!hProcess) return "";

    char procName[MAX_PATH] = { 0 };
    if (GetModuleBaseNameA(hProcess, NULL, procName, MAX_PATH)) {
        CloseHandle(hProcess);
        return toLower(procName);
    }
    CloseHandle(hProcess);
    return "";
}

std::string ProcessScanner::getProcessPath(DWORD pid) {
    HANDLE hProcess = openProcessWithDebugPrivilege(pid);
    if (!hProcess) return "";

    char procPath[MAX_PATH] = { 0 };
    if (GetModuleFileNameExA(hProcess, NULL, procPath, MAX_PATH)) {
        CloseHandle(hProcess);
        return toLower(procPath);
    }
    CloseHandle(hProcess);
    return "";
}

bool ProcessScanner::checkForModule(DWORD pid, const std::string& targetModule) {
    HANDLE hProcess = openProcessWithDebugPrivilege(pid);
    if (!hProcess) return false;

    HMODULE hModules[1024];
    DWORD cbNeeded;

    if (EnumProcessModules(hProcess, hModules, sizeof(hModules), &cbNeeded)) {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            char modName[MAX_PATH];
            if (GetModuleFileNameExA(hProcess, hModules[i], modName, sizeof(modName))) {
                std::string moduleName = toLower(modName);
                if (moduleName.find(targetModule) != std::string::npos) {
                    CloseHandle(hProcess);
                    return true;
                }
            }
        }
    }
    CloseHandle(hProcess);
    return false;
}

bool ProcessScanner::checkForProcessName(DWORD pid, const std::string& targetName) {
    std::string procName = getProcessName(pid);
    if (procName.empty()) return false;

    std::string targetLower = toLower(targetName);
    return procName.find(targetLower) != std::string::npos;
}

bool ProcessScanner::checkForTempPath(DWORD pid) {
    std::string procPath = getProcessPath(pid);
    if (procPath.empty()) return false;

    char tempPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);
    std::string tempPathLower = toLower(tempPath);

    return procPath.find(tempPathLower) != std::string::npos;
}

bool ProcessScanner::checkMemoryForString(DWORD pid, const std::string& targetString) {
    HANDLE hProcess = openProcessWithDebugPrivilege(pid);
    if (!hProcess) return false;

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    MEMORY_BASIC_INFORMATION memInfo;
    unsigned char* addr = 0;
    std::string targetLower = toLower(targetString);

    while (VirtualQueryEx(hProcess, addr, &memInfo, sizeof(memInfo))) {
        bool isReadable = (memInfo.Protect == PAGE_READONLY ||
            memInfo.Protect == PAGE_READWRITE ||
            memInfo.Protect == PAGE_EXECUTE_READ ||
            memInfo.Protect == PAGE_EXECUTE_READWRITE ||
            memInfo.Protect == PAGE_WRITECOPY ||
            memInfo.Protect == PAGE_EXECUTE_WRITECOPY);

        if (memInfo.State == MEM_COMMIT && isReadable) {
            SIZE_T bytesRead;
            std::vector<char> buffer(memInfo.RegionSize);

            if (ReadProcessMemory(hProcess, memInfo.BaseAddress, buffer.data(), memInfo.RegionSize, &bytesRead)) {
                std::string regionContent(buffer.begin(), buffer.begin() + bytesRead);
                std::string regionLower = toLower(regionContent);

                if (regionLower.find(targetLower) != std::string::npos) {
                    CloseHandle(hProcess);
                    return true;
                }
            }
        }
        addr += memInfo.RegionSize;
    }

    CloseHandle(hProcess);
    return false;
}

bool ProcessScanner::checkForWindowTitle(DWORD pid, const std::string& targetTitle) {
    std::vector<HWND> windows;

    EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
        auto& windows = *reinterpret_cast<std::vector<HWND>*>(lParam);
        windows.push_back(hwnd);
        return TRUE;
        }, reinterpret_cast<LPARAM>(&windows));

    for (HWND hwnd : windows) {
        DWORD windowPid;
        GetWindowThreadProcessId(hwnd, &windowPid);

        if (windowPid == pid) {
            char title[256];
            if (GetWindowTextA(hwnd, title, sizeof(title))) {
                std::string titleStr = toLower(title);
                std::string targetLower = toLower(targetTitle);

                if (titleStr.find(targetLower) != std::string::npos) {
                    return true;
                }
            }
        }
    }

    return false;
}

bool ProcessScanner::checkForAnyDesk(DWORD pid) {
    if (checkForModule(pid, "gcapi.dll")) return true;
    if (checkForModule(pid, "anydesk")) return true;

    if (checkForProcessName(pid, "anydesk")) return true;


    if (checkForWindowTitle(pid, "anydesk")) return true;

    std::string procPath = getProcessPath(pid);
    if (!procPath.empty()) {
        if (procPath.find("anydesk") != std::string::npos) return true;
    }

    return false;
}

HANDLE ProcessScanner::openProcessWithDebugPrivilege(DWORD pid) {
    HANDLE hToken;
    TOKEN_PRIVILEGES tkp;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid);
        tkp.PrivilegeCount = 1;
        tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, NULL, 0);
        CloseHandle(hToken);
    }

    return OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_SET_INFORMATION, FALSE, pid);
}

void ProcessScanner::freezeProcessThreads(DWORD pid) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return;

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    if (Thread32First(snapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == pid) {
                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);
                if (hThread) {
                    SuspendThread(hThread);
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(snapshot, &te32));
    }
    CloseHandle(snapshot);
}

void ProcessScanner::scanAndFreezeAnydesk() {
    std::vector<DWORD> processes = getAllProcesses();

    for (DWORD pid : processes) {
        if (checkForAnyDesk(pid)) {
            freezeProcessThreads(pid);
            break;
        }
    }
}

void ProcessScanner::scanAndFreezeLoop(int intervalSeconds) {
    std::vector<DWORD> alreadyFrozen;

    while (true) {
        std::vector<DWORD> processes = getAllProcesses();

        for (DWORD pid : processes) {
            auto it = std::find(alreadyFrozen.begin(), alreadyFrozen.end(), pid);
            if (it != alreadyFrozen.end()) {
                continue;
            }

            if (checkForAnyDesk(pid)) {
                freezeProcessThreads(pid);
                alreadyFrozen.push_back(pid);
            }
        }

        std::this_thread::sleep_for(std::chrono::seconds(intervalSeconds));
    }
}