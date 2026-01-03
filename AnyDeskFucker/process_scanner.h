#pragma once
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <vector>
#include <string>

class ProcessScanner {
public:
    ProcessScanner();
    void setConsoleVisible(bool visible);
    void scanAndFreezeLoop(int intervalSeconds = 1);
    void scanAndFreezeAnydesk();

private:
    bool checkForAnyDesk(DWORD pid);
    bool checkForModule(DWORD pid, const std::string& targetModule);
    bool checkForProcessName(DWORD pid, const std::string& targetName);
    bool checkForWindowTitle(DWORD pid, const std::string& targetTitle);
    bool checkMemoryForString(DWORD pid, const std::string& targetString);
    bool checkForTempPath(DWORD pid);
    std::vector<DWORD> getAllProcesses();
    void freezeProcessThreads(DWORD pid);
    HANDLE openProcessWithDebugPrivilege(DWORD pid);
    std::string getProcessName(DWORD pid);
    std::string getProcessPath(DWORD pid);
    std::string toLower(const std::string& str);
};