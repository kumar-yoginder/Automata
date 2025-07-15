#include <windows.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <lmcons.h>
#include <tlhelp32.h>

volatile LONG logEntryCounter = 0;

DWORD GetParentProcessIdForDLL() {
    HANDLE hSnapshot;
    PROCESSENTRY32 pe32;
    DWORD ppid = 0;
    DWORD currentPid = GetCurrentProcessId();

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        return 0;
    }

    do {
        if (pe32.th32ProcessID == currentPid) {
            ppid = pe32.th32ParentProcessID;
            break;
        }
    } while (Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    return ppid;
}

void logging() {
    char currentDir[MAX_PATH];
    char userName[UNLEN + 1];
    DWORD userNameLen = UNLEN + 1;
    DWORD currentPid = GetCurrentProcessId();
    DWORD parentPid = GetParentProcessIdForDLL();
    time_t rawtime;
    struct tm *timeinfo;
    char timestampStr[80];
    FILE *file;
    char logFilePath[MAX_PATH];
    char tempPath[MAX_PATH];
    const char *logFileName = "[yoginder_kumar].log";

    long currentLogId = InterlockedIncrement(&logEntryCounter);

    if (GetCurrentDirectoryA(MAX_PATH, currentDir) == 0)
        strcpy(currentDir, "Error getting CWD");

    if (!GetUserNameA(userName, &userNameLen))
        strcpy(userName, "Error getting user name");

    time(&rawtime);
    timeinfo = localtime(&rawtime);
    strftime(timestampStr, sizeof(timestampStr), "%Y-%m-%d %H:%M:%S", timeinfo);

    DWORD pathLen = GetTempPathA(MAX_PATH, tempPath);
    if (pathLen == 0 || pathLen > MAX_PATH) {
        sprintf(logFilePath, "%s\\%s", currentDir, logFileName);
    } else {
        if (!CreateDirectoryA(tempPath, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
            sprintf(logFilePath, "%s\\%s", currentDir, logFileName);
        } else {
            sprintf(logFilePath, "%s%s", tempPath, logFileName);
        }
    }

    file = fopen(logFilePath, "a+");
    if (file == NULL) return;

    fputs("\n--- Proxy DLL Log Entry ---\n", file);
    fprintf(file, "Log ID: %ld\n", currentLogId);
    fprintf(file, "CWD: %s\n", currentDir);
    fprintf(file, "USER Login: %s\n", userName);
    fprintf(file, "Parent ID is: %lu\n", parentPid);
    fprintf(file, "Process PID: %lu\n", currentPid);
    fprintf(file, "Time Stamp: %s\n", timestampStr);
    fprintf(file, "Action: DLL Loaded.\n");
    fprintf(file, "---------------------------\n");

    fclose(file);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        logging();
    }
    return TRUE;
}