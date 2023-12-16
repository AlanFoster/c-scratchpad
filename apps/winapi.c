#include <stdio.h>
#include <winternl.h>
#include <windows.h>
#include <ntstatus.h>

typedef NTSTATUS(NTAPI * NT_QUERY_INFORMATION_PROCESS)(
        IN HANDLE ProcessHandle,
        IN PROCESSINFOCLASS ProcessInformationClass,
        OUT PVOID ProcessInformation,
        IN ULONG ProcessInformationLength,
        OUT PULONG ReturnLength OPTIONAL);

void printLastError() {
    wchar_t buf[256];
    FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                   NULL, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                   buf, (sizeof(buf) / sizeof(wchar_t)), NULL);
    printf("Error: %ls\n", buf);
}

void createMessageBox() {
    MessageBox(
            NULL,
            L"Hello world - header",
            L"Hello world - caption",
            MB_OK
    );
}

int createProcessW() {
    wchar_t lpApplicationName[] = L"C:\\Windows\\notepad.exe";
    wchar_t* lpCommandLine = NULL;
    // Inherit
    LPSECURITY_ATTRIBUTES processAttributes = NULL;
    LPSECURITY_ATTRIBUTES threadAttributes = NULL;
    BOOL bInheritHandles = FALSE;
    DWORD dwCreationFlags = 0;
    LPVOID lpEnvironment = NULL;

    LPCWSTR lpCurrentDirectory = NULL;
    STARTUPINFO startupInfo = { 0 };
    startupInfo.cb = sizeof(startupInfo);
    PROCESS_INFORMATION processInformation = { 0 };
    BOOL success;
    success = CreateProcessW(
            lpApplicationName,
            lpCommandLine,
            processAttributes,
            threadAttributes,
            bInheritHandles,
            dwCreationFlags,
            lpEnvironment,
            lpCurrentDirectory,
            &startupInfo,
            &processInformation
    );

    if (!success) {
        printf("[x] Failed to create process\n");
        goto error;
    }

    printf("dwProcessId=%ld\n", processInformation.dwProcessId);
    printf("dwThreadId=%ld\n", processInformation.dwThreadId);
    printf("hProcess=0x%p\n", processInformation.hProcess);
    printf("hThread=0x%p\n", processInformation.hThread);

    // Wait for child to exit
    WaitForSingleObject(processInformation.hProcess, INFINITE);

    // Close process and thread handles
    CloseHandle(processInformation.hProcess);
    CloseHandle(processInformation.hThread);

    return 0;

error:
    printLastError();
    return 1;
}

int queryProcessInformation() {
    NTSTATUS status;
    PPROCESS_BASIC_INFORMATION processBasicInformation;
    DWORD dwSize;

    HMODULE hNtdll;
    NT_QUERY_INFORMATION_PROCESS hNtQueryInformationProcess;

    hNtdll = LoadLibrary(L"ntdll.dll\0");
    hNtQueryInformationProcess = (NT_QUERY_INFORMATION_PROCESS) GetProcAddress(hNtdll, "NtQueryInformationProcess");

    // First call to determine the size
    status = hNtQueryInformationProcess(
        GetCurrentProcess(),
        ProcessBasicInformation,
        NULL,
        0,
        &dwSize
    );

    if (status != STATUS_INFO_LENGTH_MISMATCH) {
        goto error;
    }

    // Allocate and clear
    processBasicInformation = (PPROCESS_BASIC_INFORMATION) malloc(dwSize);
    RtlZeroMemory(processBasicInformation, dwSize);

    if (!processBasicInformation) {
        goto error;
    }

    // Second call to query the required information
    status = hNtQueryInformationProcess(
            GetCurrentProcess(),
            ProcessBasicInformation,
            processBasicInformation,
            sizeof(PROCESS_BASIC_INFORMATION),
            &dwSize
    );

    if (!NT_SUCCESS(status)) {
        goto error;
    }

    printf("PEB base: 0x%p\n", processBasicInformation->PebBaseAddress);
    free(processBasicInformation);

    return 0;

error:
    printLastError();
    return 1;
}

int main() {
//    createMessageBox();
//    createProcessW();
    queryProcessInformation();
}
