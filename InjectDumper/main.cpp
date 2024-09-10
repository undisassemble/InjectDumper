#include <Windows.h>
#include <TlHelp32.h>
#pragma comment(lib, "User32.lib")

// RtlUserThreadStart hook
#ifdef _WIN64
DWORD dwHookOff = 2;
BYTE hook[] = {
	0x48, 0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,		// mov rax, 0xFFFFFFFFFFFFFFFF
	0xFF, 0xE0														// jmp rax
};
#else
DWORD dwHookOff = 1;
BYTE hook[] = {
	0xB8, 0xFF, 0xFF, 0xFF, 0xFF,									// mov eax, 0xFFFFFFFF
	0xFF, 0xE0														// jmp eax
};
#endif

// Console logging stuff
#define GOOD  "\x1B[32m[+]\x1B[39m "
#define BAD   "\x1B[31m[-]\x1B[39m "
#define EXTRA "    :.. "

// Globals
HANDLE hStdout;
void* AllocatedMemory[256] = { 0 };
void* TempAllocatedMemory[256] = { 0 };
char MutexName[MAX_PATH] = { 0 };
int iThreadBytes = -1;
DWORD dwMainThreadId = 0;

// Some utility stuff
namespace Funcs {
	void* pRtlUserThreadStart = NULL;
	void* pLdrLoadDll = NULL;
	void* pLoadLibraryA = NULL;
	void* pLoadLibraryExA = NULL;
	void* pLoadLibraryW = NULL;
	void* pLoadLibraryExW = NULL;
}

// Forwards
bool hkRtlUserThreadStart(void* pRoutine, void* Param1);
void hkLoadLibraryW(wchar_t* pDll);
void hkLoadLibraryA(char* pDll);
void CheckAllocatedMemory(bool bDump = true, bool bJustStrip = false);
void RemoveFreedBlocks();


/*** Utility functions ***/
void VerifyHooks(bool bSetup = false) {
	DWORD dwOldProtect = 0;

	// RtlUserThreadStart
	*reinterpret_cast<void**>(&hook[dwHookOff]) = hkRtlUserThreadStart;
	if (bSetup || memcmp(Funcs::pRtlUserThreadStart, hook, sizeof(hook))) {
		if (!VirtualProtect(Funcs::pRtlUserThreadStart, sizeof(hook), PAGE_EXECUTE_READWRITE, &dwOldProtect)) {
			WriteConsole(hStdout, BAD "Failed to change protections on RtlUserThreadStart\n", lstrlen(BAD "Failed to change protections on RtlUserThreadStart\n"), NULL, NULL);
			Sleep(INFINITE);
			exit(1);
		}
		CopyMemory(Funcs::pRtlUserThreadStart, hook, sizeof(hook));
		VirtualProtect(Funcs::pRtlUserThreadStart, sizeof(hook), dwOldProtect, &dwOldProtect);
		WriteConsole(hStdout, GOOD "Hooked RtlUserThreadStart\n", lstrlen(GOOD "Hooked RtlUserThreadStart\n"), NULL, NULL);
	}
	
	// LdrLoadDll
	*reinterpret_cast<void**>(&hook[dwHookOff]) = hkLoadLibraryW;
	if (bSetup || memcmp(Funcs::pLdrLoadDll, hook, sizeof(hook))) {
		if (!VirtualProtect(Funcs::pLdrLoadDll, sizeof(hook), PAGE_EXECUTE_READWRITE, &dwOldProtect)) {
			WriteConsole(hStdout, BAD "Failed to change protections on LdrLoadDll\n", lstrlen(BAD "Failed to change protections on LdrLoadDll\n"), NULL, NULL);
			Sleep(INFINITE);
			exit(1);
		}
		CopyMemory(Funcs::pLdrLoadDll, hook, sizeof(hook));
		VirtualProtect(Funcs::pLdrLoadDll, sizeof(hook), dwOldProtect, &dwOldProtect);
		WriteConsole(hStdout, GOOD "Hooked LdrLoadDll\n", lstrlen(GOOD "Hooked LdrLoadDll\n"), NULL, NULL);
	}

	// LoadLibraryW
	if (bSetup || memcmp(Funcs::pLoadLibraryW, hook, sizeof(hook))) {
		if (!VirtualProtect(Funcs::pLoadLibraryW, sizeof(hook), PAGE_EXECUTE_READWRITE, &dwOldProtect)) {
			WriteConsole(hStdout, BAD "Failed to change protections on LoadLibraryW\n", lstrlen(BAD "Failed to change protections on LoadLibraryW\n"), NULL, NULL);
			Sleep(INFINITE);
			exit(1);
		}
		CopyMemory(Funcs::pLoadLibraryW, hook, sizeof(hook));
		VirtualProtect(Funcs::pLoadLibraryW, sizeof(hook), dwOldProtect, &dwOldProtect);
		WriteConsole(hStdout, GOOD "Hooked LoadLibraryW\n", lstrlen(GOOD "Hooked LoadLibraryW\n"), NULL, NULL);
	}

	// LoadLibraryExW
	if (bSetup || memcmp(Funcs::pLoadLibraryExW, hook, sizeof(hook))) {
		if (!VirtualProtect(Funcs::pLoadLibraryExW, sizeof(hook), PAGE_EXECUTE_READWRITE, &dwOldProtect)) {
			WriteConsole(hStdout, BAD "Failed to change protections on LoadLibraryExW\n", lstrlen(BAD "Failed to change protections on LoadLibraryExW\n"), NULL, NULL);
			Sleep(INFINITE);
			exit(1);
		}
		CopyMemory(Funcs::pLoadLibraryExW, hook, sizeof(hook));
		VirtualProtect(Funcs::pLoadLibraryExW, sizeof(hook), dwOldProtect, &dwOldProtect);
		WriteConsole(hStdout, GOOD "Hooked LoadLibraryExW\n", lstrlen(GOOD "Hooked LoadLibraryExW\n"), NULL, NULL);
	}

	// LoadLibraryA
	*reinterpret_cast<void**>(&hook[dwHookOff]) = hkLoadLibraryA;
	if (bSetup || memcmp(Funcs::pLoadLibraryA, hook, sizeof(hook))) {
		if (!VirtualProtect(Funcs::pLoadLibraryA, sizeof(hook), PAGE_EXECUTE_READWRITE, &dwOldProtect)) {
			WriteConsole(hStdout, BAD "Failed to change protections on LoadLibraryA\n", lstrlen(BAD "Failed to change protections on LoadLibraryA\n"), NULL, NULL);
			Sleep(INFINITE);
			exit(1);
		}
		CopyMemory(Funcs::pLoadLibraryA, hook, sizeof(hook));
		VirtualProtect(Funcs::pLoadLibraryA, sizeof(hook), dwOldProtect, &dwOldProtect);
		WriteConsole(hStdout, GOOD "Hooked LoadLibraryA\n", lstrlen(GOOD "Hooked LoadLibraryA\n"), NULL, NULL);
	}

	// LoadLibraryExA
	if (bSetup || memcmp(Funcs::pLoadLibraryExA, hook, sizeof(hook))) {
		if (!VirtualProtect(Funcs::pLoadLibraryExA, sizeof(hook), PAGE_EXECUTE_READWRITE, &dwOldProtect)) {
			WriteConsole(hStdout, BAD "Failed to change protections on LoadLibraryExA\n", lstrlen(BAD "Failed to change protections on LoadLibraryExA\n"), NULL, NULL);
			Sleep(INFINITE);
			exit(1);
		}
		CopyMemory(Funcs::pLoadLibraryExA, hook, sizeof(hook));
		VirtualProtect(Funcs::pLoadLibraryExA, sizeof(hook), dwOldProtect, &dwOldProtect);
		WriteConsole(hStdout, GOOD "Hooked LoadLibraryExA\n", lstrlen(GOOD "Hooked LoadLibraryExA\n"), NULL, NULL);
	}
}

bool MatchesPattern(void* pMem, BYTE* pPattern, char* pMask) {
	for (int i = 0, n = lstrlen(pMask); i < n; i++) {
		if (pMask[i] != '?' && reinterpret_cast<BYTE*>(pMem)[i] != pPattern[i]) {
			return false;
		}
	}

	return true;
}

void AttemptPERecovery(BYTE* pPE) {
	// Headers
	IMAGE_DOS_HEADER* pDosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(pPE);
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return;
	IMAGE_NT_HEADERS* pNtHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(pPE + pDosHeader->e_lfanew);
	if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE || pNtHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC) return;
	IMAGE_SECTION_HEADER* pSectionHeaders = reinterpret_cast<IMAGE_SECTION_HEADER*>(pPE + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));

	// Create file
	char FileName[124] = { 0 };
	wsprintf(FileName, "%p.%s", pPE, (pNtHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL) ? "dll" : "exe");
	HANDLE hDumped = CreateFile(FileName, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (!hDumped || hDumped == INVALID_HANDLE_VALUE) return;

	WriteFile(hDumped, pPE, pNtHeaders->OptionalHeader.SizeOfHeaders, NULL, NULL);

	// Write sections
	DWORD dwCurrentOffset = pNtHeaders->OptionalHeader.SizeOfHeaders;
	void* pZero = NULL;
	for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
		// Skip sections without raw data
		if (!pSectionHeaders[i].PointerToRawData || !pSectionHeaders[i].SizeOfRawData) continue;
		
		// Error check
		if (pSectionHeaders[i].PointerToRawData < dwCurrentOffset) {
			CloseHandle(hDumped);
			DeleteFile(FileName);
			return;
		}

		// Write padding
		pZero = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pSectionHeaders[i].PointerToRawData - dwCurrentOffset);
		WriteFile(hDumped, pZero, pSectionHeaders[i].PointerToRawData - dwCurrentOffset, NULL, NULL);
		HeapFree(GetProcessHeap(), 0, pZero);
		dwCurrentOffset = pSectionHeaders[i].PointerToRawData;

		// Write section data
		if (pSectionHeaders[i].SizeOfRawData && pSectionHeaders[i].Misc.VirtualSize) {
			WriteFile(hDumped, pPE + pSectionHeaders[i].VirtualAddress, pSectionHeaders[i].SizeOfRawData, NULL, NULL);
			dwCurrentOffset += pSectionHeaders[i].SizeOfRawData;
		}
	}

	CloseHandle(hDumped);
	wsprintf(FileName, GOOD "Recovered PE at %p\n", pPE);
	WriteConsole(hStdout, FileName, lstrlen(FileName), NULL, NULL);
}

// This combined with DEP and stripping execution permissions from allocated memory *should* catch thread hijacking
LONG ExceptionHandler(EXCEPTION_POINTERS* pException) {
	if (pException->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && pException->ExceptionRecord->ExceptionInformation[0] == 8) {
		char buf[124];
		wsprintf(buf, GOOD "Caught possible thread hijacking injection at %p\n", pException->ExceptionRecord->ExceptionAddress);
		WriteConsoleA(hStdout, buf, lstrlen(buf), NULL, NULL);
		CheckAllocatedMemory();

		// Dump the attempted shellcode
		if (iThreadBytes) {
			wsprintf(buf, "Thread_%p.bin", pException->ExceptionRecord->ExceptionAddress);
			HANDLE hFile = CreateFile(buf, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
			if (hFile && hFile != INVALID_HANDLE_VALUE) {
				WriteFile(hFile, pException->ExceptionRecord->ExceptionAddress, iThreadBytes, NULL, NULL);
				CloseHandle(hFile);
			}
		}
		
		// If it hijacked the main thread, take over the main threads job
		if (GetCurrentThreadId() == dwMainThreadId) {
			while (1) {
				RemoveFreedBlocks();
				CheckAllocatedMemory(false, true);
				Sleep(1);
			}
		}
		exit(0);
	}
	return EXCEPTION_CONTINUE_EXECUTION;
}


/*** Memory indexing functions ***/
void CheckAllocatedMemory(bool bDump, bool bJustStrip) {
	char buf[124] = { 0 };
	HANDLE hFile = NULL;
	void* CurrentAddress = NULL;
	MEMORY_BASIC_INFORMATION MemInfo = { 0 };
	int i = 0, j = 0;
	BOOL bSuccess = false;
	DWORD dwBytesWritten = 0;
	DWORD dwMemProtection = 0;

	ZeroMemory(TempAllocatedMemory, sizeof(TempAllocatedMemory));

	while (VirtualQuery(CurrentAddress, &MemInfo, sizeof(MemInfo))) {
		// Skip if memory is invalid or just indexing memory
		if (MemInfo.State == MEM_FREE) goto double_skip;
		if (!bDump || MemInfo.State == MEM_RESERVE || MemInfo.Type & MEM_IMAGE || MemInfo.Type & MEM_MAPPED) goto skip;

		// Check if memory is already indexed
		for (j = 0; AllocatedMemory[j]; j++) {
			if (AllocatedMemory[j] == MemInfo.BaseAddress) goto skip;
		}

		// Dump memory & strip execute permissions
		VirtualProtect(MemInfo.BaseAddress, MemInfo.RegionSize, PAGE_READWRITE, &dwMemProtection);
		if (bJustStrip) {
			if (dwMemProtection == PAGE_EXECUTE || dwMemProtection == PAGE_EXECUTE_READ || dwMemProtection == PAGE_EXECUTE_READWRITE || dwMemProtection == PAGE_EXECUTE_WRITECOPY) {
				wsprintf(buf, GOOD "Stripped executable permissions from %p\n", MemInfo.BaseAddress);
				WriteConsole(hStdout, buf, lstrlen(buf), NULL, NULL);
			}
			goto skip;
		}
		wsprintf(buf, "%p-%p.bin", MemInfo.BaseAddress, reinterpret_cast<BYTE*>(MemInfo.BaseAddress) + MemInfo.RegionSize);
		hFile = CreateFile(buf, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		bSuccess = WriteFile(hFile, MemInfo.BaseAddress, MemInfo.RegionSize, &dwBytesWritten, NULL);
		CloseHandle(hFile);

		// Log
		if (bSuccess && dwBytesWritten) {
			wsprintf(buf, GOOD "Dumped allocated memory (range: %p - %p)\n", MemInfo.BaseAddress, reinterpret_cast<BYTE*>(MemInfo.BaseAddress) + MemInfo.RegionSize);
		} else {
			DeleteFile(buf);
			wsprintf(buf, BAD "Detected allocated memory, but it was not dumped (range: %p - %p)\n", MemInfo.BaseAddress, reinterpret_cast<BYTE*>(MemInfo.BaseAddress) + MemInfo.RegionSize);
		}
		WriteConsole(hStdout, buf, lstrlen(buf), NULL, NULL);
		if (dwMemProtection == PAGE_EXECUTE || dwMemProtection == PAGE_EXECUTE_READ || dwMemProtection == PAGE_EXECUTE_READWRITE || dwMemProtection == PAGE_EXECUTE_WRITECOPY) {
			WriteConsole(hStdout, EXTRA "Was executable memory\n", lstrlen(EXTRA "Was executable memory\n"), NULL, NULL);
		}
		if (*reinterpret_cast<WORD*>(MemInfo.BaseAddress) == IMAGE_DOS_SIGNATURE) {
			WriteConsole(hStdout, EXTRA "Possible PE\n", lstrlen(EXTRA "Possible PE\n"), NULL, NULL);
			AttemptPERecovery(reinterpret_cast<BYTE*>(MemInfo.BaseAddress));
		}

skip:
		TempAllocatedMemory[i] = MemInfo.BaseAddress;
		i++;
double_skip:
		CurrentAddress = reinterpret_cast<BYTE*>(CurrentAddress) + MemInfo.RegionSize;
	}

	if (!bJustStrip) CopyMemory(AllocatedMemory, TempAllocatedMemory, sizeof(TempAllocatedMemory));
}

void RemoveFreedBlocks() {
	char buf[124] = { 0 };
	MEMORY_BASIC_INFORMATION MemInfo = { 0 };
	int i = 0, j = 0;
	BOOL bSuccess = false;
	DWORD dwOldProtect = 0;
	ZeroMemory(TempAllocatedMemory, sizeof(TempAllocatedMemory));

	for (int i = 0; AllocatedMemory[i]; i++) {
		VirtualQuery(AllocatedMemory[i], &MemInfo, sizeof(MemInfo));

		// Skip if memory is invalid or just indexing memory
		if (MemInfo.State == MEM_FREE) continue;

		TempAllocatedMemory[i] = MemInfo.BaseAddress;
		i++;

		if (MemInfo.Protect == PAGE_EXECUTE_READWRITE || MemInfo.Protect == PAGE_EXECUTE_WRITECOPY) {
			if (VirtualProtect(MemInfo.BaseAddress, MemInfo.RegionSize, PAGE_EXECUTE_READ, &dwOldProtect)) {
				wsprintf(buf, GOOD "Stripped write permissions from %p\n", MemInfo.BaseAddress);
			} else {
				wsprintf(buf, BAD "Failed to strip write permissions from %p\n", MemInfo.BaseAddress);
			}
			WriteConsole(hStdout, buf, lstrlen(buf), NULL, NULL);
		}
	}

	CopyMemory(AllocatedMemory, TempAllocatedMemory, sizeof(TempAllocatedMemory));
}


/*** Hooks ***/
bool hkRtlUserThreadStart(void* pRoutine, void* Param1) {
	// Wait for mutex
	HANDLE hMutex = CreateMutexA(NULL, TRUE, MutexName);
	WaitForSingleObject(hMutex, 5000);

	// Notify
	char buf[128];
	wsprintf(buf, GOOD "Attempted thread start caught at %p\n", pRoutine);
	WriteConsole(hStdout, buf, lstrlen(buf), NULL, NULL);

	// Check for LoadLibrary injects
	if (pRoutine == Funcs::pLdrLoadDll || pRoutine == Funcs::pLoadLibraryW || pRoutine == Funcs::pLoadLibraryExW) {
		wsprintf(buf, EXTRA "Attempted LoadLibrary injection, DLL: %ls\n", Param1);
		WriteConsole(hStdout, buf, lstrlen(buf), NULL, NULL);
		wsprintf(buf, "%ls", Param1);
		int j = 0;
		for (int i = 0, n = lstrlen(buf); i < n; i++) {
			if ((buf[i] == '/' || buf[i] == '\\') && i > j) j = i + 1;
		}
		if (!CopyFile(buf, &buf[j], FALSE)) {
			wsprintf(buf, BAD "Failed to copy file %ls\n", Param1);
			WriteConsole(hStdout, buf, lstrlen(buf), NULL, NULL);
		}
	} else if (pRoutine == Funcs::pLoadLibraryA || pRoutine == Funcs::pLoadLibraryExA) {
		wsprintf(buf, EXTRA "Attempted LoadLibrary injection, DLL: %s\n", Param1);
		WriteConsole(hStdout, buf, lstrlen(buf), NULL, NULL);
		wsprintf(buf, "%s", Param1);
		int j = 0;
		for (int i = 0, n = lstrlen(buf); i < n; i++) {
			if ((buf[i] == '/' || buf[i] == '\\') && i > j) j = i + 1;
		}
		if (!CopyFile(buf, &buf[j], FALSE)) {
			wsprintf(buf, BAD "Failed to copy file %s\n", Param1);
			WriteConsole(hStdout, buf, lstrlen(buf), NULL, NULL);
		}
	}

	// Get memory info
	CheckAllocatedMemory();
	
	// Dump the attempted shellcode
	if (iThreadBytes) {
		wsprintf(buf, "Thread_%p.bin", pRoutine);
		HANDLE hFile = CreateFile(buf, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile && hFile != INVALID_HANDLE_VALUE) {
			WriteFile(hFile, pRoutine, iThreadBytes, NULL, NULL);
			CloseHandle(hFile);
		}
	}

	// Exit
	ReleaseMutex(hMutex);
	ExitThread(0); // Will crash if you dont exit here
	return true;
}

void hkLoadLibraryW(wchar_t* pDll) {
	char buf[MAX_PATH];
	wsprintf(buf, "%ls", pDll);
	hkLoadLibraryA(buf);
	_exit(1); // exit for safety
}

void hkLoadLibraryA(char* pDll) {
	int i = 0;
	for (int j = 0, n = lstrlen(pDll); j < n; j++) {
		if ((pDll[j] == '/' || pDll[j] == '\\') && j > i) i = j + 1;
	}

	CopyFile(pDll, pDll + i, FALSE);
	_exit(1); // exit for safety
}


/*** Entry ***/
int main(int argc, char** argv) {
	// Vars
	HMODULE hMod = NULL;
	DWORD dwOldProtect = 0;

	// Console setup
	SetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), ENABLE_PROCESSED_OUTPUT | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
	hStdout = GetStdHandle(STD_OUTPUT_HANDLE);

	// Config
	char OutPath[MAX_PATH] = { 0 };
	GetPrivateProfileString("Dumper", "sOutPath", ".", OutPath, MAX_PATH, ".\\InjectDumper.ini");
	iThreadBytes = GetPrivateProfileInt("Dumper", "iThreadBytes", -1, ".\\InjectDumper.ini");
	if (iThreadBytes < 0) {
		HANDLE hConfig = CreateFile("InjectDumper.ini", GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hConfig && hConfig != INVALID_HANDLE_VALUE) {
			WriteFile(hConfig, "[Dumper]\niThreadBytes=2048\nsOutPath=.\n", lstrlen("[Dumper]\niThreadBytes=2048\nsOutPath=.\n"), NULL, NULL);
			CloseHandle(hConfig);
		}
		iThreadBytes = 2048;
	}
	if (!lstrlen(OutPath)) {
		OutPath[0] = '.';
		OutPath[1] = '\\';
		OutPath[2] = 0;
	} else {
		int l = lstrlen(OutPath);
		if (OutPath[l -1] != '\\' && OutPath[l - 1] != '/') {
			OutPath[l] = '\\';
			OutPath[l + 1] = 0;
		}
		for (int i = 0; i < l; i++) {
			if (OutPath[i] == '/') OutPath[i] = '\\';
		}
	}
	if (!CreateDirectory(OutPath, NULL) && GetLastError() == ERROR_PATH_NOT_FOUND) {
		WriteConsole(hStdout, BAD "Failed to set directory, using local directory instead\n", lstrlen(BAD "Failed to set directory, using local directory instead\n"), NULL, NULL);
	} else {
		SetCurrentDirectory(OutPath);
	}

	// Setup mutex
	srand(GetTickCount64());
	for (int i = 0; i < MAX_PATH - 1; i++) {
		MutexName[i] = rand() % 256;
	}

	// Get RtlUserThreadStart
	hMod = GetModuleHandle("ntdll");
	if (!hMod) {
		WriteConsole(hStdout, BAD "Failed to locate ntdll\n", lstrlen(BAD "Failed to locate ntdll\n"), NULL, NULL);
		goto exit;
	}
	Funcs::pRtlUserThreadStart = GetProcAddress(hMod, "RtlUserThreadStart");
	if (!Funcs::pRtlUserThreadStart) {
		WriteConsole(hStdout, BAD "Failed to locate RtlUserThreadStart\n", lstrlen(BAD "Failed to locate RtlUserThreadStart\n"), NULL, NULL);
		goto exit;
	}

	// Get function addresses
	Funcs::pLdrLoadDll = GetProcAddress(hMod, "LdrLoadDll");
	Funcs::pLoadLibraryA = LoadLibraryA;
	Funcs::pLoadLibraryExA = LoadLibraryExA;
	Funcs::pLoadLibraryW = LoadLibraryW;
	Funcs::pLoadLibraryExW = LoadLibraryExW;

	// Hook RtlUserThreadStart
	VerifyHooks(true);
	
	// Extra setup stuff
	dwMainThreadId = GetCurrentThreadId();
	CheckAllocatedMemory(false);
	SetProcessDEPPolicy(PROCESS_DEP_ENABLE);
	if (!AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)ExceptionHandler)) {
		WriteConsoleA(hStdout, BAD "Failed to create exception handler\n", lstrlen(BAD "Failed to create exception handler\n"), NULL, NULL);
		goto exit;
	}
	
	// Loop
	WriteConsole(hStdout, GOOD "Watching for injections\n", lstrlen(GOOD "Watching for injections\n"), NULL, NULL);
	while (1) {
		RemoveFreedBlocks();
		CheckAllocatedMemory(false, true);
		Sleep(1);
	}

exit:
	Sleep(INFINITE);
	return 0;
}