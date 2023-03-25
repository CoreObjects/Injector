#include "pch.h"
#include "Inject.h"
#include <TlHelp32.h>
#ifdef UNICODE
BOOL Inject::RemoteInject(DWORD dwProcessId, const wchar_t* csDllPath) {
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
	if (hProcess == INVALID_HANDLE_VALUE) {
		return FALSE;
	}
	LPVOID lpBuffer = VirtualAllocEx(hProcess, NULL, MAX_PATH * 2, MEM_COMMIT, PAGE_READWRITE);
	if (lpBuffer == NULL) {
		CloseHandle(hProcess);
		return FALSE;
	}
	SIZE_T dwRealWrite;
	BOOL bRet = WriteProcessMemory(hProcess, lpBuffer, csDllPath, (wcslen(csDllPath) + 1) * 2, &dwRealWrite);
	if (!bRet) {
		CloseHandle(hProcess);
		return FALSE;
	}
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryW, lpBuffer, 0, NULL);
	if (hThread == NULL) {
		CloseHandle(hProcess);
		return FALSE;
	}
	WaitForSingleObject(hThread, -1);
	CloseHandle(hThread);
	VirtualFreeEx(hProcess, lpBuffer, 0, MEM_RELEASE);
	CloseHandle(hProcess);
	return TRUE;
}
bool Inject::RemoteFreelibrary(DWORD dwProcessId, const wchar_t* csDllPath) {
	MODULEENTRY32 me32 = { sizeof(me32) };
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE32 | TH32CS_SNAPMODULE, dwProcessId);
	if (hSnap == INVALID_HANDLE_VALUE) {
		return false;
	}
	BOOL bRet = Module32First(hSnap, &me32);
	while (bRet) {
		if (!wcscmp(csDllPath, (const wchar_t*)me32.szExePath) || !wcscmp(csDllPath, (const wchar_t*)me32.szModule)) {
			LONG_PTR dwModeBase = (LONG_PTR)me32.modBaseAddr;
			HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
			if (hProcess == INVALID_HANDLE_VALUE) {
				CloseHandle(hSnap);
				return false;
			}
			HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)FreeLibrary, (LPVOID)dwModeBase, 0, NULL);
			if (hThread == NULL) {
				CloseHandle(hSnap);
				CloseHandle(hProcess);
				return false;
			}
			WaitForSingleObject(hThread, -1);
			CloseHandle(hThread);
			CloseHandle(hProcess);
			CloseHandle(hSnap);
			return TRUE;
		}
		bRet = Module32Next(hSnap, &me32);
	}
	CloseHandle(hSnap);
	return true;
}
bool Inject::UnTraceInject(DWORD dwProcessId, const wchar_t* csDllPath) {
	RemoteInject(dwProcessId, csDllPath);
	MODULEENTRY32 me32 = { sizeof(me32) };
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE32 | TH32CS_SNAPMODULE, dwProcessId);
	if (hSnap == INVALID_HANDLE_VALUE) {
		return false;
	}
	BOOL bRet = Module32First(hSnap, &me32);
	LONG_PTR dwModeBase = 0, dwModeSize = 0;
	while (bRet) {
		if (!wcscmp(csDllPath, (const wchar_t*)me32.szExePath) || !wcscmp(csDllPath, (const wchar_t*)me32.szModule)) {
			dwModeBase = (LONG_PTR)me32.modBaseAddr;
			dwModeSize = (LONG_PTR)me32.modBaseSize;
			break;
		}
		bRet = Module32Next(hSnap, &me32);
	}
	CloseHandle(hSnap);
	if (!bRet) {
		return false;
	}
	char* szBuffer = new char[dwModeSize] {0};
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
	if (hProcess == INVALID_HANDLE_VALUE) {
		CloseHandle(hSnap);
		return false;
	}
	bRet = ReadProcessMemory(hProcess, (LPVOID)dwModeBase, szBuffer, dwModeSize, NULL);
	if (!bRet) {
		CloseHandle(hProcess);
		return false;
	}
	bRet = RemoteFreelibrary(dwProcessId, csDllPath);
	if (!bRet) {
		CloseHandle(hProcess);
		return false;
	}
	LPVOID lpModule = VirtualAllocEx(hProcess, (LPVOID)dwModeBase, dwModeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (lpModule == NULL) {
		CloseHandle(hProcess);
		return false;
	}
	bRet = WriteProcessMemory(hProcess, (LPVOID)dwModeBase, szBuffer, dwModeSize, NULL);
	CloseHandle(hProcess);
	return bRet;
}
#else
BOOL Inject::RemoteInject(DWORD dwProcessId, const char* csDllPath) {
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
	if (hProcess == INVALID_HANDLE_VALUE) {
		return FALSE;
	}
	LPVOID lpBuffer = VirtualAllocEx(hProcess, NULL, MAX_PATH, MEM_COMMIT, PAGE_READWRITE);
	if (lpBuffer == NULL) {
		CloseHandle(hProcess);
		return FALSE;
	}
	SIZE_T dwRealWrite;
	BOOL bRet = WriteProcessMemory(hProcess, lpBuffer, csDllPath, strlen(csDllPath) + 1, &dwRealWrite);
	if (!bRet) {
		CloseHandle(hProcess);
		return FALSE;
	}
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, lpBuffer, 0, NULL);
	if (hThread == NULL) {
		CloseHandle(hProcess);
		return FALSE;
	}
	WaitForSingleObject(hThread, -1);
	CloseHandle(hThread);
	VirtualFreeEx(hProcess, lpBuffer, 0, MEM_RELEASE);
	CloseHandle(hProcess);
	return TRUE;
}
bool Inject::RemoteFreelibrary(DWORD dwProcessId, const char* csDllPath) {
	MODULEENTRY32 me32 = { sizeof(me32) };
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE32 | TH32CS_SNAPMODULE, dwProcessId);
	if (hSnap == INVALID_HANDLE_VALUE) {
		return false;
	}
	BOOL bRet = Module32First(hSnap, &me32);
	while (bRet) {
		if (!strcmp(csDllPath, (const char*)me32.szExePath) || !strcmp(csDllPath, (const char*)me32.szModule)) {
			DWORD dwModeBase = (DWORD)me32.modBaseAddr;
			HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
			if (hProcess == INVALID_HANDLE_VALUE) {
				CloseHandle(hSnap);
				return false;
			}
			HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)FreeLibrary, (LPVOID)dwModeBase, 0, NULL);
			if (hThread == NULL) {
				CloseHandle(hSnap);
				CloseHandle(hProcess);
				return false;
			}
			WaitForSingleObject(hThread, -1);
			CloseHandle(hThread);
			CloseHandle(hProcess);
			CloseHandle(hSnap);
			return TRUE;
		}
		bRet = Module32Next(hSnap, &me32);
	}
	CloseHandle(hSnap);
	return true;
}
bool Inject::UnTraceInject(DWORD dwProcessId, const char* csDllPath) {
	RemoteInject(dwProcessId, csDllPath);
	MODULEENTRY32 me32 = { sizeof(me32) };
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE32 | TH32CS_SNAPMODULE, dwProcessId);
	if (hSnap == INVALID_HANDLE_VALUE) {
		return false;
	}
	BOOL bRet = Module32First(hSnap, &me32);
	DWORD dwModeBase = 0, dwModeSize = 0;
	while (bRet) {
		if (!strcmp(csDllPath, (const char*)me32.szExePath) || !strcmp(csDllPath, (const char*)me32.szModule)) {
			dwModeBase = (DWORD)me32.modBaseAddr;
			dwModeSize = (DWORD)me32.modBaseSize;
			break;
		}
		bRet = Module32Next(hSnap, &me32);
	}
	CloseHandle(hSnap);
	if (!bRet) {
		return false;
	}
	char* szBuffer = new char[dwModeSize] {0};
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
	if (hProcess == INVALID_HANDLE_VALUE) {
		CloseHandle(hSnap);
		return false;
	}
	bRet = ReadProcessMemory(hProcess, (LPVOID)dwModeBase, szBuffer, dwModeSize, NULL);
	if (!bRet) {
		CloseHandle(hProcess);
		return false;
	}
	bRet = RemoteFreelibrary(dwProcessId, csDllPath);
	if (!bRet) {
		CloseHandle(hProcess);
		return false;
	}
	LPVOID lpModule = VirtualAllocEx(hProcess, (LPVOID)dwModeBase, dwModeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (lpModule == NULL) {
		CloseHandle(hProcess);
		return false;
	}
	bRet = WriteProcessMemory(hProcess, (LPVOID)dwModeBase, szBuffer, dwModeSize, NULL);
	CloseHandle(hProcess);
	return bRet;
}
#endif // UNICODE