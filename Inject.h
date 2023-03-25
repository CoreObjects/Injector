#pragma once
class Inject {

public:
#ifdef UNICODE
	BOOL RemoteInject(DWORD dwProcessId, const wchar_t* csDllPath);
	bool RemoteFreelibrary(DWORD dwProcessId, const wchar_t* csDllPath);
	bool UnTraceInject(DWORD dwProcessId, const wchar_t* csDllPath);
#else
	BOOL RemoteInject(DWORD dwProcessId, const char* csDllPath);
	bool RemoteFreelibrary(DWORD dwProcessId, const char* csDllPath);
	bool UnTraceInject(DWORD dwProcessId, const char* csDllPath);
#endif // UNICODE

};

