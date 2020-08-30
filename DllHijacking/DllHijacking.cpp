#include <Windows.h>
#define SECURITY_WIN32
#include <security.h>
#include <sddl.h>
#include <iostream>
#include <fstream>
#include <sstream>


std::string logfilePath = std::string("C:\\DllHijackingPOC.log");


std::string GetLastErrorStdStr(DWORD error) {

	if (error) {
		LPVOID lpMsgBuf;
		DWORD bufLen = FormatMessageA(
			FORMAT_MESSAGE_ALLOCATE_BUFFER |
			FORMAT_MESSAGE_FROM_SYSTEM |
			FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL,
			error,
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
			(LPSTR)&lpMsgBuf,
			0, NULL);

		if (bufLen) {
			LPCSTR lpMsgStr = (LPCSTR)lpMsgBuf;
			std::string result(lpMsgStr, lpMsgStr + bufLen - 1);

			LocalFree(lpMsgBuf);

			return result;
		}
	}
	return std::string("failed to get error description");
}


std::string GetLastErrorStdStr() {

	DWORD err = GetLastError();
	return std::to_string(err) + ", " + GetLastErrorStdStr(err);
}


std::string getTokenUser() {

	HANDLE hToken = NULL;
	PTOKEN_USER pTokenUser = NULL;
	DWORD pTokenUserSize = 0;
	std::stringstream result = std::stringstream();

	if (OpenProcessToken(
		GetCurrentProcess(),
		TOKEN_ALL_ACCESS,
		&hToken
	) == 0) {
		return result.str();
	}

	GetTokenInformation(
		hToken,
		TokenUser,
		NULL,
		pTokenUserSize,
		&pTokenUserSize
	);
	if (pTokenUserSize == 0) {
		CloseHandle(hToken);
		return result.str();
	}

	pTokenUser = (PTOKEN_USER)malloc(pTokenUserSize);

	if (GetTokenInformation(
		hToken,
		TokenUser,
		pTokenUser,
		pTokenUserSize,
		&pTokenUserSize
	) == 0) {
		CloseHandle(hToken);
		return result.str();
	}

	DWORD usernameLen = 0;
	DWORD domainNameLen = 0;
	LPSTR username = NULL;
	LPSTR domainName = NULL;
	SID_NAME_USE sidType;

	LookupAccountSidA(
		NULL,
		(SID*)pTokenUser->User.Sid,
		username,
		&usernameLen,
		domainName,
		&domainNameLen,
		&sidType
	);
	if (usernameLen == 0) {
		CloseHandle(hToken);
		return result.str();
	}

	username = (LPSTR)malloc(usernameLen);
	domainName = (LPSTR)malloc(domainNameLen);

	std::string err = GetLastErrorStdStr();
	if (LookupAccountSidA(
		NULL,
		pTokenUser->User.Sid,
		username,
		&usernameLen,
		domainName,
		&domainNameLen,
		&sidType
	) == 0) {
		free(domainName);
		free(username);
		CloseHandle(hToken);
		return result.str();
	}

	result << domainName << "\\" << username;
	free(domainName);
	free(username);
	CloseHandle(hToken);
	return result.str();
}


std::string getTokenSidString() {

	PTOKEN_USER pTokenUser = NULL;
	DWORD pTokenUserSize = 0;
	std::string result = std::string();
	HANDLE hToken = NULL;

	if (OpenProcessToken(
		GetCurrentProcess(),
		TOKEN_ALL_ACCESS,
		&hToken
	) == 0) {
		std::string err = GetLastErrorStdStr();
		return result;
	}

	GetTokenInformation(
		hToken,
		TokenUser,
		NULL,
		pTokenUserSize,
		&pTokenUserSize
	);
	if (pTokenUserSize == 0) {
		CloseHandle(hToken);
		return result;
	}

	pTokenUser = (PTOKEN_USER)malloc(pTokenUserSize);

	if (GetTokenInformation(
		hToken,
		TokenUser,
		pTokenUser,
		pTokenUserSize,
		&pTokenUserSize
	) == 0) {
		CloseHandle(hToken);
		return result;
	}

	LPSTR stringSid;

	if (ConvertSidToStringSidA(
		pTokenUser->User.Sid,
		&stringSid
	) == 0) {
		CloseHandle(hToken);
		return result;
	}

	result = std::string(stringSid);
	free(pTokenUser);
	LocalFree(stringSid);
	CloseHandle(hToken);
	return result;
}


void logToFile(std::string s) {

	std::ofstream out(logfilePath, std::ofstream::out | std::ofstream::app);
	if (out.fail()) {
		DWORD err = GetLastError();
		std::string errstr = GetLastErrorStdStr(err);
		// what to do with this?? todo
		return;
	}
	SYSTEMTIME t;
	GetLocalTime(&t);

	out << t.wHour << ':' << t.wMinute << ':' << t.wSecond << ':' << t.wMilliseconds << " | ";
	out << s;
	out.close();
}


std::string getDllPath() {

	char path[MAX_PATH];
	HMODULE hm = NULL;
	std::string result = std::string();

	if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
		GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
		(LPCSTR)&logToFile, &hm) == 0)
	{
		return result;
	}
	if (GetModuleFileNameA(hm, path, sizeof(path)) == 0)
	{
		return result;
	}

	result = std::string(path);
	return result;
}


BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{

	std::stringstream logString = std::stringstream();
	std::string processUsername = getTokenUser();
	std::string processSid = getTokenSidString();
	std::string dllPath = getDllPath();
	LPSTR processCommandLine = GetCommandLineA();
	processUsername = processUsername.empty() ? std::string("Unknown") : processUsername;
	dllPath = dllPath.empty() ? std::string("Unknown") : dllPath;

	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:

		logString << "Process hijacked!\n";
		logString << "Process information:\n";
		logString << "\tUsername: " << processUsername << "\n";
		logString << "\tSID: " << processSid << "\n";
		logString << "\tCommand line: " << processCommandLine << "\n";
		logString << "\tDll Path: " << dllPath << "\n";
		logToFile(logString.str());

	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}