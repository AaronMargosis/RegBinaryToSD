// RegBinaryToSD
// Read a REG_BINARY value and translate to a security descriptor.  Allows various specs for root key HKLM\software, HKLM:\software, HKEY_LOCAL_MACHINE\software, etc.


//TODO: Add printer rights?

#include <Windows.h>
#include <io.h>
#include <fcntl.h>
#include <iostream>
#include <vector>
#include "HEX.h"
#include "SysErrorMessage.h"
#include "StringUtils.h"
#include "SecurityDescriptorUtils.h"

void Usage(const wchar_t* argv0, const wchar_t* szError = nullptr)
{
	std::wstring sExe = GetFileNameFromFilePath(argv0);
	if (szError)
	{
		std::wcerr << szError << std::endl;
	}
	std::wcerr
		<< std::endl
		<< sExe << L": parses data in a REG_BINARY registry value as a Security Descriptor." << std::endl
		<< std::endl
		<< L"Usage:" << std::endl
		<< std::endl
		<< L"    " << sExe << L" -k keypath [-v valuename] [-o objtype]" << std::endl
		<< std::endl
		<< L"keypath   : Full path to a registry key, of the form \"rootkey\\subkey\". Supported root keys" << std::endl
		<< L"            include HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER, HKEY_USERS, and HKEY_CLASSES_ROOT." << std::endl
		<< L"            The root key portion can be its full name (e.g., \"HKEY_LOCAL_MACHINE\")," << std::endl
		<< L"            abbreviated (e.g., \"HKLM\"), or PowerShell drive format (e.g., \"hklm:\"). The" << std::endl
		<< L"            key path is case-insensitive. The keypath must be quoted if it contains spaces," << std::endl
		<< L"            and should be quoted when executed in PowerShell if the keypath contains special" << std::endl
		<< L"            characters such as parentheses or curly braces." << std::endl
		<< std::endl
		<< L"valuename : The name of a value in that key, usually a REG_BINARY value. The name must be" << std::endl
		<< L"            quoted if it contains spaces. If -v is not specified, " << sExe << L" reads the" << std::endl
		<< L"            key's default (unnamed) value." << std::endl
		<< std::endl
		<< L"objtype   : (Optional) An object type to translate permission names. Supported object types" << std::endl
		<< L"            include \"SDDL\" and the following: file, dir, pipe, key, share, process, thread," << std::endl
		<< L"            service, scm, com, winsta, desktop, section, filemap, evt, token, and ntds." << std::endl
		<< L"            If objtype is \"SDDL\", " << sExe << L" outputs the security descriptor in Security" << std::endl
		<< L"            Descriptor Definition Language format." << std::endl
		<< std::endl
		<< L"Examples:" << std::endl
		<< L"  " << sExe << L" -k \"HKCR\\AppId\\{00021401-0000-0000-C000-000000000046}\" -v AccessPermission -o com" << std::endl
		<< L"  " << sExe << L" -k HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\DefaultSecurity -v SrvsvcShareAdminConnect -o share" << std::endl
		<< L"  " << sExe << L" -k HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\CoreMessagingRegistrar\\Security -v Security -o service" << std::endl
		<< L"  " << sExe << L" -k HKEY_LOCAL_MACHINE\\SECURITY\\Policy\\SecDesc" << std::endl
		<< L"(That last example must be executed as LocalSystem.)" << std::endl
		<< std::endl
		;
	exit(-1);
}

int wmain(int argc, wchar_t**argv)
{
	// Set output mode to UTF8.
	if (_setmode(_fileno(stdout), _O_U8TEXT) == -1 || _setmode(_fileno(stderr), _O_U8TEXT) == -1)
	{
		std::wcerr << L"Unable to set stdout and/or stderr modes to UTF8." << std::endl;
	}

	std::wstring sRootKey, sSubKey;
	const wchar_t* szValueName = nullptr;
	const wchar_t* szObjType = nullptr;

	int ixArg = 1;
	while (ixArg < argc)
	{
		if (0 == _wcsicmp(L"-k", argv[ixArg]))
		{
			if (++ixArg >= argc)
				Usage(argv[0], L"Missing arg for -k");
			std::wstring sKeyPath = argv[ixArg];
			// Split root key from subkey at the first backslash. If none, not a valid key
			size_t ixChar = sKeyPath.find_first_of(L'\\');
			if (std::wstring::npos == ixChar)
				Usage(argv[0], L"Invalid registry path");
			sRootKey = sKeyPath.substr(0, ixChar);
			sSubKey = sKeyPath.substr(ixChar + 1);
			// Supporting PowerShell drive format: if the root key has a ':' remove it
			ixChar = sRootKey.find_first_of(L':');
			if (std::wstring::npos != ixChar)
				sRootKey = sRootKey.substr(0, ixChar);
			// Supporting input from PowerShell: remove trailing backslash in the subkey
			while (EndsWith(sSubKey, L'\\'))
				sSubKey = sSubKey.substr(0, sSubKey.length() - 1);
		}
		else if (0 == _wcsicmp(L"-v", argv[ixArg]))
		{
			if (++ixArg >= argc)
				Usage(argv[0], L"Missing arg for -v");
			szValueName = argv[ixArg];
		}
		else if (0 == _wcsicmp(L"-o", argv[ixArg]))
		{
			if (++ixArg >= argc)
				Usage(argv[0], L"Missing arg for -o");
			szObjType = argv[ixArg];
		}
		else
		{
			Usage(argv[0], L"Invalid parameter");
		}
		++ixArg;
	}

	if (sRootKey.length() == 0 || sSubKey.length() == 0)
		Usage(argv[0]);

	// Get the proper root key value for calling APIs
	HKEY hRootKey = NULL;
	const wchar_t* szRootKey = sRootKey.c_str();
	if (0 == _wcsicmp(szRootKey, L"HKLM") || 0 == _wcsicmp(szRootKey, L"HKEY_LOCAL_MACHINE"))
	{
		hRootKey = HKEY_LOCAL_MACHINE;
		sRootKey = L"HKEY_LOCAL_MACHINE";
	}
	else if (0 == _wcsicmp(szRootKey, L"HKCU") || 0 == _wcsicmp(szRootKey, L"HKEY_CURRENT_USER"))
	{
		hRootKey = HKEY_CURRENT_USER;
		sRootKey = L"HKEY_CURRENT_USER";
	}
	else if (0 == _wcsicmp(szRootKey, L"HKCR") || 0 == _wcsicmp(szRootKey, L"HKEY_CLASSES_ROOT"))
	{
		hRootKey = HKEY_CLASSES_ROOT;
		sRootKey = L"HKEY_CLASSES_ROOT";
	}
	else if (0 == _wcsicmp(szRootKey, L"HKU") || 0 == _wcsicmp(szRootKey, L"HKEY_USERS"))
	{
		hRootKey = HKEY_USERS;
		sRootKey = L"HKEY_USERS";
	}
	else
	{
		std::wcerr << L"Unrecognized root key: " << szRootKey << std::endl;
		Usage(argv[0]);
	}
	std::wcout
		<< L"Root  : " << sRootKey << std::endl
		<< L"Subkey: " << sSubKey << std::endl
		<< L"Value : " << (szValueName ? szValueName : L"(default/unnamed value)") << std::endl
		<< std::endl;

	HKEY hKey = NULL;
	LONG rv = RegOpenKeyExW(hRootKey, sSubKey.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &hKey);
	if (ERROR_SUCCESS != rv)
	{
		std::wcerr << L"Error opening key: " << SysErrorMessageWithCode(rv) << std::endl;
		Usage(argv[0]);
	}
	// Determine the type and the number of bytes needed to read the data.
	DWORD dwType = 0, cbData = 0;
	rv = RegQueryValueExW(hKey, szValueName, NULL, &dwType, NULL, &cbData);
	if (ERROR_SUCCESS != rv && ERROR_MORE_DATA != rv)
	{
		std::wcout << L"Error reading registry value: " << SysErrorMessageWithCode(rv) << std::endl;
		Usage(argv[0]);
	}
	// Notify if the value isn't a REG_BINARY, but continue processing.
	if (REG_BINARY != dwType)
	{
		const wchar_t* szType = nullptr;
		switch (dwType)
		{
		case REG_NONE:                       szType = L"REG_NONE"; break;
		case REG_SZ:                         szType = L"REG_SZ"; break;
		case REG_EXPAND_SZ:                  szType = L"REG_EXPAND_SZ"; break;
		case REG_BINARY:                     szType = L"REG_BINARY"; break;
		case REG_DWORD:                      szType = L"REG_DWORD"; break;
		case REG_DWORD_BIG_ENDIAN:           szType = L"REG_DWORD_BIG_ENDIAN"; break;
		case REG_LINK:                       szType = L"REG_LINK"; break;
		case REG_MULTI_SZ:                   szType = L"REG_MULTI_SZ"; break;
		case REG_RESOURCE_LIST:              szType = L"REG_RESOURCE_LIST"; break;
		case REG_FULL_RESOURCE_DESCRIPTOR:   szType = L"REG_FULL_RESOURCE_DESCRIPTOR"; break;
		case REG_RESOURCE_REQUIREMENTS_LIST: szType = L"REG_RESOURCE_REQUIREMENTS_LIST"; break;
		case REG_QWORD:                      szType = L"REG_QWORD"; break;
		}
		std::wcout << L"Note: the registry value is not a REG_BINARY. It is type ";
		if (nullptr != szType)
			std::wcout << szType;
		else
			std::wcout << dwType;
		std::wcout << L"." << std::endl << std::endl;
	}
	// Allocate memory and read the value again
	std::vector<byte> regValueData(cbData, 0);
	rv = RegQueryValueExW(hKey, szValueName, NULL, &dwType, regValueData.data(), &cbData);
	if (ERROR_SUCCESS == rv)
	{
		//std::wcout << std::endl;
		OutputSecurityDescriptor(std::wcout, (PSECURITY_DESCRIPTOR)regValueData.data(), szObjType);
		std::wcout << std::endl;
	}
	else
	{
		std::wcout << L"Error reading registry value: " << SysErrorMessageWithCode(rv) << std::endl;
	}
	return 0;
}

