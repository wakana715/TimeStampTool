/*
 * TimeStampTool CMD SrcDir DstDir FromDate ToDate SrcExt DstExt
 *      CMD : Command 0:List, 1:Copy, 2:HardLink, 3:HASH, 4:PACK
 *   SrcDir : Directory      ex. C:\Src
 *   DstDir : Directory      ex. C:\Dst
 * FromDate : YYYYMMDDHHmmSS ex. 20000101
 *   ToDate : YYYYMMDDHHmmSS ex. 99999999
 *   SrcExt : Extend         ex. jp2
 *   DstExt : Extend         ex. jpg
>TimeStampTool 0 C:\Windows\System C:
List 0x0000                  3866 2019-12-07_18:08:39 C:\Speech\speech-synthesis.xsd
List 0x0000                 16968 2019-12-07_18:08:39 C:\Speech\synthesis-core.xsd
List 0x0000                 10205 2019-12-07_18:08:39 C:\Speech\xml.xsd
>TimeStampTool 1 C:\Windows\System C:
Copy 0x0000                  3866 2019-12-07_18:08:39 C:\Speech\speech-synthesis.xsd
Copy 0x0000                 16968 2019-12-07_18:08:39 C:\Speech\synthesis-core.xsd
Copy 0x0000                 10205 2019-12-07_18:08:39 C:\Speech\xml.xsd
>TimeStampTool 2 C:\Windows\System C:
Link 0x0000                  3866 2019-12-07_18:08:39 C:\Speech\speech-synthesis.xsd
Link 0x0000                 16968 2019-12-07_18:08:39 C:\Speech\synthesis-core.xsd
Link 0x0000                 10205 2019-12-07_18:08:39 C:\Speech\xml.xsd
>TimeStampTool 3 C:\Windows\System C:
Hash 0x0000 61bb8b000a956b0bc61df642f92e2daf                 3866 2019-12-07_18:08:39 C:\Speech\speech-synthesis.xsd
Hash 0x0000 d7d50c9c760d583853d635cf2ae05911                16968 2019-12-07_18:08:39 C:\Speech\synthesis-core.xsd
Hash 0x0000 79f05e58d3ac430625bacf952f55b857                10205 2019-12-07_18:08:39 C:\Speech\xml.xsd
>TimeStampTool 4 C:\Windows\System C: 0 9999
%CMD% %OPT% "C:\Windows\System\Speech.zip" "C:\Windows\System\Speech\*.*" %OPT2%
>SET CMD=C:\share\2000\7-Zip\7z.exe
>SET OPT=a
>SET OPT2=-r -mx=9
 */
#include <windows.h>
#include <shlobj.h>
#include <stdio.h>
#include <iostream>
#include <iomanip>
#include <string>
#include <sstream>
#include <vector>
#include <map>
#include <algorithm>
#include <functional>

#ifdef __BORLANDC__
#if __BORLANDC__ <= 0x551
typedef LONG LSTATUS;
#define __func__	__FUNC__
#define	PROV_RSA_AES		24
#define	wcsnlen_s(p,n)		wcslen(p)
#define	wcscat_s(d,n,a)		wcscat(d,a)
#define wcsncpy_s(d,n,s,c)	wcsncpy(d,s,c);
#define strncpy_s(d,n,s,c)	strncpy(d,s,c)
int fopen_s(FILE** fp, const char* filename, const char* mode)
{
	if ((*fp = fopen(filename, mode)) == NULL)
	{
		return -1;
	}
	return 0;
}
#endif /* if __BORLANDC__ <= 0x551 */
#endif /* ifdef __BORLANDC__ */

#define REG_KEY_COUNT			"SOFTWARE\\TimeStampTool"
#define REG_KEY_STR_CONVERT		"SOFTWARE\\TimeStampTool\\StrConvert"
#define REG_KEY_CMD				"SOFTWARE\\TimeStampTool\\Cmd"
#define REG_KEY_SRC				"SOFTWARE\\TimeStampTool\\Src"
#define REG_KEY_DST				"SOFTWARE\\TimeStampTool\\Dst"
#define REG_KEY_FROM_DATE_TIME	"SOFTWARE\\TimeStampTool\\FromDateTime"
#define REG_KEY_TO_DATE_TIME	"SOFTWARE\\TimeStampTool\\ToDateTime"
#define REG_KEY_EXT_SRC			"SOFTWARE\\TimeStampTool\\ExtSrc"
#define REG_KEY_EXT_DST			"SOFTWARE\\TimeStampTool\\ExtDst"
#define REG_NAME_COUNT			"Count"
#define COUNT_LEN				  32
#define VALUE_LEN				 256
#define CMD_LEN					   8
#define	MD5_LEN					  16
#define PRINT_LEN				2048
#define READ_BUF_SIZE			(1024*2048)
#define DESKTOP_PATH_LEN		1024
#define FULL_PATH_LEN			 256
#define VOLUME_LABEL_LEN		 256
#define FILE_SYSTEM_LEN			 256
#define MAX_LEN					1024
#define LOG_FILE_LEN			  32
#define LOG_FILE_PATH_LEN		(DESKTOP_PATH_LEN + LOG_FILE_LEN + 1)
#define REPORT_FILE_NAME		"report.txt"
#define REPORT_FILE_PATH_LEN	(DESKTOP_PATH_LEN + 16)
/*
 * YYYY-MM-DD HH:MM:SS YYYYMMDDHHMMSS 
 *           1         2         3
 * 01234567890123456789012345678901234
 */
#define	POS_DATE_TIME_PRINT		  0
#define	POS_DATE_TIME_SEP		 10
#define	POS_DATE_TIME_STR_ST	 20
#define	POS_DATE_TIME_STR_ED	 34
#define	LEN_DATE_TIME_STR		(POS_DATE_TIME_STR_ED - POS_DATE_TIME_STR_ST)

enum E_CMD
{
	E_CMD_LIST = 0,
	E_CMD_COPY,
	E_CMD_LINK,
	E_CMD_HASH,
	//E_CMD_MAKE,
	E_CMD_PACK,
	E_CMD_MAX
};

enum E_REG_INDEX
{
	E_REG_CMD = 0,
	E_REG_SRC,
	E_REG_DST,
	E_REG_FROM_DATE_TIME,
	E_REG_TO_DATE_TIME,
	E_REG_EXT_SRC,
	E_REG_EXT_DST,
	E_REG_MAX
};

/* ファイルの作成日時，アクセス日時，更新日時 */
enum E_FT_INDEX
{
	E_FT_CREATE = 0,
	E_FT_ACCESS,
	E_FT_UPDATE,
	E_FT_MAX
};

enum E_DT_INDEX
{
	E_DT_YEAR = 0,
	E_DT_MONTH,
	E_DT_WEEK,
	E_DT_DAY,
	E_DT_HOUR,
	E_DT_MINUTE,
	E_DT_SECOND,
	E_DT_MILLI,
	E_DT_MAX
};

static const char*	g_str_cmd[] =
{
	"List", "Copy", "Link", "Hash", "Pack", NULL
};

static const char*	g_str_reg_key[] =
{
	REG_KEY_CMD, REG_KEY_SRC, REG_KEY_DST, REG_KEY_FROM_DATE_TIME, REG_KEY_TO_DATE_TIME, REG_KEY_EXT_SRC, REG_KEY_EXT_DST, NULL
};

typedef struct
{
	char**				pp_str_cmd;
	int					n_cmd;
	char*				p_str_cmd;
	wchar_t				wcs_cmd[CMD_LEN];
	/* file info */
	int					is_get_volume_label;
	wchar_t				wcs_full_path[FULL_PATH_LEN];
	wchar_t				wcs_volume_label[VOLUME_LABEL_LEN];
	char				str_volume_label[VOLUME_LABEL_LEN];
	wchar_t				wcs_file_system[FILE_SYSTEM_LEN];
	char				str_file_system[FILE_SYSTEM_LEN];
	wchar_t				file_time[E_FT_MAX][POS_DATE_TIME_STR_ED];
	unsigned __int64	file_size;
	/* file output */
	wchar_t				desktop_path[DESKTOP_PATH_LEN];
	char				read_print[PRINT_LEN];
	/* pack */
	std::map<std::wstring, std::wstring> map_path;
	/* registry */
	char**				pp_str_reg_key;
	HKEY				hkey;	/* REG_KEY_STR_CONVERT */
	wchar_t				wcs_count[COUNT_LEN];
	char				str_count[COUNT_LEN];
	wchar_t				reg_value[E_REG_MAX][VALUE_LEN];
	/* log */
	HANDLE				h_log;
	wchar_t				wcs_file_log[LOG_FILE_LEN];
	char				str_file_log[LOG_FILE_LEN];
	wchar_t				wcs_path_log[LOG_FILE_PATH_LEN];
	long				len_path_log;
	/* report.txt */
	SYSTEMTIME			stime_start;
	SYSTEMTIME			stime_end;
	FILETIME			ftime_start;
	FILETIME			ftime_end;
	unsigned __int64	n_time_diff;
	SYSTEMTIME			stime_diff;
	unsigned long		all_file_count;
	unsigned __int64	all_file_size;
	wchar_t				wcs_path_report[REPORT_FILE_PATH_LEN];
	long				len_path_report;
	HANDLE				h_report;
}T_GLOBAL;

static T_GLOBAL g_global;

static int StrToWide(const char* _p_str, wchar_t* _p_wcs, const int len)
{
	return MultiByteToWideChar(CP_ACP, 0, _p_str, -1, _p_wcs, len);
}

static int WideToStr(const wchar_t* _p_wcs, char* _p_str, const int len)
{
	return WideCharToMultiByte(CP_OEMCP, 0, _p_wcs, -1, _p_str, len, NULL, NULL);
}

static bool ShellRegCreate(const char* _p_key, HKEY* _p_hKey)
{
	LPCSTR	lpKey = reinterpret_cast<LPCSTR>(_p_key);
	LSTATUS ret = ::RegCreateKeyA(HKEY_CURRENT_USER, lpKey, _p_hKey);
	if (ERROR_SUCCESS != ret)
	{
		return false;
	}
	return true;
}

static bool ShellRegReadWriteInt(const char* _p_key, const char* _p_name, int* _p_value, const int _add)
{
	HKEY hKey = NULL;
	if (!ShellRegCreate(_p_key, &hKey))
	{
		return false;
	}
	int	n_value = 0;
	DWORD dwType = 0;
	DWORD dwSize = sizeof(DWORD);
	LPBYTE lpGet = reinterpret_cast<LPBYTE>(&n_value);
	(void)::RegQueryValueExA(hKey, _p_name, 0, &dwType, lpGet, &dwSize);
	if (_add != 0)
	{
		n_value += _add;
		const BYTE*	lpSet = reinterpret_cast<const BYTE*>(&n_value);
		LSTATUS ret = ::RegSetValueExA(hKey, _p_name, 0, REG_DWORD, lpSet, sizeof(DWORD));
		if (ERROR_SUCCESS != ret)
		{
			(void)::RegCloseKey(hKey);
			return false;
		}
	}
	(void)::RegCloseKey(hKey);
	*_p_value = n_value;
	return true;
}

static bool ShellRegReadDelete(const char* _p_path, const wchar_t* _p_name, wchar_t* _p_value, int* _p_size, const bool _is_delete)
{
	HKEY hKey = NULL;
	if (!ShellRegCreate(_p_path, &hKey))
	{
		return false;
	}
	LPCWSTR	lpName = reinterpret_cast<LPCWSTR>(_p_name);
	LPWSTR	lpData = reinterpret_cast<LPWSTR>(_p_value);
	PLONG	lpSize = reinterpret_cast<PLONG>(_p_size);
	LSTATUS ret = ::RegQueryValueW(hKey, lpName, lpData, lpSize);
	if (_is_delete)
	{
		(void)::RegDeleteKeyW(hKey, lpName);
	}
	(void)::RegCloseKey(hKey);
	if (ERROR_SUCCESS != ret)
	{
		return false;
	}
	return true;
}

static bool ShellRegWrite(const char* _p_key, const char* _p_name, const char* _p_value)
{
	HKEY hKey = NULL;
	if (!ShellRegCreate(_p_key, &hKey))
	{
		return false;
	}
	LPCSTR	lpName = reinterpret_cast<LPCSTR>(_p_name);
	LPCSTR	lpData = reinterpret_cast<LPCSTR>(_p_value);
	LSTATUS ret = ::RegSetValueA(hKey, lpName, REG_SZ, lpData, 0);
	(void)::RegCloseKey(hKey);
	if (ERROR_SUCCESS != ret)
	{
		return false;
	}
	return true;
}

static void ShellGetFullPath(const wchar_t* _p_path, wchar_t* _p_full_path, const int _len_full_path, wchar_t** _pp_file)
{
	GetFullPathNameW(_p_path, _len_full_path, _p_full_path, _pp_file);
}

static void ShellGetVolumeInfo(const wchar_t* _p_path, wchar_t* _p_vl, const int _len_vl, wchar_t* _p_sys, const int _len_sys)
{
	DWORD	dwSerial, dwLength, dwFlags;
	GetVolumeInformationW(_p_path, _p_vl, _len_vl, &dwSerial, &dwLength, &dwFlags, _p_sys, _len_sys);
}

static bool ShellMkDir(const wchar_t* _p_path)
{
	LPCWSTR lpPath = reinterpret_cast<LPCWSTR>(_p_path);
	BOOL ret = ::CreateDirectoryW(lpPath, NULL);
	if (ret != FALSE)
	{
		return true;
	}
	if (::GetLastError() != ERROR_ALREADY_EXISTS)
	{
		return false;
	}
	return true;
}

static bool ShellSetFileDirectoryTime(const wchar_t* _p_src, const wchar_t* _p_dst, bool _isFile)
{
	LPCWSTR lpFileNameSrc = reinterpret_cast<LPCWSTR>(_p_src);
	WIN32_FIND_DATAW findData = {0};
	HANDLE handle_src = ::FindFirstFileW(lpFileNameSrc, &findData);
	if (handle_src == INVALID_HANDLE_VALUE)
	{
		return false;
	}
	(void)::FindClose(handle_src);
	FILETIME fileTimeLocal[E_FT_MAX] = {0}, fileTime[E_FT_MAX] = {0};
	(void)::FileTimeToLocalFileTime(&findData.ftCreationTime,	&fileTimeLocal[E_FT_CREATE]);
	(void)::FileTimeToLocalFileTime(&findData.ftLastAccessTime,	&fileTimeLocal[E_FT_ACCESS]);
	(void)::FileTimeToLocalFileTime(&findData.ftLastWriteTime,	&fileTimeLocal[E_FT_UPDATE]);
	(void)::LocalFileTimeToFileTime(&fileTimeLocal[E_FT_CREATE], &fileTime[E_FT_CREATE]);
	(void)::LocalFileTimeToFileTime(&fileTimeLocal[E_FT_ACCESS], &fileTime[E_FT_ACCESS]);
	(void)::LocalFileTimeToFileTime(&fileTimeLocal[E_FT_UPDATE], &fileTime[E_FT_UPDATE]);
	DWORD dwFlagsAndAttributes = _isFile ? FILE_ATTRIBUTE_NORMAL: FILE_FLAG_BACKUP_SEMANTICS;
	LPCWSTR lpFileNameDst = reinterpret_cast<LPCWSTR>(_p_dst);
	HANDLE handle_dst = ::CreateFileW(lpFileNameDst, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, dwFlagsAndAttributes, NULL);
	if (handle_dst == INVALID_HANDLE_VALUE)
	{
		return false;
	}
	BOOL ret = ::SetFileTime(handle_dst, &fileTime[E_FT_CREATE], &fileTime[E_FT_ACCESS], &fileTime[E_FT_UPDATE]);
	if (ret == 0)
	{
		return false;
	}
	CloseHandle(handle_dst);
	return true;
}

static bool ShellMkDirTree(std::wstring& _wstr_path_src, std::wstring& _wstr_path_dst, std::vector<std::wstring>& _vct_rel, const bool _is_make, std::map<std::wstring, std::wstring>& _map_path)
{
	std::wstringstream wss_src;
	std::wstringstream wss_dst;
	wss_src << _wstr_path_src;
	wss_dst << _wstr_path_dst;
	if (_is_make && !ShellMkDir(_wstr_path_dst.c_str()))
	{
		return false;
	}
	if (_is_make)
	{
		(void)ShellSetFileDirectoryTime(_wstr_path_src.c_str(), _wstr_path_dst.c_str(), false);
	}
	for (std::vector<std::wstring>::iterator it = _vct_rel.begin(); it != _vct_rel.end(); ++it)
	{
		if (_map_path.count(_wstr_path_src) == 0)
		{
			_map_path[_wstr_path_src] = *it;
		}
		wss_src	<< L"\\" << *it;
		wss_dst	<< L"\\" << *it;
		_wstr_path_src = wss_src.str();
		_wstr_path_dst = wss_dst.str();
		if (_is_make && !ShellMkDir(_wstr_path_dst.c_str()))
		{
			return false;
		}
		if (_is_make && !ShellSetFileDirectoryTime(_wstr_path_src.c_str(), _wstr_path_dst.c_str(), false))
		{
			return false;
		}
	}
	return true;
}

static void ShellPrintFile(const wchar_t* _p_str)
{
	::OutputDebugStringW(_p_str);
	int size = WideToStr(_p_str, g_global.read_print, PRINT_LEN);
	printf(g_global.read_print);
	if (g_global.h_log != INVALID_HANDLE_VALUE && size > 1)
	{
		::WriteFile(g_global.h_log, g_global.read_print, size - 1, NULL, NULL);
	}
}

static void ShellPrintFileInfo(const wchar_t* _p_cmd, const unsigned long _err, const unsigned __int64 _size, const wchar_t* _p_time, const wchar_t* _p_hash, const wchar_t* _p_file)
{
	std::wstringstream wss_err;
	wss_err << std::hex << std::setw(4) << std::setfill(L'0') << _err;
	std::wstringstream wss;
	wss	<< _p_cmd << L" " << L"0x" << wss_err.str().c_str() << L" " << _p_hash << L" " << std::setw(20) << _size << L" " << _p_time << L" " << _p_file << L"\x0d\x0a";
	ShellPrintFile(wss.str().c_str());
}

static void ShellListCopyLink(const int _cmd, const wchar_t* _p_src, const wchar_t* _p_dst)
{
	LPCWSTR lpFrom = reinterpret_cast<LPCWSTR>(_p_src);
	LPCWSTR lpNew  = reinterpret_cast<LPCWSTR>(_p_dst);
	unsigned long err = 0;
	switch (_cmd)
	{
	case E_CMD_LIST:
		ShellPrintFileInfo(g_global.wcs_cmd, 0, g_global.file_size, &g_global.file_time[E_FT_UPDATE][POS_DATE_TIME_PRINT], L"", _p_dst);
		break;
	case E_CMD_COPY:
		if (::CopyFileW(lpFrom, lpNew, FALSE) == FALSE)	// ForceWrite
		{
			err = static_cast<unsigned long>(::GetLastError());
		}
		ShellPrintFileInfo(g_global.wcs_cmd, err, g_global.file_size, &g_global.file_time[E_FT_UPDATE][POS_DATE_TIME_PRINT], L"", _p_dst);
		break;
	case E_CMD_LINK:
		if (::CreateHardLinkW(lpNew, lpFrom, NULL) == FALSE)
		{
			err = static_cast<unsigned long>(::GetLastError());
		}
		ShellPrintFileInfo(g_global.wcs_cmd, err, g_global.file_size, &g_global.file_time[E_FT_UPDATE][POS_DATE_TIME_PRINT], L"", _p_dst);
		break;
	}
	g_global.all_file_count++;
	g_global.all_file_size += g_global.file_size;
}

static byte s_read_buf[READ_BUF_SIZE];
static void ShellHash(const wchar_t* _p_src, const wchar_t* _p_dst)
{
	HCRYPTPROV hCryptProv;
	HCRYPTHASH hCryptHash = 0;
	HANDLE handle = INVALID_HANDLE_VALUE;
	ALG_ID	algid = CALG_MD5;
	byte hash[MD5_LEN] = {0};
	DWORD dwHashLength = MD5_LEN;
	DWORD dwRead = 0;
	size_t	len;
	int is_d88;
	bool skip = false;
	unsigned long err = 0;
	/* CRYPT_VERIFYCONTEXT : 他のパラメータを指定すると Guest アカウントで動作しない */
	if (::CryptAcquireContextW(&hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) != TRUE)
	{
		skip = true;
		err = static_cast<unsigned long>(::GetLastError());
		printf("ERR %s:%d\n", __func__, __LINE__);
	}
	if (skip == false && ::CryptCreateHash(hCryptProv, algid, 0, 0, &hCryptHash) != TRUE)
	{
		skip = true;
		err = static_cast<unsigned long>(::GetLastError());
		printf("ERR %s:%d\n", __func__, __LINE__);
	}
	if (skip == false)
	{
		handle = ::CreateFileW(_p_src, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_READONLY | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
		if (handle == INVALID_HANDLE_VALUE)
		{
			skip = true;
			err = static_cast<unsigned long>(::GetLastError());
			printf("ERR %s:%d\n", __func__, __LINE__);
		}
	}
	is_d88 = 0;
	if (skip == false)
	{
		len = wcsnlen_s(_p_src, MAX_LEN);
		if (len > 4)
		{
			if (_wcsnicmp(&_p_src[len - 4], L".d88", 5) == 0)
			{
				is_d88 = 1;
			}
		}
	}
	if (skip == false)
	{
		do
		{
			dwRead = 0;
			if (::ReadFile(handle, s_read_buf, READ_BUF_SIZE, &dwRead, NULL) == 0)
			{
				skip = true;
				err = static_cast<unsigned long>(::GetLastError());
				printf("ERR %s:%d\n", __func__, __LINE__);
				break;
			}
			if (is_d88 != 0)
			{
				memset(s_read_buf, 0, 0x20);	/* Clear Headder */
				is_d88 = 0;
			}
			if (::CryptHashData(hCryptHash, s_read_buf, dwRead, 0) != TRUE)
			{
				skip = true;
				err = static_cast<unsigned long>(::GetLastError());
				printf("ERR %s:%d\n", __func__, __LINE__);
				break;
			}
		} while (dwRead != 0);
	}
	if (skip == false && ::CryptGetHashParam(hCryptHash, HP_HASHVAL, hash, &dwHashLength, 0) != TRUE)
	{
		skip = true;
		err = static_cast<unsigned long>(::GetLastError());
		printf("ERR %s:%d\n", __func__, __LINE__);
	}
	if (handle != INVALID_HANDLE_VALUE)
	{
		::CloseHandle(handle);
	}
	if (hCryptHash)
	{
		::CryptDestroyHash(hCryptHash);
	}
	if (hCryptProv)
	{
		::CryptReleaseContext(hCryptProv, 0);
	}
	std::wstringstream wss_md5;
	if (skip == false)
	{
		for (int i = 0; i < MD5_LEN; i++)
		{
			unsigned int val = static_cast<unsigned int>(hash[i]);
			wss_md5 << std::setfill(L'0') << std::hex << std::setw(2) << val;
		}
	}
	ShellPrintFileInfo(g_global.wcs_cmd, err, g_global.file_size, &g_global.file_time[E_FT_UPDATE][POS_DATE_TIME_PRINT], wss_md5.str().c_str(), _p_dst);
	g_global.all_file_count++;
	g_global.all_file_size += g_global.file_size;
}

static void ShellFullPathFile(const wchar_t* _p_src, const wchar_t* _p_dst, const wchar_t* _p_file, std::vector<std::wstring>& _vct_rel)
{
	std::wstring wstr_file = _p_file;
	std::wstring wstr_ext_src = g_global.reg_value[E_REG_EXT_SRC];
	if (wstr_ext_src.length() > 0)
	{
		std::transform(wstr_ext_src.begin(), wstr_ext_src.end(), wstr_ext_src.begin(), ::tolower);
		size_t pos_ext_src = wstr_file.rfind(L'.');
		if (pos_ext_src != std::string::npos)
		{
			std::wstring wstr_match_src = wstr_file.substr(pos_ext_src + 1);
			std::transform(wstr_match_src.begin(), wstr_match_src.end(), wstr_match_src.begin(), ::tolower);
			if (wstr_match_src.compare(wstr_ext_src) != 0)
			{
				return;
			}
		}
	}
	std::wstring wstr_path_src = _p_src;
	std::wstring wstr_path_dst = _p_dst;
	bool is_make = true;
	if (g_global.n_cmd == E_CMD_LIST || g_global.n_cmd == E_CMD_HASH || g_global.n_cmd == E_CMD_PACK)
	{
		is_make = false;
	}
	if (ShellMkDirTree(wstr_path_src, wstr_path_dst, _vct_rel, is_make, g_global.map_path))
	{
		std::wstringstream wss_src;
		std::wstringstream wss_dst;
		wss_src	<< wstr_path_src << L"\\" << _p_file;
		wss_dst	<< wstr_path_dst << L"\\" << _p_file;
		if (g_global.is_get_volume_label == 0)
		{
			g_global.is_get_volume_label  = 1;
			wchar_t* p_file = &wss_src.str()[0];
			ShellGetFullPath(wss_src.str().c_str(), g_global.wcs_full_path, FULL_PATH_LEN, &p_file);
			wchar_t wcs_drive[4];
			wcsncpy_s(wcs_drive, 4, g_global.wcs_full_path, 3);
			wcs_drive[3] = L'\0';
			ShellGetVolumeInfo(wcs_drive, g_global.wcs_volume_label, VOLUME_LABEL_LEN, g_global.wcs_file_system, FILE_SYSTEM_LEN);
			WideToStr(g_global.wcs_volume_label, g_global.str_volume_label, VOLUME_LABEL_LEN);
			WideToStr(g_global.wcs_file_system,  g_global.str_file_system,   FILE_SYSTEM_LEN);
		}
		switch (g_global.n_cmd)
		{
		case E_CMD_LIST:
		case E_CMD_COPY:
		case E_CMD_LINK:
			ShellListCopyLink(g_global.n_cmd, wss_src.str().c_str(), wss_dst.str().c_str());
			break;
		case E_CMD_HASH:
			ShellHash(wss_src.str().c_str(), wss_dst.str().c_str());
			break;
		default:
			break;
		}
	}
}

static void SetDateTimeFormat(const int* _p_time, wchar_t* _p_val)
{
	int	nYear	= _p_time[E_DT_YEAR];
	int	nMonth	= _p_time[E_DT_MONTH];
	int	nDay	= _p_time[E_DT_DAY];
	int	nHour	= _p_time[E_DT_HOUR];
	int	nMinute	= _p_time[E_DT_MINUTE];
	int	nSecond	= _p_time[E_DT_SECOND];
	{
		std::wstringstream wss;
		/* YYYY-MM-DD HH:MM:SS */
		wss	<< std::setfill(L'0') << std::setw(4) << nYear		<< L"-"
			<< std::setfill(L'0') << std::setw(2) << nMonth		<< L"-"
			<< std::setfill(L'0') << std::setw(2) << nDay		<< L"_"
			<< std::setfill(L'0') << std::setw(2) << nHour		<< L":"
			<< std::setfill(L'0') << std::setw(2) << nMinute	<< L":"
			<< std::setfill(L'0') << std::setw(2) << nSecond;
		wss >> &_p_val[POS_DATE_TIME_PRINT];
	}
	{
		std::wstringstream wss;
		/* YYYYMMDDHHMMSS */
		wss	<< std::setfill(L'0') << std::setw(4) << nYear
			<< std::setfill(L'0') << std::setw(2) << nMonth
			<< std::setfill(L'0') << std::setw(2) << nDay
			<< std::setfill(L'0') << std::setw(2) << nHour
			<< std::setfill(L'0') << std::setw(2) << nMinute
			<< std::setfill(L'0') << std::setw(2) << nSecond;
		wss >> &_p_val[POS_DATE_TIME_STR_ST];
	}
}

static void TimeStampTool(const wchar_t* _p_src, const wchar_t* _p_rel, std::vector<std::wstring>& _vct_rel)
{
	std::wstringstream wss;
	wss	<< _p_src;
	{
		for (std::vector<std::wstring>::iterator it = _vct_rel.begin(); it != _vct_rel.end(); ++it)
		{
			wss	<< L"\\" << *it;
		}
	}
	if (_p_rel[0] != L'\0')
	{
		wss	<< L"\\" << _p_rel;
	}
	wss	<< L"\\*";
	std::wstring path(wss.str());
	LPCWSTR	lpFileName = reinterpret_cast<LPCWSTR>(path.c_str());
	WIN32_FIND_DATAW find;
	HANDLE handle = ::FindFirstFileW(lpFileName, &find);
	if (INVALID_HANDLE_VALUE == handle) 
	{
		return;
	}
	std::vector<std::wstring> vct_dir;
	std::vector<std::wstring> vct_file;
	ULARGE_INTEGER	ulFileSize;
	do
	{
		if (find.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			if (wcscmp(find.cFileName, L".")  != 0 &&
				wcscmp(find.cFileName, L"..") != 0)
			{
				vct_dir.push_back(find.cFileName);
			}
		}
		else
		{
			vct_file.push_back(find.cFileName);
			FILETIME	  fileTime[E_FT_MAX] = {0};
			SYSTEMTIME	systemTime[E_FT_MAX] = {0};
			int n_time[E_FT_MAX][E_DT_MAX] = {0};
			(void)::FileTimeToLocalFileTime(&find.ftCreationTime,   &fileTime[E_FT_CREATE]);
			(void)::FileTimeToLocalFileTime(&find.ftLastAccessTime, &fileTime[E_FT_ACCESS]);
			(void)::FileTimeToLocalFileTime(&find.ftLastWriteTime,  &fileTime[E_FT_UPDATE]);
			(void)::FileTimeToSystemTime(&fileTime[0] , &systemTime[0]);
			(void)::FileTimeToSystemTime(&fileTime[1] , &systemTime[1]);
			(void)::FileTimeToSystemTime(&fileTime[2] , &systemTime[2]);
			for (int i = 0; i < E_FT_MAX; i++)
			{
				n_time[i][E_DT_YEAR]	= systemTime[i].wYear;
				n_time[i][E_DT_MONTH]	= systemTime[i].wMonth;
				n_time[i][E_DT_WEEK]	= systemTime[i].wDayOfWeek;
				n_time[i][E_DT_DAY]		= systemTime[i].wDay;
				n_time[i][E_DT_HOUR]	= systemTime[i].wHour;
				n_time[i][E_DT_MINUTE]	= systemTime[i].wMinute;
				n_time[i][E_DT_SECOND]	= systemTime[i].wSecond;
				n_time[i][E_DT_MILLI]	= systemTime[i].wMilliseconds;
				SetDateTimeFormat(n_time[i], g_global.file_time[i]);
			}
			/* [POS_DATE_TIME_STR_ST] YYYYMMDDHHMMSS */
			int ret_from = wcscmp(&g_global.file_time[E_FT_UPDATE][POS_DATE_TIME_STR_ST], g_global.reg_value[E_REG_FROM_DATE_TIME]);
			int ret_to   = wcscmp(&g_global.file_time[E_FT_UPDATE][POS_DATE_TIME_STR_ST], g_global.reg_value[E_REG_TO_DATE_TIME]);
			if (ret_from >= 0 && ret_to < 0)
			{
				ulFileSize.u.HighPart = find.nFileSizeHigh;
				ulFileSize.u.LowPart  = find.nFileSizeLow;
				g_global.file_size = static_cast<unsigned __int64>(ulFileSize.QuadPart);
				std::vector<std::wstring> vct_rel;
				{
					for (std::vector<std::wstring>::iterator it = _vct_rel.begin(); it != _vct_rel.end(); ++it)
					{
						vct_rel.push_back(*it);
					}
				}
				if (_p_rel[0] != L'\0')
				{
					std::wstring str_rel(_p_rel);
					vct_rel.push_back(str_rel);
				}
				const wchar_t* p_file = static_cast<const wchar_t*>(find.cFileName);
				ShellFullPathFile(_p_src, g_global.reg_value[E_REG_DST], p_file, vct_rel);
			}
		}
	}
	while (::FindNextFileW(handle, &find) != 0);
	(void)::FindClose(handle);
	std::sort(vct_dir.begin(),vct_dir.end());
	std::sort(vct_file.begin(),vct_file.end());
	std::vector<std::wstring> vct_rel;
	{
		for (std::vector<std::wstring>::iterator it = _vct_rel.begin(); it != _vct_rel.end(); ++it)
		{
			vct_rel.push_back(*it);
		}
	}
	if (_p_rel[0] != L'\0')
	{
		std::wstring str_rel(_p_rel);
		vct_rel.push_back(str_rel);
	}
	{
		for (std::vector<std::wstring>::iterator it = vct_dir.begin(); it != vct_dir.end(); ++it)
		{
			std::wstring str_dir(*it);
			TimeStampTool(_p_src, str_dir.c_str(), vct_rel);
		}
	}
}

static bool TimeStampToolInit()
{
	g_global.pp_str_reg_key	= const_cast<char**>(g_str_reg_key);
	g_global.pp_str_cmd		= const_cast<char**>(g_str_cmd);
	g_global.is_get_volume_label = 0;
	g_global.all_file_count	= 0;
	g_global.all_file_size	= 0;
	return true;
}

static bool TimeStampToolReg()
{
	if (!ShellRegCreate(REG_KEY_STR_CONVERT, &g_global.hkey))
	{
		return false;
	}
	int n_count = 0;
	if (!ShellRegReadWriteInt(REG_KEY_COUNT, REG_NAME_COUNT, &n_count, 0))
	{
		return false;
	}
	if (g_global.n_cmd >= E_CMD_MAX)
	{
		return false;
	}
	{
		std::wstringstream wss;
		wss	<< n_count;
		wss >> g_global.wcs_count;
		std::stringstream ss;
		ss	<< n_count;
		ss	>> g_global.str_count;
	}
	(void)memset(g_global.reg_value, 0, sizeof(g_global.reg_value));
	for (int i = 0; g_global.pp_str_reg_key[i] != NULL; i++)
	{
		int n_size = VALUE_LEN;
		if (!ShellRegReadDelete(g_global.pp_str_reg_key[i], g_global.wcs_count, g_global.reg_value[i], &n_size, true))
		{
			break;
		}
	}
	{
		std::wstringstream wss;
		wss << g_global.reg_value[E_REG_CMD];
		wss >> g_global.n_cmd;
	}
	g_global.p_str_cmd = g_global.pp_str_cmd[g_global.n_cmd];
	StrToWide(g_global.p_str_cmd, g_global.wcs_cmd, CMD_LEN);
	if (g_global.reg_value[E_REG_SRC][0] == L'\0' ||
		g_global.reg_value[E_REG_DST][0] == L'\0')
	{
		return false;
	}
	if (wcscmp(g_global.reg_value[E_REG_SRC], g_global.reg_value[E_REG_DST]) == 0)
	{
		return false;
	}
	size_t n_len_from = wcsnlen_s(g_global.reg_value[E_REG_FROM_DATE_TIME], VALUE_LEN);
	if (n_len_from < LEN_DATE_TIME_STR)	/* YYYYMMDDHHMMSS */
	{
		std::wstring wstr_fill(LEN_DATE_TIME_STR, L'0');
		wcscat_s(g_global.reg_value[E_REG_FROM_DATE_TIME], VALUE_LEN, wstr_fill.c_str());
		g_global.reg_value[E_REG_FROM_DATE_TIME][LEN_DATE_TIME_STR] = L'\0';
	}
	size_t n_len_to = wcsnlen_s(g_global.reg_value[E_REG_TO_DATE_TIME], VALUE_LEN);
	if (n_len_to < LEN_DATE_TIME_STR)	/* YYYYMMDDHHMMSS */
	{
		std::wstring wstr_fill(LEN_DATE_TIME_STR, L'9');
		wcscat_s(g_global.reg_value[E_REG_TO_DATE_TIME], VALUE_LEN, wstr_fill.c_str());
		g_global.reg_value[E_REG_TO_DATE_TIME][LEN_DATE_TIME_STR] = L'\0';
	}
	::SHGetSpecialFolderPathW(NULL, g_global.desktop_path, CSIDL_DESKTOP, 0);
	::GetLocalTime(&g_global.stime_start);
	{
		std::wstringstream wss;
		wss << g_global.wcs_cmd << L"_";
		wss << std::setfill(L'0') << std::setw(4) << g_global.stime_start.wYear;
		wss << std::setfill(L'0') << std::setw(2) << g_global.stime_start.wMonth;
		wss << std::setfill(L'0') << std::setw(2) << g_global.stime_start.wDay << L"_";
		wss << std::setfill(L'0') << std::setw(2) << g_global.stime_start.wHour;
		wss << std::setfill(L'0') << std::setw(2) << g_global.stime_start.wMinute;
		wss << std::setfill(L'0') << std::setw(2) << g_global.stime_start.wSecond;
		wss << L".txt";
		wss >> g_global.wcs_file_log;
	}
	/* wcs_file_log -> str_file_log */
	WideToStr(g_global.wcs_file_log, g_global.str_file_log, LOG_FILE_LEN);
	{
		std::wstringstream wss;
		wss << g_global.desktop_path << L"\\";
		wss << g_global.wcs_file_log;
		wss >> g_global.wcs_path_log;
	}
	g_global.h_log = ::CreateFileW(g_global.wcs_path_log, GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	std::vector<std::wstring> vct_rel;
	TimeStampTool(g_global.reg_value[E_REG_SRC], L"", vct_rel);
	switch (g_global.n_cmd)
	{
	case E_CMD_PACK:
		{
			std::wstring wstr_ext_src = g_global.reg_value[E_REG_EXT_SRC];
			std::wstring wstr_ext_dst = g_global.reg_value[E_REG_EXT_DST];
			if (wstr_ext_src.length() == 0)
			{
				wstr_ext_src = L"\\*.*";
			}
			else
			{
				wstr_ext_src = L"\\*." + wstr_ext_src;
			}
			if (wstr_ext_dst.length() == 0)
			{
				wstr_ext_dst = L".zip";
			}
			else
			{
				wstr_ext_dst = L"." + wstr_ext_dst;
			}
			std::wstringstream wss;
			for (std::map<std::wstring, std::wstring>::iterator it = g_global.map_path.begin(); it != g_global.map_path.end(); ++it)
			{
				wss	<< L"%%CMD%% %%OPT%% "
					<< L"\"" << it->first << L"\\" << it->second << wstr_ext_dst << L"\" ";
				wss	<< L"\"" << it->first << L"\\" << it->second << wstr_ext_src << L"\" %%OPT2%%\x0d\x0a";
			}
			ShellPrintFile(wss.str().c_str());
		}
		break;
	default:
		break;
	}
	::CloseHandle(g_global.h_log);
	::GetLocalTime(&g_global.stime_end);
	::SystemTimeToFileTime(&g_global.stime_start, &g_global.ftime_start);
	::SystemTimeToFileTime(&g_global.stime_end,   &g_global.ftime_end);
	g_global.n_time_diff  = *((unsigned __int64*)&g_global.ftime_end);
	g_global.n_time_diff -= *((unsigned __int64*)&g_global.ftime_start);
	::FileTimeToSystemTime((FILETIME*)&g_global.n_time_diff, &g_global.stime_diff);
	StrToWide(REPORT_FILE_NAME, g_global.wcs_path_report, REPORT_FILE_PATH_LEN);
	(void)::RegCloseKey(g_global.hkey);
	{
		std::wstringstream wss;
		wss << g_global.desktop_path << L"\\";
		wss << g_global.wcs_path_report;
		wss >> g_global.wcs_path_report;
	}
	g_global.h_report = ::CreateFileW(g_global.wcs_path_report, FILE_SHARE_READ | GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	::SetFilePointer(g_global.h_report, 0, NULL, FILE_END);
	{
		std::stringstream ss;
		ss << g_global.p_str_cmd;
		ss << "\t";
		ss << std::setfill('0') << std::setw(4) << g_global.stime_start.wYear	<< "-";
		ss << std::setfill('0') << std::setw(2) << g_global.stime_start.wMonth	<< "-";
		ss << std::setfill('0') << std::setw(2) << g_global.stime_start.wDay	<< "_";
		ss << std::setfill('0') << std::setw(2) << g_global.stime_start.wHour	<< ":";
		ss << std::setfill('0') << std::setw(2) << g_global.stime_start.wMinute	<< ":";
		ss << std::setfill('0') << std::setw(2) << g_global.stime_start.wSecond	<< ".";
		ss << std::setfill('0') << std::setw(3) << g_global.stime_start.wMilliseconds;
		ss << "\t";
		ss << std::setfill('0') << std::setw(4) << g_global.stime_end.wYear		<< "-";
		ss << std::setfill('0') << std::setw(2) << g_global.stime_end.wMonth	<< "-";
		ss << std::setfill('0') << std::setw(2) << g_global.stime_end.wDay		<< "_";
		ss << std::setfill('0') << std::setw(2) << g_global.stime_end.wHour		<< ":";
		ss << std::setfill('0') << std::setw(2) << g_global.stime_end.wMinute	<< ":";
		ss << std::setfill('0') << std::setw(2) << g_global.stime_end.wSecond	<< ".";
		ss << std::setfill('0') << std::setw(3) << g_global.stime_end.wMilliseconds;
		ss << "\t";
		__int64 n_hour  = g_global.n_time_diff / 10000 / 1000 / 60 / 60;
		ss << std::setfill('0') << std::setw(6) << n_hour						<< ":";
		ss << std::setfill('0') << std::setw(2) << g_global.stime_diff.wMinute	<< ":";
		ss << std::setfill('0') << std::setw(2) << g_global.stime_diff.wSecond	<< ".";
		ss << std::setfill('0') << std::setw(3) << g_global.stime_diff.wMilliseconds;
		ss << "\t";
		ss << std::setfill(' ') << std::setw(10) << g_global.all_file_count;
		ss << "\t";
		ss << std::setfill(' ') << std::setw(20) << g_global.all_file_size;
		ss << "\t";
		ss << g_global.str_volume_label;
		ss << "\t";
		ss << g_global.str_file_system;
		ss << "\t";
		ss << g_global.str_file_log << "\x0d\x0a";
		::WriteFile(g_global.h_report, ss.str().c_str(), (DWORD)ss.str().size(), NULL, NULL);
	}
	CloseHandle(g_global.h_report);
	return true;
}

int main(int argc, char *argv[])
{
	TimeStampToolInit();
	if (argc > 2)
	{
		int n_count = 0;
		if (!ShellRegReadWriteInt(REG_KEY_COUNT, REG_NAME_COUNT, &n_count, 1))
		{
			return 1;
		}
		std::stringstream ss;
		ss	<< n_count;
		ss	>> g_global.str_count;
		for (int i = 0; g_global.pp_str_reg_key[i] != NULL; i++)
		{
			if (i < argc)
			{
				(void)ShellRegWrite(g_global.pp_str_reg_key[i], g_global.str_count, argv[i + 1]);
			}
			else
			{
				(void)ShellRegWrite(g_global.pp_str_reg_key[i], g_global.str_count, "");
			}
		}
		if (!TimeStampToolReg())
		{
			return 2;
		}
	}
	return 0;
}
