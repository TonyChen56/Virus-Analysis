// ConsoleApplication1.cpp : 定义控制台应用程序的入口点。
//
// 修复EXE.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include<atlstr.h>
#include<Windows.h>

//获取后缀名
CString GetFileHouzhui(CString FileName)
{
	WCHAR* pStr = new WCHAR[FileName.GetLength() + 1]{};
	memcpy(pStr, FileName.GetBuffer(), FileName.GetLength() * 2);
	for (int i = FileName.GetLength(); i > 0; i--)
	{
		if (pStr[i] == L'.')
		{
			return &pStr[i + 1];
		}
	}
	return L"";
}

//还原EXE
BOOL DeCodeEXE(CString Path)
{
	HANDLE hFile = CreateFile(Path,
		GENERIC_READ,
		FALSE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("文件打开失败\n");
		return 0;
	}


	HANDLE hFile2 = CreateFile(L"C:\\Windows\\System32\\drivers\\spo0lsv.exe",
		GENERIC_READ,
		FALSE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (hFile2 == INVALID_HANDLE_VALUE)
	{
		printf("文件打开失败\n");
		return 0;
	}

	DWORD VirSize = GetFileSize(hFile2, NULL);

	//获取文件大小
	DWORD dwSize = GetFileSize(hFile, NULL);

	CloseHandle(hFile2);

	char* g_lpBase = NULL;

	if (dwSize < 11534336)
	{
		g_lpBase = new char[dwSize]{};
		//读文件
		DWORD dwCount = 1;
		BOOL bRet =
			ReadFile(hFile, g_lpBase/*pBuf*/, dwSize, &dwCount, NULL);

		//释放资源
		CloseHandle(hFile);

		char* New_lpBase = g_lpBase + VirSize;

		//判断新的指针是不是PE结构

		auto pDos = (PIMAGE_DOS_HEADER)New_lpBase;
		if (pDos->e_magic != IMAGE_DOS_SIGNATURE/*0x4D5A*/)
		{
			return FALSE;
		}
		PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + New_lpBase);
		if (pNt->Signature != IMAGE_NT_SIGNATURE/*0x4550*/)
		{
			return FALSE;
		}

		//char* End_lpBase = g_lpBase + dwSize;
		BOOL IsVir = FALSE;
		int index = 1;

		DWORD OldFileSize = 0;
		if (g_lpBase[dwSize - index] == 1)
		{
			index++;
			while (g_lpBase[dwSize - index] >= 0x30 && g_lpBase[dwSize - index] <= 0x39)
			{
				int nNum = 1;
				for (int Count = 1; Count < index - 1; Count++)
				{
					nNum *= 10;
				}
				OldFileSize += nNum*(g_lpBase[dwSize - index] - '0');
				index++;
			}
		}


		for (int i = 1; i < MAX_PATH + 20; i++)
		{
			//判断结尾是不是Whboy
			if (g_lpBase[dwSize - i] == 0x57)
				if (g_lpBase[dwSize - i + 1] == 0x68)
					if (g_lpBase[dwSize - i + 2] == 0x42)
						if (g_lpBase[dwSize - i + 3] == 0x6F)
							if (g_lpBase[dwSize - i + 4] == 0x79)
							{
								//dwSize -= i;
								IsVir = TRUE;
								break;
							}
		}
		if (IsVir)
		{

			//dwSize -= VirSize;
			SetFileAttributes(Path.GetBuffer(), 0x80);
			DeleteFile(Path.GetBuffer());
			HANDLE hFile = CreateFile(Path,
				GENERIC_WRITE,
				FALSE,
				NULL,
				OPEN_ALWAYS,
				FILE_ATTRIBUTE_NORMAL,
				NULL);
			if (hFile == INVALID_HANDLE_VALUE)
			{
				printf("文件打开失败\n");
				return 0;
			}
			DWORD temp;
			WriteFile(hFile, New_lpBase, OldFileSize, &temp, NULL);
			CloseHandle(hFile);

			delete g_lpBase/*pBuf*/;
			return 0;
		}
	}

	return 0;
}

void FindFile(CString Path)
{
	//1.尝试查找第一个文件
	WIN32_FIND_DATA FileInfo = { 0 };
	HANDLE File = FindFirstFile(Path + "\\*", &FileInfo);

	//2.遍历文件夹的所有文件
	if (File != INVALID_HANDLE_VALUE)
	{
		do
		{
			//3.1如果是文件夹就递归
			if (FileInfo.dwFileAttributes &FILE_ATTRIBUTE_DIRECTORY)
			{
				//3.1.1排除两个文件夹
				if (CString(".") != FileInfo.cFileName &&CString("..") != FileInfo.cFileName)
					FindFile(Path + CString("\\") + FileInfo.cFileName);
			}
			else
			{
				//3.2如果是文件
				//3.3判断是否为.exe结尾
				CString Houzhui = GetFileHouzhui(FileInfo.cFileName);
				if (Houzhui.CompareNoCase(L"exe") == 0)
				{
					DeCodeEXE(Path + L"\\" + FileInfo.cFileName);
				}

			}
		} while (FindNextFile(File, &FileInfo));
	}
}



// int _tmain(int argc, _TCHAR* argv[])
// {
// 	printf("输入要遍历的文件夹\n");
// 	char Path[MAX_PATH] = {};
// 	scanf_s("%[^\n]", Path, MAX_PATH);
// 
// 	CString WPath(Path);
// 
// 	FindFile(WPath);
// 
// 	return 0;
// }

