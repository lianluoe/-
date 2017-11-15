#include "TSocket_Mgr.h"
#include <iostream>
using namespace std;

//目录字典结构
struct DIR_NODE
{
	char szDir[512];
	DIR_NODE *pNext;
	DIR_NODE()
	{
		memset(this, 0, sizeof(DIR_NODE));
	}
};

struct DIR_DICT
{
	void *pUnKnow;
	DIR_NODE *pHead;
};

enum THREAD_STATE 
{
	STOP = 0,
	RUN
};

HANDLE g_hConsoleOutput;
bool g_bSSL = false;
bool g_bSetPort = false;
int g_iThreadMax = 10;
int g_iThreadNum = 0;
int g_dwMilliseconds = 50;
int g_iTimeOut = 16;
int g_iThreadState = RUN;
int g_iExistNum = 0;
char g_szRootPath[512] = {'\0'};
char g_szFileName[128] = {'\0'};
DIR_DICT g_tDirDict;
CRITICAL_SECTION tCS_Count;
CRITICAL_SECTION tCS_Print;

/*程序启动提示信息*/
void HeadMsg()
{
	system("cls");
	g_hConsoleOutput = GetStdHandle(STD_OUTPUT_HANDLE);
	if ( g_hConsoleOutput == INVALID_HANDLE_VALUE )
	{
		printf("GetStdHandle failed!\n");
	}
	SetConsoleTextAttribute(g_hConsoleOutput, BACKGROUND_BLUE|BACKGROUND_GREEN|FOREGROUND_BLUE|FOREGROUND_GREEN|FOREGROUND_INTENSITY);
	printf(" Welcome to the real world!            wwwscan v3.0 Build 061007 <SSL Inside> \r\n");
	SetConsoleTextAttribute(g_hConsoleOutput, BACKGROUND_BLUE|BACKGROUND_GREEN|FOREGROUND_BLUE|FOREGROUND_INTENSITY);
	printf("                                                                    By uhhuhy \r\n");
	SetConsoleTextAttribute(g_hConsoleOutput, BACKGROUND_BLUE|BACKGROUND_GREEN|FOREGROUND_BLUE|FOREGROUND_GREEN|FOREGROUND_RED|FOREGROUND_INTENSITY);
	printf("                                                          http://www.xsec.org \r\n");
	SetConsoleTextAttribute(g_hConsoleOutput, FOREGROUND_BLUE|FOREGROUND_GREEN|FOREGROUND_RED);
	printf("\r\n");
}

/*程序参数帮助信息*/
void HelpMsg(char *p)
{
	printf("<Usage>:  %s <HostName|Ip> [Options]\r\n", p);
	printf("<Options>:\n");
	printf("          -p port        : set http/https port\r\n");
	printf("          -m thread      : set max thread\r\n");
	printf("          -t timeout     : tcp timeout in seconds\r\n");
	printf("          -r rootpath    : set root path to scan\r\n");
	printf("          -ssl           : will use ssl\r\n");
	printf("<Example>:\n");
	printf("          %s www.target.com -p 8080 -m 10 -t 16\r\n", p);
	printf("          %s www.target.com -r \"/test/\" -p 80\r\n", p);
	printf("          %s www.target.com -ssl\r\n", p);
	printf("\r\n");
}

/*从文件中读出要扫描的目录字典*/
void ObtainDirDict(DIR_DICT &tDict, char* szFileName)
{
	int iCount = 0;
	char szBuf[512] = {'\0'};
	char *p = NULL;
	DIR_NODE *pPreNode = NULL;
	DIR_NODE *pNode = NULL;
	FILE* fd = fopen(szFileName, "r");
	if ( fd != NULL )
	{
		while ( fgets(szBuf, sizeof(szBuf)-1, fd) )
		{
			p = strchr(szBuf, '\n');
			if ( p )
				*p = 0;
			p = strchr(szBuf, '\r');
			if ( p )
				*p = 0;
			pNode = new DIR_NODE;
			strncpy(pNode->szDir, szBuf, sizeof(pNode->szDir)-1);
			if ( iCount )
				pPreNode->pNext = pNode;
			else
				tDict.pHead = pNode;
			pPreNode = pNode;
			++iCount;
		}
		if ( iCount )
			pPreNode->pNext = NULL;
		
		fclose(fd);
	}
	else
	{
		printf("Open %s failed! Error:%d\n", szFileName, GetLastError());
	}
}

/*获取服务器基本信息*/
bool GetTargetSrvInfo(TSocket_Addr &tAddr)
{
	TSocket_Opt tSockOpt;
	char* pPos = NULL;
	char szSend[1024] = {'\0'};
	char szRecv[1024] = {'\0'};
	char szBuf[1024] = {'\0'};
	char szTemp[512] = {'\0'};
	char szFileBuf[2048] = {'\0'};
	
	try
	{
		if ( tSockOpt.socket() )
		{
			if ( tSockOpt.connect(tAddr.szTargetIP, tAddr.iPort) )
			{
				printf("Connecting %s:%d...", tAddr.szTargetIP, tAddr.iPort);
				if ( tSockOpt.select( SEND, g_iTimeOut) )
				{
					printf("Succeed!\r\n");
					printf("Trying To Get Server Type...");
					memset(szSend, 0, sizeof(szSend));
					_snprintf(szSend, sizeof(szSend), "GET /nothisexistpage.html HTTP/1.1\r\nHost: %s\r\n\r\n", tAddr.szTarget);
					if ( !tSockOpt.send(szSend, strlen(szSend)) || !tSockOpt.select( RECV, g_iTimeOut) \
						|| !tSockOpt.recv(szRecv, sizeof(szRecv)) )
						throw "Failed!";
					
					if ( !strncmp(szRecv, "HTTP/", 5) )
					{
						pPos = strstr(szRecv, "Server:");
						if ( pPos != NULL )
						{
							memset(szBuf, 0, sizeof(szBuf));
							strncpy(szBuf, pPos, sizeof(szBuf)-1);
							pPos = strstr(szBuf, "\n");
							if ( pPos != NULL )
							{
								printf(" Succeed!\r\n");
								strncpy(szTemp, szBuf, strlen(szBuf)-strlen(pPos));
								printf("Server Type:  ");
								SetConsoleTextAttribute(g_hConsoleOutput, FOREGROUND_BLUE|FOREGROUND_RED|FOREGROUND_INTENSITY);
								printf("%s\r\n", szTemp);
								SetConsoleTextAttribute(g_hConsoleOutput, FOREGROUND_BLUE|FOREGROUND_GREEN|FOREGROUND_RED);
								
							}
							else
								printf("Failed!\r\n");
						}
						else
							printf("Failed!\r\n");
						
						printf("Testing If There Is A Default Turning Page...");
						
						if ( !strncmp(&szRecv[9], "200",  3) )
						{
							pPos = strstr(szRecv, "Content-Length: ");
							if ( pPos != NULL ) 
							{
								strncpy(szBuf, pPos+16, sizeof(szBuf)-1);
								strncpy(szTemp, szBuf, strlen(szBuf) - strlen(strstr(szBuf, "\n")));
								tAddr.iBaseCLen = atoi(szTemp);
							}
						}
						
						if ( tAddr.iBaseCLen )
							printf("Found!\r\n\r\n");
						else
							printf("Not Found!\r\n\r\n");
						
						DeleteFile(g_szFileName);
						memcpy(szFileBuf, "", strlen("<html>\r\n<head>\r\n"));
						char szStr[] = "<html>\r\n" \
							"<head>\r\n" \
							"<meta http-equiv=\"Content-Type\" content=\"text/html; charset=gb2312\">\r\n" \
							"<style type=\"text/css\">\r\n" \
							"<!--\r\n" \
							"body {  FONT-FAMILY: verdana;  font-size: 10pt; color: #000000} \r\n"
							"-->\r\n" \
							"</style>\r\n" \
							"<title>wwwscan v3.0 Scan Report</title>\r\n" \
							"</head>\r\n\r\n" \
							"<body bgcolor=\"#FFFFFF\">\r\n\r\n" \
							"<p align=\"left\">" \
							"<font face=\"Verdana\" size=\"3\">\r\n" \
							"wwwscan v3.0 scan report\r\n"
							"</font>" \
							"</p>\r\n" \
							"<hr>\r\n";
						memcpy(szFileBuf, szStr, strlen(szStr));
						FILE *fd = fopen(g_szFileName, "a");
						if ( fd != NULL )
						{
							fprintf(fd, "%s", szFileBuf);
							fclose(fd);
						}				
					}
					else
						throw "Failed!";
				}
				else
					throw "Failed!";
				
			}
		}
	}
	catch(char *e)
	{
		printf("error:%s\r\n", e);
		return false;
	}
	
	return true;
}

//检测目录是否存在
bool DirectoryCheck(char *szTarget, char *szTargetIP, int iPort, char *szDir, char *szBuf, int iMax, int iBaseCLen)
{
	TSocket_Opt tSockOpt;
	char szSend[2048] = {'\0'};
	char szRecv[1024] = {'\0'};
	char szBuffer[1024] = {'\0'};
	char szContent[512] = {'\0'};
	char szRet[512] = {'\0'};
	
	_snprintf(szSend, sizeof(szSend), "GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", szDir, szTarget);
	if ( !tSockOpt.socket() || !tSockOpt.connect(szTargetIP, iPort) 
		|| !tSockOpt.select(SEND, g_iTimeOut) || !tSockOpt.send(szSend, strlen(szSend)))
		return false;
	if ( !tSockOpt.select(RECV, g_iTimeOut) 
		|| !tSockOpt.recv(szRecv, sizeof(szRecv)) )
		return false;
	if ( !strncmp(&szRecv[9], "200", 3) )
	{
		char szBuf[1024] = {'\0'};
		char* p = strstr(szRecv, "Content-Length: ");
		if ( p != NULL )
		{
			strncpy(szBuffer, p+16, sizeof(szBuffer)-1);
			p = strstr(szBuffer, "\n");
			if ( p != NULL)
			{
				int iLen = strlen(szBuffer) - strlen(p);
				strncpy(szContent, szBuffer, iLen);
				if (atoi(szContent) == iBaseCLen)
				{
					return false;
				}
			}
		}
	}
	
	char* p = strstr(szRecv, "Server:");
	if ( p != NULL )
	{
		strncpy(szRet, szRecv, strlen(szRecv) - strlen(p));
		p = strchr(szRet, '\r');
		*p = '\0';
		if ( p != NULL )
			p = strchr(szRet, '\n');
		if ( p != NULL )
			*p = '\0';
	}
	
	strncpy(szBuf, szRet, iMax-1);
	
	if ( !strncmp(&szRecv[9], "200", 3) )
		return true;
	if ( !strncmp(&szRecv[9], "500", 3) )
		return true;
	
	if ( szDir[strlen(szDir)-1] == '/' )
	{
		if ( !strncmp(&szRecv[9], "403", 3) )
			return true;
	}			
	return false;
}

DWORD WINAPI ThreadProc(LPVOID lpParameter)
{
	char szTarget[256] = {'\0'};
	char szTargetIP[32] = {'\0'};
	char szDir[512] = {'\0'};
	char szBuf[64] = {'\0'};
	char szFileBuf[2048] = {'\0'};
	int iPort;
	int iBaseCLen;
	THREAD_PARAM tParam;
	
	memcpy(&tParam, reinterpret_cast<THREAD_PARAM*>(lpParameter), sizeof(THREAD_PARAM));
	strncpy(szTarget, tParam.szTarget, sizeof(szTarget)-1);
	strncpy(szTargetIP, tParam.szTargetIP, sizeof(szTargetIP)-1);
	strncpy(szDir, tParam.szDir, sizeof(szDir)-1);
	iPort = tParam.iPort;
	iBaseCLen = tParam.iBaseCLen;
	
	EnterCriticalSection(&tCS_Print);
	printf("                                                                             \r");
	printf("Checking:  %s...\r", &szDir);
	LeaveCriticalSection(&tCS_Print);
	
	if ( DirectoryCheck(szTarget, szTargetIP, iPort, szDir, szBuf, sizeof(szBuf)-1, iBaseCLen) )
	{
		++g_iExistNum;
		EnterCriticalSection(&tCS_Print);
		if ( strlen(szBuf) == 0 )
		{
			printf("Found:  %s  !!!\n", szDir);
		}
		else
		{
			printf("Found:  %s  (", szDir);
			SetConsoleTextAttribute(g_hConsoleOutput, FOREGROUND_GREEN|FOREGROUND_INTENSITY);
			printf("%s", szBuf);
			SetConsoleTextAttribute(g_hConsoleOutput, FOREGROUND_BLUE|FOREGROUND_GREEN|FOREGROUND_RED);
			printf(")  !!!\n");
		}
		LeaveCriticalSection(&tCS_Print);
		
		FILE* fd = fopen(g_szFileName, "a");
		if ( fd )
		{
			sprintf(
				szFileBuf,
				"<a href=\"http://%s:%d%s\">http://%s:%d%s</a>   <font face=\"Verdana\" color=\"#FF0000\" size=\"2\">%s</font><br>\n",
				szTarget,
				iPort,
				szDir,
				szTarget,
				iPort,
				szDir,
				szBuf);
			fprintf(fd, "%s", szFileBuf);
			fclose(fd);
		}
	}
	Sleep(100);
	EnterCriticalSection(&tCS_Count);
	--g_iThreadNum;
	LeaveCriticalSection(&tCS_Count);
	
	return 0;
}

//依次遍历目录字典列表，对于每个目录名都使用一个线程来进行探测
void ExploreWebDir(TSocket_Addr &tAddr, char* szRootPath)
{
	DIR_NODE *pDir = g_tDirDict.pHead;
	THREAD_PARAM tParam;
	unsigned long iId = 0;
	while ( pDir != NULL)
	{
		memset(&tParam, 0, sizeof(THREAD_PARAM));
		strncpy(tParam.szTargetIP, tAddr.szTargetIP, sizeof(tParam.szTargetIP)-1);
		strncpy(tParam.szTarget, tAddr.szTarget, sizeof(tParam.szTarget)-1);
		_snprintf(tParam.szDir, sizeof(tParam.szDir), "%s%s", szRootPath, pDir->szDir);
		tParam.iBaseCLen = tAddr.iBaseCLen;
		tParam.iPort = tAddr.iPort;
		tParam.pAddr = &tAddr;
		while ( g_iThreadNum >= g_iThreadMax )
			Sleep(100);
		HANDLE hHandle = CreateThread(NULL, NULL, &ThreadProc, reinterpret_cast<void*>(&tParam), 0, &iId);
		if ( hHandle )
		{
			EnterCriticalSection(&tCS_Count);
			++g_iThreadNum;
			LeaveCriticalSection(&tCS_Count);
			Sleep(g_dwMilliseconds);
			CloseHandle(hHandle);
		}
		pDir = pDir->pNext;
	}
	Sleep(1000);
	return;
}

int main(int argc, TCHAR* argv[])
{
	int iPort = 80;
	char szTarget[256] = {'\0'};
	char szTargetIP[32] = {'\0'};
	TSocket_Addr tAddrInfo;
	InitializeCriticalSection(&tCS_Count);
	InitializeCriticalSection(&tCS_Print);
	
	// TODO: code your application's behavior here.	
	//显示启动信息
	HeadMsg();
	if ( argc < 2 )
	{
		//显示帮助信息
		HelpMsg(*argv);
		return -1;
	}
	
	//解析输入参数
	char** pParam = argv;
	for (int i=0; i<argc; i++,pParam++)
	{
		if ( !_stricmp(*pParam, "-m"))
			g_iThreadMax = atoi(pParam[1]);
		if ( !_stricmp(*pParam, "-t"))
			g_iTimeOut = atoi(pParam[1]);
		if ( !_stricmp(*pParam, "-p"))
		{
			iPort = atoi(pParam[1]);
			g_bSetPort = true;
		}
		if ( !_stricmp(*pParam, "-r"))
			strncpy(g_szRootPath, pParam[1], sizeof(g_szRootPath)-1);
		if ( !_stricmp(*pParam, "-ssl") )
			g_bSSL = true;
	}
	if ( !g_bSetPort && g_bSSL)
		iPort = 443;
	
	//套接字初始化
	if ( !WSAInit() )
	{
		printf("WSASocket Init failed!\r\n");
		return -1;
	}
	
	//获取目标IP信息
	strncpy(szTarget, argv[1], sizeof(szTarget)-1);
	printf("Resolving Ip of %s...", &szTarget);
	hostent *pHost = NULL;
	pHost = gethostbyname(szTarget);
	if (!pHost)
	{
		printf(" Failed!\n\n");
		WSACleanup();
		return -1;
	}
	char *pTarget = inet_ntoa(**(struct in_addr **)pHost->h_addr_list);
	strncpy(szTargetIP, pTarget?pTarget:szTarget, sizeof(szTargetIP)-1);
	printf(" OK: %s\r\n", szTargetIP);
	
	//获取目录字典
	ObtainDirDict( g_tDirDict, "cgi.list");
	
	//设置扫描结果文件名
	_snprintf(g_szFileName, sizeof(g_szFileName), "%s.html", &szTarget);
	
	//如果指定了根目录并且根目录字符串的结尾为'/'字符则去掉末尾的'/'字符
	if ( strlen(g_szRootPath) != 0 && g_szRootPath[strlen(g_szRootPath)-1] == '/' )
		g_szRootPath[strlen(g_szRootPath)-1] = '\0';
	
	if ( !g_bSSL )
	{
		//设置服务器地址信息
		tAddrInfo.FillInAddr(szTarget, szTargetIP, iPort);
		//获取服务器信息
		if ( !GetTargetSrvInfo(tAddrInfo) )
		{
			WSACleanup();
			return -1;
		}
		
		//目录搜索
		ExploreWebDir(tAddrInfo, g_szRootPath);
	}
	else
	{
		//SSL
	}
	
	while ( g_iThreadNum )
		Sleep(1000);
	WSACleanup();
	FILE *fp = fopen(g_szFileName, "a");
	if (fp)
	{
		fprintf(fp, "</table></html>\n");
		fclose(fp);
	}
	printf("                                                                             \r\n");
	printf("\nAll Done, Found %d.\n", g_iExistNum);
	return 0;
}

