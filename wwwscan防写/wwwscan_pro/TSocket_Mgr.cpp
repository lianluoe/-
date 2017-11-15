#include "TSocket_Mgr.h"
#include <stdio.h>

bool WSAInit()
{
	WORD wVersionRequested;
	WSADATA wsaData;
	int err;
	
	wVersionRequested = MAKEWORD( 2, 2 );
	
	err = WSAStartup( wVersionRequested, &wsaData );
	if ( err != 0 ) {
		printf("WSAStartup failed! Error:%d\n", GetLastError());
		return false;
	}
	
	if ( LOBYTE( wsaData.wVersion ) != 2 ||
		HIBYTE( wsaData.wVersion ) != 2 ) {
		WSACleanup( );
		return false; 
	}

	return true;
}

TSocket_Addr::TSocket_Addr()
{
	memset(this, 0 , sizeof(TSocket_Addr));
}

TSocket_Addr::~TSocket_Addr()
{
	memset(this, 0 , sizeof(TSocket_Addr));
}

void TSocket_Addr::FillInAddr(char* szTarget, char* szTargetIP, int iPort)
{
	strncpy(this->szTarget, szTarget, sizeof(this->szTarget)-1);
	strncpy(this->szTargetIP, szTargetIP, sizeof(this->szTargetIP)-1);
	this->lAddr = ntohl(inet_addr(this->szTargetIP));
	this->iPort = iPort;
	this->iBaseCLen = 0;
}

TSocket_Opt::TSocket_Opt()
{
	memset(this, 0, sizeof(TSocket_Opt));
	m_iSockfd = INVALID_SOCKET;
	m_lArgp = 1;
}

TSocket_Opt::~TSocket_Opt()
{
	if (m_iSockfd != INVALID_SOCKET)
		closesocket(m_iSockfd);
}

bool TSocket_Opt::socket()
{
	try
	{
		m_iSockfd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if ( m_iSockfd == INVALID_SOCKET )
			throw "socket failed!";
		if ( ioctlsocket(m_iSockfd, FIONBIO, &m_lArgp) )
			throw "ioctlsocket failed!";
	}
	catch(char *e)
	{
		printf("error:%s\r\n",e);
		return false;
	}
	return true;
}

bool TSocket_Opt::connect(char *szAddr, int iPort)
{
	m_tSockaddr.sin_family = AF_INET;
	m_tSockaddr.sin_port = htons(iPort);
	m_tSockaddr.sin_addr.s_addr = inet_addr(szAddr);
	::connect(m_iSockfd, (const struct sockaddr *)&m_tSockaddr, sizeof(struct sockaddr_in));
	return true;
}

bool TSocket_Opt::select(int SockActionType, int iTimeOut)
{
	m_tTimeOut.tv_sec = iTimeOut;
	m_tTimeOut.tv_usec = 0;
	m_lArgp = 0;
	//略微改动防止出现
	try
	{
		switch (SockActionType)
		{
		case RECV:
			{
				FD_ZERO(&m_rfds);
				FD_SET(m_iSockfd, &m_rfds);
				while (true)
				{
					if ( ::select(0, &m_rfds, NULL, NULL, &m_tTimeOut) == SOCKET_ERROR )
					{
						int err = WSAGetLastError();
						if ( err != WSAEINPROGRESS)
							throw "select socket read failed!";
					}
					else
					{
						if ( FD_ISSET(m_iSockfd, &m_rfds) )
							break;
					}
				}
				break;
			}
		case SEND:
			{
				FD_ZERO(&m_wfds);
				FD_SET(m_iSockfd, &m_wfds);
				while (true)
				{
					if ( ::select(0, NULL, &m_wfds, NULL, &m_tTimeOut) == SOCKET_ERROR )
					{
						int err = WSAGetLastError();
						if ( err != WSAEINPROGRESS)
							throw "select socket write failed!";
					}
					else
					{
						if ( FD_ISSET(m_iSockfd, &m_wfds) )
							break;
					}
				}
				break;
			}
		default:
			throw "SocketActionType unknown!";
		}
	}
	catch(char *e)
	{
		printf("error:%s\r\n", e);
		return false;
	}

  return true;
}

bool TSocket_Opt::send(char* szBuf,int iLen)
{
	try
	{
		if ( ::send(this->m_iSockfd, szBuf, iLen+1, 0) == SOCKET_ERROR )
			throw "send socket failed!";
	}
	catch(char *e)
	{
		printf("error:%s\r\n",e);
		return false;
	}
	return true;
}

bool TSocket_Opt::recv(char* szBuf,int iLen)
{
	try
	{
		if ( ::recv(this->m_iSockfd, szBuf, iLen-1, 0) == SOCKET_ERROR )
			throw "recv socket failed!";
	}
	catch(char *e)
	{
		printf("error:%s\r\n",e);
		return false;
	}
	return true;
}
