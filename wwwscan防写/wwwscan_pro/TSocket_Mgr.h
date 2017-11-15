#ifndef _T_SOCKET_MGR_H_
#define _T_SOCKET_MGR_H_

#include <Winsock2.h>

/*套接字*/
enum ACTION_TYPE
{
	RECV = 1,
	SEND
};

class TSocket_Addr
{
public:
	TSocket_Addr();
	void FillInAddr(char*, char*, int);//设置套接字
	virtual ~TSocket_Addr();

public:
  char szTarget[256];		//目标地址，可以是域名格式也可以是IP格式
  char szTargetIP[32];	//目标地址IP格式
  long lAddr;	//目标地址IP的long格式
  int iPort;	//目标地址端口号
  int iBaseCLen;	//基准包大小，用来和其他目录返回包进行比较
};

class TSocket_Opt
{
public:
	TSocket_Opt();
	virtual ~TSocket_Opt();
	bool socket();//创建非阻塞套接字
	bool connect(char*, int);//建立非阻塞链接
	bool select(int, int);//等待链接建立
	bool recv(char*,int);//接收数据
	bool send(char*,int);//发送数据

private:
  SOCKET m_iSockfd;	//用于发送或者接收数据的套接字
  struct sockaddr_in m_tSockaddr; //发送或者接收的目标地址信息
  timeval m_tTimeOut;	//最大等待时间
  unsigned long m_lArgp;	//用于ioctlsocket设置套接字非阻塞的参数
  fd_set m_rfds;	//接收等待队列
  fd_set m_wfds;	//写入等待队列
};

struct THREAD_PARAM//线程参数
{
  char szTarget[256];	//目标地址
  char szTargetIP[32];	//目标地址IP格式
  char szDir[1024];	//需要探测的目录名
  int iPort;	//端口号
  int iBaseCLen;	//基准包大小
  TSocket_Addr *pAddr;
};

bool WSAInit();

#endif