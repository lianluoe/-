#ifndef _T_SOCKET_MGR_H_
#define _T_SOCKET_MGR_H_

#include <Winsock2.h>

/*�׽���*/
enum ACTION_TYPE
{
	RECV = 1,
	SEND
};

class TSocket_Addr
{
public:
	TSocket_Addr();
	void FillInAddr(char*, char*, int);//�����׽���
	virtual ~TSocket_Addr();

public:
  char szTarget[256];		//Ŀ���ַ��������������ʽҲ������IP��ʽ
  char szTargetIP[32];	//Ŀ���ַIP��ʽ
  long lAddr;	//Ŀ���ַIP��long��ʽ
  int iPort;	//Ŀ���ַ�˿ں�
  int iBaseCLen;	//��׼����С������������Ŀ¼���ذ����бȽ�
};

class TSocket_Opt
{
public:
	TSocket_Opt();
	virtual ~TSocket_Opt();
	bool socket();//�����������׽���
	bool connect(char*, int);//��������������
	bool select(int, int);//�ȴ����ӽ���
	bool recv(char*,int);//��������
	bool send(char*,int);//��������

private:
  SOCKET m_iSockfd;	//���ڷ��ͻ��߽������ݵ��׽���
  struct sockaddr_in m_tSockaddr; //���ͻ��߽��յ�Ŀ���ַ��Ϣ
  timeval m_tTimeOut;	//���ȴ�ʱ��
  unsigned long m_lArgp;	//����ioctlsocket�����׽��ַ������Ĳ���
  fd_set m_rfds;	//���յȴ�����
  fd_set m_wfds;	//д��ȴ�����
};

struct THREAD_PARAM//�̲߳���
{
  char szTarget[256];	//Ŀ���ַ
  char szTargetIP[32];	//Ŀ���ַIP��ʽ
  char szDir[1024];	//��Ҫ̽���Ŀ¼��
  int iPort;	//�˿ں�
  int iBaseCLen;	//��׼����С
  TSocket_Addr *pAddr;
};

bool WSAInit();

#endif