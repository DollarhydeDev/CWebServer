#pragma once

#define SECURITY_WIN32
#define SCHANNEL_USE_BLACKLISTS

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <sspi.h>
#include <iostream>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Secur32.lib")

#include "../../MemoryManagement/CBuffer/CBuffer.h"

class ServerSocket
{
public:
	ServerSocket();
	~ServerSocket();

	void CreateSocket();
	void ListenForConnections();
	void AcceptClientConnection();

private:
	SOCKET serverSocket;
	SOCKET clientSocket;

	CtxtHandle securityContext;

	void GetServerIP(CBuffer* wcharBuffer);
	void ApplyDefaultSettings();
};

