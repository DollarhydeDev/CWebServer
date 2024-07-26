#pragma once

#define SECURITY_WIN32
#define SCHANNEL_USE_BLACKLISTS

#include <windows.h>
#include <Winternl.h>
#include <sspi.h>
#include <schannel.h>
#include <winsock.h>
#include <iostream>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Secur32.lib")
#pragma comment(lib, "Crypt32.lib")

class Authentication
{
public:
	Authentication();
	~Authentication();

	void AuthenticateInbound(SOCKET* socket, wchar_t* certificateIp);

private:
	void GetCertificateData(HCERTSTORE* certificateStore, PCCERT_CONTEXT* certificate, wchar_t* certificateIp);
};

