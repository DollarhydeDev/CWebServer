#pragma once

#define SECURITY_WIN32
#define SCHANNEL_USE_BLACKLISTS

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <Winternl.h>
#include <sspi.h>
#include <schannel.h>
#include <iostream>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Secur32.lib")
#pragma comment(lib, "Crypt32.lib")

#include "../../MemoryManagement/CBuffer/CBuffer.h"

class Authentication
{
public:
	Authentication();
	~Authentication();

	void AuthenticateInbound(SOCKET* inboundSocket, wchar_t* certificateName, CtxtHandle* securityContextBuffer);
	void DecryptData(CBuffer* encryptedData, CBuffer* decryptedData, CtxtHandle* securityContext);
	void EncryptData(CBuffer* decryptedData, CBuffer* encryptedData, CtxtHandle* securityContext);

private:
	void GetCertificateData(HCERTSTORE* certificateStoreBuffer, PCCERT_CONTEXT* certificateBuffer, wchar_t* certificateName);
};

