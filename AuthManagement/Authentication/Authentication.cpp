#include "Authentication.h"

Authentication::Authentication()
{
}
Authentication::~Authentication()
{
}

void Authentication::GetCertificateData(HCERTSTORE* certificateStore, PCCERT_CONTEXT* certificate, wchar_t* certificateIp)
{
	*certificateStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, NULL, CERT_SYSTEM_STORE_LOCAL_MACHINE, L"MY");
	if (*certificateStore == NULL)
	{
		throw std::runtime_error("Failed to open certificate store");
	}

	*certificate = CertFindCertificateInStore(*certificateStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_SUBJECT_STR, certificateIp, NULL); // Research this further
	if (*certificate == NULL)
	{
		CertCloseStore(certificateStore, CERT_CLOSE_STORE_FORCE_FLAG);
		throw std::runtime_error("Failed to find certificate in store");
	}
}

void Authentication::AuthenticateInbound(SOCKET* socket, wchar_t* certificateIp)
{
	HCERTSTORE certificateStore;
	PCCERT_CONTEXT certificate;

	GetCertificateData(&certificateStore, &certificate, certificateIp);

	// Setup the credentials information
	SCH_CREDENTIALS schCredentials = {};
	ZeroMemory(&schCredentials, sizeof(schCredentials));

	schCredentials.dwVersion = SCH_CREDENTIALS_VERSION;
	schCredentials.dwCredFormat = SCH_CRED_FORMAT_CERT_CONTEXT;
	schCredentials.cCreds = 1;
	schCredentials.paCred = &certificate;
	schCredentials.hRootStore = &certificateStore;
	schCredentials.dwSessionLifespan = 60000 * 5; // 5 minutes (certificateExpiration)
	schCredentials.dwFlags = 0;

	TCHAR schannel[1024];
	wcscpy_s(schannel, sizeof(schannel) / sizeof(TCHAR), L"Schannel");

	CredHandle credentials;
	ZeroMemory(&credentials, sizeof(credentials));

	TimeStamp certificateExpiration;
	ZeroMemory(&certificateExpiration, sizeof(certificateExpiration));

	// Acquire the credentials handle by passing in the credentials information, will be used for the handshake
	SECURITY_STATUS securityStatus = AcquireCredentialsHandle(NULL, (LPWSTR)&schannel, SECPKG_CRED_INBOUND, NULL, &schCredentials, NULL, NULL, &credentials, &certificateExpiration);
	if (securityStatus != SEC_E_OK)
	{
		std::cout << "Failed to acquire credentials handle. Code: " << securityStatus << std::endl;
		CertFreeCertificateContext(certificate);
		CertCloseStore(certificateStore, CERT_CLOSE_STORE_FORCE_FLAG);
		return mFailureCode[1];
	}

	// Perform the handshake with the client
	int handshakeStatus = AuthenticateClientHandshake(clientSocket, &credentials, &certificateExpiration);
	if (handshakeStatus != mSuccessCode)
	{
		std::cout << "Failed to perform handshake with client. Code: " << handshakeStatus << std::endl;
		CertFreeCertificateContext(certificate);
		CertCloseStore(certificateStore, CERT_CLOSE_STORE_FORCE_FLAG);
		return mFailureCode[2];
	}

	// Cleanup
	CertFreeCertificateContext(certificate);
	CertCloseStore(certificateStore, CERT_CLOSE_STORE_FORCE_FLAG);

	return mSuccessCode;
}