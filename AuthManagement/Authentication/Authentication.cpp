#include "Authentication.h"

Authentication::Authentication()
{
}
Authentication::~Authentication()
{
}

void Authentication::GetCertificateData(HCERTSTORE* certificateStoreBuffer, PCCERT_CONTEXT* certificateBuffer, wchar_t* certificateName)
{
	*certificateStoreBuffer = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, NULL, CERT_SYSTEM_STORE_LOCAL_MACHINE, L"MY");
	if (*certificateStoreBuffer == NULL)
	{
		throw std::runtime_error("Failed to open certificate store");
	}

	*certificateBuffer = CertFindCertificateInStore(*certificateStoreBuffer, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_SUBJECT_STR, certificateName, NULL); // Research this further
	if (*certificateBuffer == NULL)
	{
		CertCloseStore(certificateStoreBuffer, CERT_CLOSE_STORE_FORCE_FLAG);
		throw std::runtime_error("Failed to find certificate in store");
	}
}
void Authentication::AuthenticateInbound(SOCKET* inboundSocket, wchar_t* certificateName, CtxtHandle* securityContextBuffer)
{
	int successCode = 0;

	HCERTSTORE certificateStore;
	PCCERT_CONTEXT certificate;

	GetCertificateData(&certificateStore, &certificate, certificateName);

	// Setup the credentials information
	SCH_CREDENTIALS schCredentials = {};
	ZeroMemory(&schCredentials, sizeof(schCredentials));

	schCredentials.dwVersion = SCH_CREDENTIALS_VERSION;
	schCredentials.dwCredFormat = SCH_CRED_FORMAT_CERT_CONTEXT;
	schCredentials.cCreds = 1;
	schCredentials.paCred = &certificate;
	schCredentials.hRootStore = &certificateStore;
	schCredentials.dwSessionLifespan = 60000 * 5; // 5 minutes (Until cert expires)
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
		CertFreeCertificateContext(certificate);
		CertCloseStore(certificateStore, CERT_CLOSE_STORE_FORCE_FLAG);

		throw std::exception("Failed to acquire credentials handle.");
	}

	// Perform the handshake with the client
	DWORD dwSSPIFlags = ASC_REQ_REPLAY_DETECT | ASC_REQ_SEQUENCE_DETECT | ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_STREAM;
	DWORD dwSSPIOutFlags;

	// Setup output buffers
	SecBuffer outputBuffers[1];
	SecBufferDesc outputBufferData;

	outputBuffers[0].pvBuffer = NULL;
	outputBuffers[0].BufferType = SECBUFFER_TOKEN;
	outputBuffers[0].cbBuffer = 0;

	outputBufferData.cBuffers = 1;
	outputBufferData.pBuffers = outputBuffers;
	outputBufferData.ulVersion = SECBUFFER_VERSION;
	ZeroMemory(securityContextBuffer, sizeof(CtxtHandle));

	bool firstCall = true;

	bool handshakeComplete = false;
	while (!handshakeComplete)
	{
		char allocatedMemoryForRecv[4096];
		int bytesReceived = recv(*inboundSocket, allocatedMemoryForRecv, sizeof(allocatedMemoryForRecv), 0);
		if (bytesReceived == SOCKET_ERROR || bytesReceived == 0)
		{
			throw std::exception("Failed to receive data from client.");
		}

		// Setup input buffers
		SecBuffer inputBuffers[2];
		SecBufferDesc inputBufferData;

		inputBuffers[0].pvBuffer = allocatedMemoryForRecv;
		inputBuffers[0].cbBuffer = bytesReceived;
		inputBuffers[0].BufferType = SECBUFFER_TOKEN;

		inputBuffers[1].pvBuffer = NULL;
		inputBuffers[1].cbBuffer = 0;
		inputBuffers[1].BufferType = SECBUFFER_EMPTY;

		inputBufferData.cBuffers = 2;
		inputBufferData.pBuffers = inputBuffers;
		inputBufferData.ulVersion = SECBUFFER_VERSION;

		SECURITY_STATUS securityStatus;

		if (firstCall)
		{
			securityStatus = AcceptSecurityContext(&credentials, NULL, &inputBufferData, dwSSPIFlags, SECURITY_NATIVE_DREP, securityContextBuffer, &outputBufferData, &dwSSPIOutFlags, &certificateExpiration);
			firstCall = false;
		}
		else
		{
			securityStatus = AcceptSecurityContext(&credentials, securityContextBuffer, &inputBufferData, dwSSPIFlags, SECURITY_NATIVE_DREP, securityContextBuffer, &outputBufferData, &dwSSPIOutFlags, &certificateExpiration);
		}

		if (securityStatus == SEC_E_INCOMPLETE_MESSAGE)
		{
			continue;
		}
		else if (securityStatus == SEC_I_COMPLETE_NEEDED || securityStatus == SEC_I_COMPLETE_AND_CONTINUE)
		{
			securityStatus = CompleteAuthToken(securityContextBuffer, &outputBufferData);
			if (securityStatus != SEC_E_OK)
			{
				throw std::exception("Failed to complete authentication token.");
			}
		}

		if (securityStatus == SEC_E_OK || securityStatus == SEC_I_CONTINUE_NEEDED)
		{
			if (outputBuffers[0].cbBuffer != 0 && outputBuffers[0].pvBuffer != NULL)
			{
				int bytesSent = send(*inboundSocket, (char*)outputBuffers[0].pvBuffer, outputBuffers[0].cbBuffer, 0);
				if (bytesSent == SOCKET_ERROR)
				{
					throw std::exception("Failed to send data to client.");
				}

				FreeContextBuffer(outputBuffers[0].pvBuffer);
			}
			else
			{
				std::cout << "No data to send to client. Is this supposed to happen? Prolly not" << std::endl;
			}
		}
		else
		{
			throw std::exception("Failed to accept security context.");
		}

		if (securityStatus == SEC_E_OK)
		{
			handshakeComplete = true;
		}
	}

	// Cleanup
	CertFreeCertificateContext(certificate);
	CertCloseStore(certificateStore, CERT_CLOSE_STORE_FORCE_FLAG);
}

void Authentication::DecryptData(CBuffer* encryptedData, CBuffer* decryptedData, CtxtHandle* securityContext)
{
	SecBufferDesc inputBufferData;
	SecBuffer inputBuffers[4];

	inputBuffers[0].BufferType = SECBUFFER_DATA;
	inputBuffers[0].pvBuffer = encryptedData->GetCharBuffer(); // Data to decrypt
	inputBuffers[0].cbBuffer = encryptedData->GetCharBufferSize(); // Size of data to decrypt

	inputBuffers[1].BufferType = SECBUFFER_EMPTY;
	inputBuffers[2].BufferType = SECBUFFER_EMPTY;
	inputBuffers[3].BufferType = SECBUFFER_EMPTY;

	inputBufferData.ulVersion = SECBUFFER_VERSION;
	inputBufferData.cBuffers = 4;
	inputBufferData.pBuffers = inputBuffers;

	SECURITY_STATUS encryptionStatus = DecryptMessage(securityContext, &inputBufferData, 0, NULL);
	if (encryptionStatus != SEC_E_OK)
	{
		throw std::exception("Error decrypting message.");
	}

	for (int i = 1; i < 4; i++) // Loop through buffers and check for data
	{
		if (inputBuffers[i].BufferType == SECBUFFER_DATA)
		{
			// Setup the decrypted buffer
			decryptedData->AllocateCharBuffer(inputBuffers[i].cbBuffer + 1);

			memcpy(decryptedData->GetCharBuffer(), inputBuffers[i].pvBuffer, inputBuffers[i].cbBuffer); // Copy the decrypted data to the data buffer
			decryptedData->GetCharBuffer()[inputBuffers[i].cbBuffer] = 0x00; // Null terminate the data buffer

			break; // Should we break here? Or do we try to fit all the data into the data buffer?
		}
	}
}
void Authentication::EncryptData(CBuffer* decryptedData, CBuffer* encryptedData, CtxtHandle* securityContext)
{
	// Get the sizes for the encryption
	SecPkgContext_StreamSizes sizes;
	SECURITY_STATUS status = QueryContextAttributes(securityContext, SECPKG_ATTR_STREAM_SIZES, &sizes);
	if (status != SEC_E_OK)
	{
		throw std::exception("Failed to query context attributes");
	}

	int totalSize = sizes.cbHeader + sizes.cbTrailer + decryptedData->GetCharBufferSize();

	encryptedData->AllocateCharBuffer(totalSize);

	// Prepare input buffers
	SecBuffer inputBuffers[4];
	SecBufferDesc inputBufferData;

	// This part of the buffer will hold the header
	inputBuffers[0].BufferType = SECBUFFER_STREAM_HEADER;
	inputBuffers[0].cbBuffer = sizes.cbHeader;
	inputBuffers[0].pvBuffer = encryptedData->GetCharBuffer();

	// This part of the buffer will hold the data, excluding the header
	inputBuffers[1].BufferType = SECBUFFER_DATA;
	inputBuffers[1].cbBuffer = decryptedData->GetCharBufferSize();
	inputBuffers[1].pvBuffer = encryptedData->GetCharBuffer() + sizes.cbHeader;

	// Copy the responseBuffer data to the allocated space (offset by the header size, so there is room for the header to be copied into the buffer)
	memcpy(encryptedData->GetCharBuffer() + sizes.cbHeader, decryptedData->GetCharBuffer(), decryptedData->GetCharBufferSize());

	// This part of the buffer will hold the trailer
	inputBuffers[2].BufferType = SECBUFFER_STREAM_TRAILER;
	inputBuffers[2].cbBuffer = sizes.cbTrailer;
	inputBuffers[2].pvBuffer = encryptedData->GetCharBuffer() + sizes.cbHeader + decryptedData->GetCharBufferSize();

	// This part of the buffer will hold the padding (empty buffer)
	inputBuffers[3].BufferType = SECBUFFER_EMPTY;

	inputBufferData.ulVersion = SECBUFFER_VERSION;
	inputBufferData.cBuffers = 4;
	inputBufferData.pBuffers = inputBuffers;

	// Encrypt the data
	SECURITY_STATUS encryptionStatus = EncryptMessage(securityContext, 0, &inputBufferData, 0);
	if (encryptionStatus != SEC_E_OK)
	{
		throw std::exception("Failed to encrypt message");
	}
}