#include "ServerSocket.h"

ServerSocket::ServerSocket() : serverSocket(INVALID_SOCKET), clientSocket(INVALID_SOCKET), securityContext({0})
{
}
ServerSocket::~ServerSocket()
{
	if (serverSocket != INVALID_SOCKET)
	{
		closesocket(serverSocket);
	}

	if (clientSocket != INVALID_SOCKET)
	{
		closesocket(clientSocket);
	}

	DeleteSecurityContext(&securityContext);
}

void ServerSocket::CreateSocket()
{
	serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (serverSocket == INVALID_SOCKET)
	{
		throw std::exception("Error at socket()");
	}

	ApplyDefaultSettings();
}
void ServerSocket::ApplyDefaultSettings()
{
	// Set up the server settings
	sockaddr_in socketSettings({0});
	int addressFamily = AF_INET;
	int portNumber = 54000;

	// Allocate memory for the IP address (GetServerIP will handle the wchar allocation, not sure if I want to keep it this way)
	CBuffer ipAddressBuffer;
	GetServerIP(&ipAddressBuffer);

	socketSettings.sin_family = addressFamily;
	socketSettings.sin_port = htons(portNumber); // htons converts the port number to network byte order

	// InetPtonW converts the IP address into network byte order from a string
	int conversionStatus = InetPtonW(AF_INET, ipAddressBuffer.GetWCharBuffer(), &socketSettings.sin_addr);
	if (conversionStatus <= 0)
	{
		throw std::exception("Error at InetPtonW()");
	}

	// Bind the server socket using the server settings
	int bindStatus = bind(serverSocket, (sockaddr*)&socketSettings, sizeof(sockaddr_in));
	if (bindStatus == SOCKET_ERROR)
	{
		throw std::exception("Error at bind()");
	}
}

void ServerSocket::ListenForConnections()
{
	unsigned short defaultMaxConnections = 1;

	// Listen for incoming connections
	int listenStatus = listen(serverSocket, defaultMaxConnections);
	if (listenStatus == SOCKET_ERROR)
	{
		throw std::exception("Error at listen()");
	}
}
void ServerSocket::AcceptClientConnection()
{
	// Accept the incoming connection
	clientSocket = accept(serverSocket, NULL, NULL);
	if (clientSocket == INVALID_SOCKET)
	{
		throw std::exception("Error at accept()");
	}
}

void ServerSocket::ReadClientRequest(SOCKET* clientSocket, CBuffer* requestBuffer)
{
	const int recvBufferSize = 4096;
	char recvBuffer[recvBufferSize];
	int bytesRecieved = recv(*clientSocket, recvBuffer, recvBufferSize, 0);
	if (bytesRecieved == 0)
	{
		throw std::exception("Receieved 0 bytes from client");
	}

	if (bytesRecieved > recvBufferSize)
	{
		throw std::exception("Incoming bytes is larger than const buffer in read client. Potentially need to rethink this method.");
	}

	requestBuffer->AllocateCharBuffer(bytesRecieved + 1);
	memcpy(requestBuffer->GetCharBuffer(), recvBuffer, bytesRecieved);
	requestBuffer->GetCharBuffer()[bytesRecieved] = 0x00;
}
void ServerSocket::RespondToClient(SOCKET* clientSocket, CBuffer* responseBuffer)
{
	// Send data to the client
	int bytesSent = send(*clientSocket, responseBuffer->GetCharBuffer(), responseBuffer->GetCharBufferSize(), 0);
	if (bytesSent == 0)
	{
		throw std::exception("Sent 0 bytes to client");
	}

	Sleep(1000);
}

void ServerSocket::GetServerIP(CBuffer* wcharBuffer)
{
	int successCode = 0;

	// Allocate memory so we can copy the host name into it. Dividing the buffer by 2 since char is 1 byte and wchar_t is 2 bytes
	int hostNameBufferSize = 256;
	CBuffer hostNameBuffer;
	hostNameBuffer.AllocateCharBuffer(hostNameBufferSize);

	// Get the host name and copy it into the allocated memory
	int getHostStatus = gethostname(hostNameBuffer.GetCharBuffer(), hostNameBuffer.GetCharBufferSize());
	if (getHostStatus != successCode)
	{
		throw std::exception("Error at gethostname()");
	}

	hostNameBuffer.GetCharBuffer()[hostNameBuffer.GetCharBufferSize() - 1] = 0x00; // Null terminate the string

	// Get length of the host name in wide characters
	int wideHostNameLength = MultiByteToWideChar(CP_ACP, 0, hostNameBuffer.GetCharBuffer(), -1, nullptr, 0);
	if (wideHostNameLength == 0)
	{
		throw std::exception("Error at MultiByteToWideChar()");
	}

	// Allocate memory for new wide character host name using length of wide character host name
	CBuffer wideCharHostName;
	wideCharHostName.AllocateWCharBuffer(wideHostNameLength);

	// Convert the host name to wide characters and copy it into the allocated memory
	int conversionStatus = MultiByteToWideChar(CP_ACP, 0, hostNameBuffer.GetCharBuffer(), -1, wideCharHostName.GetWCharBuffer(), wideCharHostName.GetWCharBufferSize());
	if (conversionStatus == 0)
	{
		throw std::exception("Error at MultiByteToWideChar()");
	}

	// Set up the search information for the host, specifying the hosts family, socket type, and protocol we want returned
	ADDRINFOW hostSearchInformation({ 0 });
	hostSearchInformation.ai_family = AF_INET;
	hostSearchInformation.ai_socktype = SOCK_STREAM;
	hostSearchInformation.ai_protocol = IPPROTO_TCP;

	// Create a pointer to hold the result of the search
	ADDRINFOW* hostResultInformation = nullptr;

	// Get the address information for the host and copy it into the result pointer
	int getAddressStatus = GetAddrInfoW(wideCharHostName.GetWCharBuffer(), NULL, &hostSearchInformation, &hostResultInformation);
	if (getAddressStatus != successCode)
	{
		throw std::exception("Error at GetAddrInfoW()");
	}

	// Retrieve memory address for the the address information
	sockaddr_in* hostAddressInfo = (sockaddr_in*)hostResultInformation->ai_addr;

	// Get the IP address from the address information pointer
	IN_ADDR hostIpAddress = hostAddressInfo->sin_addr;

	wcharBuffer->AllocateWCharBuffer(INET_ADDRSTRLEN);

	// Convert the IP address from a network byte order into a string and copy it into the allocated memory
	InetNtopW(hostSearchInformation.ai_family, (void*)&hostIpAddress, wcharBuffer->GetWCharBuffer(), INET_ADDRSTRLEN);
	if (wcharBuffer->GetWCharBuffer() == nullptr)
	{
		FreeAddrInfoW(hostResultInformation);
		throw std::exception("Error at InetNtopW()");
	}

	FreeAddrInfoW(hostResultInformation);
}
SOCKET* ServerSocket::GetServerSocket()
{
	return &serverSocket;
}
SOCKET* ServerSocket::GetClientSocket()
{
	return &clientSocket;
}
CtxtHandle* ServerSocket::GetSecurityContext()
{
	return &securityContext;
}