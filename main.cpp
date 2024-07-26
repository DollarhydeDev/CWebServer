#include "MemoryManagement/CBuffer/CBuffer.h"
#include "AuthManagement/Authentication/Authentication.h"
#include "ConnectionManagement/ServerSocket/ServerSocket.h"

#include <iostream>

int main()
{
	WSADATA wsaData;
	int startResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (startResult != 0)
	{
		std::cout << "WSAStartup failed with error: " << startResult << std::endl;
		return 1;
	}

	ServerSocket serverSocket;

	// Creates a new socket and binds it to local ip and default port.
	try
	{
		serverSocket.CreateSocket();
	}
	catch (const std::exception& e)
	{
		std::cout << "Issue at create socket: " << e.what() << std::endl;

		WSACleanup();
		return 1;
	}

	// Sets the socket to listen for incoming connections
	try
	{
		serverSocket.ListenForConnections();
	}
	catch (const std::exception& e)
	{
		std::cout << "Issue at socket listen: " << e.what() << std::endl;

		WSACleanup();
		return 1;
	}

	// Accepts incoming connection (will halt the thread and wait if no connection has been receivied)
	try
	{
		serverSocket.AcceptClientConnection();
	}
	catch (const std::exception& e)
	{
		std::cout << "Issue at accept client: " << e.what() << std::endl;

		WSACleanup();
		return 1;
	}

	Authentication authentication;
	wchar_t certificateName[] = L"192.168.5.110";

	// Authenticates client using a certificate stored
	try
	{
		authentication.AuthenticateInbound(serverSocket.GetClientSocket(), certificateName, serverSocket.GetSecurityContext());
	}
	catch (const std::exception& e)
	{
		std::cout << "Issue at authenticate client: " << e.what() << std::endl;

		WSACleanup();
		return 1;
	}

	// Buffer for reading client req
	CBuffer requestBuffer;

	// Try reading the incoming client request
	try
	{
		serverSocket.ReadClientRequest(serverSocket.GetClientSocket(), &requestBuffer);
	}
	catch (const std::exception& e)
	{
		std::cout << "Issue reading client request: " << e.what() << std::endl;

		WSACleanup();
		return 1;
	}

	// Buffer for holding decrypted data
	CBuffer decryptedRequestBuffer;

	// Decrypt message received using the authenticated client and cert + requestbuffer
	try
	{
		authentication.DecryptData(&requestBuffer, &decryptedRequestBuffer, serverSocket.GetSecurityContext());
	}
	catch (const std::exception& e)
	{
		std::cout << "Issue at decrypt client data: " << e.what() << std::endl;

		WSACleanup();
		return 1;
	}

	std::cout << "Incoming req: " << decryptedRequestBuffer.GetCharBuffer() << std::endl;

	char response[] = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\nContent-Length: 18\r\n\r\nHello from server!";
	CBuffer responseBuffer;
	responseBuffer.AllocateCharBuffer(strlen(response) + 1);

	memcpy(responseBuffer.GetCharBuffer(), response, strlen(response));
	responseBuffer.GetCharBuffer()[strlen(response)] = 0x00;

	std::cout << "Response: " << response << std::endl;

	// Buffer for holding encrypted data
	CBuffer encryptedResponseBuffer;

	// Encrypt message received using the cert + encryptedResponseBuffer
	try
	{
		authentication.EncryptData(&responseBuffer, &encryptedResponseBuffer, serverSocket.GetSecurityContext());
	}
	catch (const std::exception& e)
	{
		std::cout << "Issue at encrypt client data: " << e.what() << std::endl;

		WSACleanup();
		return 1;
	}

	// Respond to client with encrypted buffer
	try
	{
		serverSocket.RespondToClient(serverSocket.GetClientSocket(), &encryptedResponseBuffer);
	}
	catch (const std::exception& e)
	{
		std::cout << "Issue at encrypt client data: " << e.what() << std::endl;

		WSACleanup();
		return 1;
	}

	std::cout << "Done." << std::endl;

	WSACleanup();
	return 0;
}