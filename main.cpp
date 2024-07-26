#include "MemoryManagement/CBuffer/CBuffer.h"
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

	try
	{
		ServerSocket serverSocket;
		serverSocket.CreateSocket();
	}
	catch (const std::exception& e)
	{
		std::cout << e.what() << std::endl;
	}

	WSACleanup();

	return 0;
}