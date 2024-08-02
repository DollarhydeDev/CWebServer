#pragma once

#include <iostream>

#include "../../../MemoryManagement/CBuffer/CBuffer.h"

class HttpsRequest
{
public:
	HttpsRequest(CBuffer* httpsRequestBuffer);
	~HttpsRequest();

	enum RequestTypes
	{
		GET,
		PUT,
		POST,
		DELETE,
		UNKNOWN
	};

private:
	RequestTypes requestType;

	void ParseRequest(CBuffer* httpsRequestBuffer);
};

