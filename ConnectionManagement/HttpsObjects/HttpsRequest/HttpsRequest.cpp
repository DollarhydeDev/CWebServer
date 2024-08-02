#include "HttpsRequest.h"

HttpsRequest::HttpsRequest(CBuffer* httpsRequestBuffer)
{
	ParseRequest(httpsRequestBuffer);
}
HttpsRequest::~HttpsRequest()
{

}

void HttpsRequest::ParseRequest(CBuffer* httpsRequestBuffer)
{
	// Establish request type

	switch (httpsRequestBuffer->GetCharBuffer()[0])
	{
		case 'G':
			requestType = GET;
			break;

		case 'D':
			requestType = DELETE;
			break;

		case 'P':
			switch (httpsRequestBuffer->GetCharBuffer()[1])
			{
				case 'U':
					requestType = PUT;
					break;

				case 'O':
					requestType = POST;
					break;
			}
			break;

		default:
			requestType = UNKNOWN;
	}

	if (requestType == UNKNOWN)
	{
		throw std::exception("Uknown request type in ParseRequest()");
	}

	unsigned short requestOffset;
	unsigned short lineEndingCharOffset = 1;
	unsigned short spaceCharOffset = 1;

	// Establish offset of request type
	switch (requestType)
	{
		case GET:
			requestOffset = 3 + spaceCharOffset + lineEndingCharOffset;

		case PUT:
			requestOffset = 3 + spaceCharOffset + lineEndingCharOffset;

		case POST:
			requestOffset = 4 + spaceCharOffset + lineEndingCharOffset;

		case DELETE:
			requestOffset = 6 + spaceCharOffset + lineEndingCharOffset;
	}

	// Establish requested resource
}
