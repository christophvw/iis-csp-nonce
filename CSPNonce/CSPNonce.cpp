#define _WINSOCKAPI_
#include <windows.h>
#include <sal.h>
#include <httpserv.h>
#include <string>
#include <wincrypt.h>
#include <bcrypt.h>
using namespace std;

class CCSPNonce : public CHttpModule
{
private:
    REQUEST_NOTIFICATION_STATUS
        HandleOnBeginRquest(
            IN IHttpContext* pHttpContext
        )
    {
        IHttpRequest* pHttpRequest = pHttpContext->GetRequest();
        if (pHttpRequest == NULL)
        {
            return RQ_NOTIFICATION_CONTINUE;
        }

        const WCHAR* pszURI = pHttpContext->GetScriptName();
        if ((pszURI != NULL) && (wcsstr(pszURI, L"html") != NULL))
        {
            /* Disable compression */
            pHttpRequest->DeleteHeader(HttpHeaderAcceptEncoding);
        }


        return RQ_NOTIFICATION_CONTINUE;
    }

public:

    REQUEST_NOTIFICATION_STATUS
        OnBeginRequest(
            IN IHttpContext* pHttpContext,
            IN IHttpEventProvider* pProvider
        )
    {
        UNREFERENCED_PARAMETER(pProvider);
        return HandleOnBeginRquest(pHttpContext);
    }

    REQUEST_NOTIFICATION_STATUS
        OnPostBeginRequest(
            IN IHttpContext* pHttpContext,
            IN IHttpEventProvider* pProvider
        )
    {
        UNREFERENCED_PARAMETER(pProvider);
        return HandleOnBeginRquest(pHttpContext);
    }

    REQUEST_NOTIFICATION_STATUS
        OnSendResponse(
            IN IHttpContext* pHttpContext,
            IN ISendResponseProvider* pProvider
        )
    {
        UNREFERENCED_PARAMETER(pProvider);

        HRESULT hr;
        PCSTR pszServerHeader;
        USHORT cchServerHeader;
        std::string sRandomNonceString("randomNonceGoesHere");
        size_t index = 0;
        std::string sRandomNonce;

        IHttpResponse* pHttpResponse = pHttpContext->GetResponse();

        if (pHttpResponse != NULL)
        {
            pHttpResponse->GetHeader("content-security-policy", &cchServerHeader);
            if (cchServerHeader > 0)
            {
                pszServerHeader = (PCSTR)pHttpContext->AllocateRequestMemory(cchServerHeader + 1);

                if (pszServerHeader == NULL)
                {
                    hr = HRESULT_FROM_WIN32(ERROR_NOT_ENOUGH_MEMORY);
                    pProvider->SetErrorStatus(hr);
                    return RQ_NOTIFICATION_FINISH_REQUEST;
                }

                pszServerHeader = pHttpResponse->GetHeader(
                    "content-security-policy", &cchServerHeader);

                std::string sServerHeader(pszServerHeader);
                BYTE buf[64];

                if (BCryptGenRandom(NULL, buf, (ULONG)sizeof(buf), BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0) {
                    DWORD dwSize = 0;
                    if (CryptBinaryToStringA(buf, sizeof(buf) / sizeof(buf[0]), CRYPT_STRING_BASE64URI | CRYPT_STRING_NOCRLF, nullptr, &dwSize))
                    {
                        LPSTR pszDestination = static_cast<LPSTR> (HeapAlloc(GetProcessHeap(), HEAP_NO_SERIALIZE, dwSize));
                        if (pszDestination)
                        {
                            if (!CryptBinaryToStringA(buf, sizeof(buf) / sizeof(buf[0]), CRYPT_STRING_BASE64URI | CRYPT_STRING_NOCRLF, pszDestination, &dwSize))
                            {
                                return RQ_NOTIFICATION_CONTINUE;
                            }
                            sRandomNonce.assign(pszDestination, 32);
                            HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, pszDestination);
                        }
                    }

                    //Replace nonce-randomNonce with random nonce
                    while ((index = sServerHeader.find(sRandomNonceString, index)) != string::npos) {
                        sServerHeader.replace(index, sRandomNonceString.length(), sRandomNonce);
                        index += sRandomNonce.length();
                    }

                    pHttpResponse->SetHeader(
                        "Content-Security-Policy", sServerHeader.c_str(),
                        (USHORT)sServerHeader.length(), TRUE);
                }

            }

            const HTTP_RESPONSE* pRawResponse = pHttpResponse->GetRawHttpResponse();
            if (pRawResponse == NULL)
            {
                return RQ_NOTIFICATION_CONTINUE;
            }

            if (pRawResponse->StatusCode != 200)
            {
                return RQ_NOTIFICATION_CONTINUE;
            }

            if (pRawResponse->EntityChunkCount == 0)
            {
                // buffer empty
                return RQ_NOTIFICATION_CONTINUE;
            }
            else if (pRawResponse->EntityChunkCount > 1)
            {
                //multi entity buffer not supported
                OutputDebugStringA("multi entity buffer not supported");
                return RQ_NOTIFICATION_CONTINUE;
            }

            PHTTP_DATA_CHUNK pEntityChunk = pRawResponse->pEntityChunks;
            if (pEntityChunk == NULL)
            {
                return RQ_NOTIFICATION_CONTINUE;
            }

            if (pRawResponse->pEntityChunks->DataChunkType != HttpDataChunkFromMemory &&
                pRawResponse->pEntityChunks->DataChunkType != HttpDataChunkFromFileHandle)
            {
                /* not supported */
                OutputDebugStringA("Chunk not from memory or file");
                return RQ_NOTIFICATION_CONTINUE;
            }

            if (pEntityChunk->DataChunkType == HttpDataChunkFromFileHandle &&
                (pEntityChunk->FromFileHandle.ByteRange.StartingOffset.QuadPart > 0 ||
                    pEntityChunk->FromFileHandle.ByteRange.Length.QuadPart > (250 * 1024 * 1024)))
            {
                /* not supported */
                OutputDebugStringA("HttpDataChunkFromFileHandle too big");
                return RQ_NOTIFICATION_CONTINUE;
            }

            USHORT nContentTypeLength = 0;
            PCSTR pszContentType = pHttpResponse->GetHeader(HttpHeaderContentType, &nContentTypeLength);
            if (pszContentType == NULL || nContentTypeLength == 0)
            {
                return RQ_NOTIFICATION_CONTINUE;
            }
            if (_stricmp(pszContentType, "text/html") != 0)
            {
                return RQ_NOTIFICATION_CONTINUE;
            }

            if (pEntityChunk->DataChunkType == HttpDataChunkFromMemory)
            {
                std::string sBuffer((PCSTR)pEntityChunk->FromMemory.pBuffer, pEntityChunk->FromMemory.BufferLength);

                //Replace randomNonce with a random nonce
                index = 0;
                while ((index = sBuffer.find(sRandomNonceString, index)) != string::npos) {
                    sBuffer.replace(index, sRandomNonceString.length(), sRandomNonce);
                    index += sRandomNonce.length();
                }

                //OutputDebugStringA(sBuffer.c_str());

                BYTE* pbyData = (BYTE*)pHttpContext->AllocateRequestMemory((DWORD)sBuffer.length());
                if (pbyData != NULL)
                {
                    // copy the response data
                    memcpy(pbyData, sBuffer.c_str(), sBuffer.length());

                    // change the buffer pointer
                    pEntityChunk->FromMemory.pBuffer = pbyData;
                    pEntityChunk->FromMemory.BufferLength = (ULONG) sBuffer.length();

                    char sContentLength[255];
                    sprintf_s(sContentLength, "%I64u", sBuffer.length());
                    pHttpResponse->SetHeader(HttpHeaderContentLength, sContentLength,
                        (USHORT)strlen(sContentLength), TRUE);
                }

            }
        }

        return RQ_NOTIFICATION_CONTINUE;
    }
};

class CCSPNonceFactory : public IHttpModuleFactory
{
public:
    HRESULT
        GetHttpModule(
            OUT CHttpModule** ppModule,
            IN IModuleAllocator* pAllocator
        )
    {
        UNREFERENCED_PARAMETER(pAllocator);

        CCSPNonce* pModule = new CCSPNonce;
        if (!pModule)
        {
            return HRESULT_FROM_WIN32(ERROR_NOT_ENOUGH_MEMORY);
        }
        else
        {
            *ppModule = pModule;
            pModule = NULL;
            return S_OK;
        }
    }

    void
        Terminate()
    {
        delete this;
    }
};

HRESULT
__stdcall
RegisterModule(
    DWORD dwServerVersion,
    IHttpModuleRegistrationInfo* pModuleInfo,
    IHttpServer* pGlobalInfo
)
{
    UNREFERENCED_PARAMETER(dwServerVersion);
    UNREFERENCED_PARAMETER(pGlobalInfo);

    HRESULT hr;
    hr = pModuleInfo->SetRequestNotifications(
        new CCSPNonceFactory,
        RQ_BEGIN_REQUEST | RQ_SEND_RESPONSE,
        RQ_BEGIN_REQUEST
    );
    if (FAILED(hr))
    {
        return hr;
    }

    hr = pModuleInfo->SetPriorityForRequestNotification(
        RQ_SEND_RESPONSE,
        PRIORITY_ALIAS_HIGH
    );
    if (FAILED(hr))
    {
        return hr;
    }
    return hr;
}