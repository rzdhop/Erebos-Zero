#include <windows.h>
#include <http.h>
#pragma comment(lib, "httpapi.lib")

#define COMPLETION_KEY_HTTP 1
#define HTTP_RECEIVE_BUFFER_SIZE 4096

// State machine for the asynchronous operation
typedef enum _IO_STATE {
    IoStateReceiveRequest,
    IoStateSendResponse
} IO_STATE;

// Custom context wrapping OVERLAPPED
typedef struct _HTTP_IO_CONTEXT {
    OVERLAPPED Overlapped;       // MUST be the first member
    HANDLE hReqQueue;            // Handle to the HTTP Request Queue
    IO_STATE State;              // Current state of this operation
    HTTP_REQUEST_ID RequestId;   // Unique ID assigned by http.sys
    PCHAR RequestBuffer;         // Raw memory buffer for the HTTP packet
    ULONG BufferLength;          // Size of the buffer
    PHTTP_REQUEST pRequest;      // Pointer to the parsed request (mapped inside RequestBuffer)
} HTTP_IO_CONTEXT, *PHTTP_IO_CONTEXT;

DWORD WINAPI WorkerRoutine(LPVOID lpParam) {
    HANDLE hIocp = (HANDLE)lpParam;
    DWORD bytesTransferred = 0;
    ULONG_PTR completionKey = 0;
    LPOVERLAPPED pOverlapped = NULL;

    while (TRUE) {
        // CPU transitions to ring 0 and waits for a thread scheduler signal.
        // Thread state becomes WaitReason = WrQueue.
        BOOL bRet = GetQueuedCompletionStatus(
            hIocp, 
            &bytesTransferred, 
            &completionKey, 
            &pOverlapped, 
            INFINITE
        );

        if (pOverlapped == NULL) {
            // Unrecoverable error in IOCP mechanism or thread pool shutdown
            break; 
        }

        // Recover our full context structure
        PHTTP_IO_CONTEXT pContext = (PHTTP_IO_CONTEXT)pOverlapped;

        if (!bRet) {
            // I/O failed at the kernel level (e.g., client disconnected abruptly)
            HeapFree(GetProcessHeap(), 0, pContext->RequestBuffer);
            HeapFree(GetProcessHeap(), 0, pContext);
            continue;
        }

        if (completionKey == COMPLETION_KEY_HTTP) {
            
            if (pContext->State == IoStateReceiveRequest) {
                // 1. Process the incoming HTTP Request
                
                // pContext->pRequest now contains the parsed HTTP headers/verb
                // Example: Route to C2 logic based on URL or Verb (GET/POST)
                /* if (pContext->pRequest->Verb == HttpVerbPOST) {
                       // Extract payload
                   }
                */

                // 2. Prepare the HTTP Response
                HTTP_RESPONSE response;
                ZeroMemory(&response, sizeof(response));
                response.StatusCode = 200;
                response.pReason = "OK";
                response.ReasonLength = 2;

                // 3. Send Response Asynchronously
                pContext->State = IoStateSendResponse;
                ZeroMemory(&pContext->Overlapped, sizeof(OVERLAPPED));

                ULONG result = HttpSendHttpResponse(
                    pContext->hReqQueue,
                    pContext->pRequest->RequestId,
                    0,
                    &response,
                    NULL,
                    &bytesTransferred,
                    NULL,
                    0,
                    &pContext->Overlapped, // IOCP will notify us when send is done
                    NULL
                );

                if (result != NO_ERROR && result != ERROR_IO_PENDING) {
                    // Send failed immediately
                    HeapFree(GetProcessHeap(), 0, pContext->RequestBuffer);
                    HeapFree(GetProcessHeap(), 0, pContext);
                }

            } else if (pContext->State == IoStateSendResponse) {
                // 4. Cleanup after response is sent
                // At this point, the transaction is complete. 
                
                // Memory mechanism: We must either free the context or recycle it 
                // for the next HttpReceiveHttpRequest.
                // For robustness, free and re-allocate (or implement a lookaside list to avoid heap fragmentation).
                
                HeapFree(GetProcessHeap(), 0, pContext->RequestBuffer);
                HeapFree(GetProcessHeap(), 0, pContext);

                // IMPORTANT: The main thread or a dedicated listener thread MUST 
                // continuously post new HttpReceiveHttpRequest calls with new OVERLAPPED 
                // structures, otherwise the server will stop accepting new requests.
            }
        }
    }
    return 0;
}

int main() {

    
    return 0;
}