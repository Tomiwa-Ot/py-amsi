#include <stdio.h>
#include "amsi.h"
#pragma comment(lib, "amsi.lib")

// Compile commands:
// -----------------
// gcc -c -fPIC scanner.c -o scanner.o   
// gcc --whole-file -shared -Wl,-soname,scanner.dll -o amsiscanner.dll scanner.o C:\Windows\System32\amsi.dll   

HAMSICONTEXT amsiContext;
HAMSISESSION amsiSession;
AMSI_RESULT result;
HRESULT hr;
// IAntimalwareProvider iap;


void initialize(int debug)
{
    hr = AmsiInitialize(L"py-amsi", &amsiContext);
    if (FAILED(hr))
    {
        if (debug == 1)
        {
            printf("[!] AmsiInitialize failed\n");
            exit(100);
        }
    }
}

void openSession(int debug)
{
    hr = AmsiOpenSession(amsiContext, &amsiSession);
    if (FAILED(hr))
    {
        if (debug == 1)
            printf("[!] AmsiOpenSession failed\n");
        AmsiUninitialize(amsiContext);
        exit(101);
    }
}


void terminate()
{
    AmsiCloseSession(amsiContext, amsiSession);
    AmsiUninitialize(amsiContext);
}

int scanString(LPCWSTR text, LPCWSTR name, int debug)
{

    int returnCode;

    initialize(debug);
    openSession(debug);

    
    hr = AmsiScanString(amsiContext, text, name, amsiSession, &result);
    if (FAILED(hr))
    {
        if (debug == 1)
            printf("[!] AmsiScanString failed\n");
        exit(102);
    }
    else
    {
        switch (result)
        {
        case AMSI_RESULT_CLEAN:
            if (debug == 1)
                printf("String is clean\n");
            returnCode = AMSI_RESULT_CLEAN;
            break;
        case AMSI_RESULT_NOT_DETECTED:
            if (debug == 1)
                printf("No threat detected\n");
            returnCode = AMSI_RESULT_NOT_DETECTED;
            break;
        case AMSI_RESULT_BLOCKED_BY_ADMIN_START:
            if (debug == 1)
                printf("Threat is blocked by the administrator\n");
            returnCode = AMSI_RESULT_BLOCKED_BY_ADMIN_START;
            break;
        case AMSI_RESULT_BLOCKED_BY_ADMIN_END:
            if (debug == 1)
                printf("Threat is blocked by the administrator\n");
            returnCode = AMSI_RESULT_BLOCKED_BY_ADMIN_END;
            break;
        case AMSI_RESULT_DETECTED:
            if (debug == 1)
                printf("String is considered malware\n");
            returnCode = AMSI_RESULT_DETECTED;
            break;
        default:
            if (debug == 1)
                printf("N/A\n");
            returnCode = 5;
            break;
        }
    }
    
    terminate();
    return returnCode;
}

int scanBytes(BYTE* payload, ULONG payloadSize, LPCWSTR name, int debug)
{
    int returnCode;
    
    initialize(debug);
    openSession(debug);

    // FILE *fileptr;
    // char *buffer;
    // long filelen;

    // fileptr = fopen(path, "rb"); // Open the file in binary mode
    // fseek(fileptr, 0, SEEK_END); // Jump to the end of the file
    // filelen = ftell(fileptr); // Get the current byte offset in the file
    // buffer = (char *)malloc(filelen * sizeof(char)); // Enough memory for the file
    // fread(buffer, filelen, 1, fileptr); // Read the entire file
    // fclose(fileptr); // Close file
    
    hr = AmsiScanBuffer(amsiContext, payload, payloadSize, name, amsiSession, &result);
    if (FAILED(hr))
    {
        if (debug == 1)
            printf("[!] AmsiScanBuffer failed\n");
        exit(102);
    }  
    else
    {
        switch (result)
        {
        case AMSI_RESULT_CLEAN:
            if (debug == 1)
                printf("File is clean\n");
            returnCode = AMSI_RESULT_CLEAN;
            break;
        case AMSI_RESULT_NOT_DETECTED:
            if (debug == 1)
                printf("No threat detected\n");
            returnCode = AMSI_RESULT_NOT_DETECTED;
            break;
        case AMSI_RESULT_BLOCKED_BY_ADMIN_START:
            if (debug == 1)
                printf("Threat is blocked by the administrator\n");
            returnCode = AMSI_RESULT_BLOCKED_BY_ADMIN_START;
            break;
        case AMSI_RESULT_BLOCKED_BY_ADMIN_END:
            if (debug == 1)
                printf("Threat is blocked by the administrator\n");
            returnCode = AMSI_RESULT_BLOCKED_BY_ADMIN_END;
            break;
        case AMSI_RESULT_DETECTED:
            if (debug == 1)
                printf("File is considered malware\n");
            returnCode = AMSI_RESULT_DETECTED;
            break;
        default:
            if (debug == 1)
                printf("N/A\n");
            returnCode = 5;
            break;
        }
    }
    terminate();
    return returnCode;
}

