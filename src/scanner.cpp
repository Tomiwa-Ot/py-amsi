#include "amsi.h"
#pragma comment(lib, "amsi.lib")


HAMSICONTEXT amsiContext;
HRESULT hr;
HAMSISESSION amsiSession;
AMSI_RESULT result;

void initialize()
{
    hr = AmsiInitialize(L"py-amsi", &amsiContext);
    
}

void openSession()
{
    hr = AmsiOpenSession(amsiContext, &amsiSession);
}

void terminate()
{
    AmsiCloseSession(amsiContext, amsiSession);
    AmsiUninitialize(amsiContext);
}

int scanString(LPCWSTR text, LPCWSTR name)
{
    initialize();
    if (FAILED(hr))
    {
        return 2;
    }

    openSession();
    if (FAILED(hr))
    {
        AmsiUninitialize(amsiContext);
        return 3;
    }

    hr = AmsiScanString(amsiContext, text, name, amsiSession, &result);
    if (FAILED(hr))
        return 4;
    else
    {
        if (result >= AMSI_RESULT_CLEAN)
            return 1;
    }
    terminate();
    return 0;
}

int scanBytes(BYTE* payload, ULONG payloadSize, LPCWSTR name)
{
    initialize();
    if (FAILED(hr))
    {
        return 2;
    }

    openSession();
    if (FAILED(hr))
    {
        AmsiUninitialize(amsiContext);
        return 3;
    }

    hr = AmsiScanBuffer(amsiContext, payload, payloadSize, name, amsiSession, &result);
    if (FAILED(hr))
        return 4;
    else
    {
        if (result >= AMSI_RESULT_CLEAN)
            return 1;
    }
    terminate();
    return 0;
}
