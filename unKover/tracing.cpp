#include "meta.h"
#include <stdarg.h>
#include <strsafe.h>
#include <TraceLoggingProvider.h>

// Define TraceLogging provider
// GUID generated for this provider: {12345678-1234-1234-1234-1234567890AB}
TRACELOGGING_DEFINE_PROVIDER(
    g_hTraceProvider,
    "unKover",
    (0x95bc72d9, 0x99bc, 0x7317, 0x12, 0xbc, 0xda, 0xc4, 0xe2, 0x19, 0x20, 0x0c)
);

void UkTraceEtw(_In_ PCSTR Type, _In_ PCSTR Format, ...)
{
    CHAR buffer[512];
    va_list args;
    va_start(args, Format);
    // Format message into buffer
    StringCbVPrintfA(buffer, sizeof(buffer), Format, args);
    va_end(args);

    TraceLoggingWrite(
        g_hTraceProvider,
        "UnkoverEvent",
        TraceLoggingString(Type, "Type"),
        TraceLoggingString(buffer, "Message")
    );
}
