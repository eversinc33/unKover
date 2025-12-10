#include "meta.h"
#include <stdarg.h>
#include <strsafe.h>
#include <TraceLoggingProvider.h>

TRACELOGGING_DEFINE_PROVIDER(
    g_hTraceProvider,
    "unKover",
    (0x95bc72d9, 0x99bc, 0x7317, 0x12, 0xbc, 0xda, 0xc4, 0xe2, 0x19, 0x20, 0x0c)
);

/**
 * @brief Emit an ETW trace event using TraceLogging.
 *
 * @param[IN] Type   ASCII category string.
 * @param[IN] Format printf-style ANSI format string.
 */
_IRQL_requires_same_
_IRQL_requires_(PASSIVE_LEVEL)
void
UkTraceEtw(
    _In_ PCSTR Type,
    _In_ PCSTR Format,
    ...
)
{
    CHAR buffer[1024];
    va_list args;
    va_start(args, Format);
    StringCbVPrintfA(buffer, sizeof(buffer), Format, args);
    va_end(args);

    TraceLoggingWrite(
        g_hTraceProvider,
        "UnkoverEvent",
        TraceLoggingString(Type, "Type"),
        TraceLoggingString(buffer, "Message")
    );
}
