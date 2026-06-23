#include <AttestationClient.h>
#include <cstdarg>
#include <cstdio>
#include <vector>

#include "Logger.h"

void Logger::Log(const char *log_tag,
                 LogLevel level,
                 const char *function,
                 const int line,
                 const char *fmt,
                 ...)
{
    va_list args;
    va_start(args, fmt);
    int len = std::vsnprintf(nullptr, 0, fmt, args);
    va_end(args);
    if (len < 0)
        return;

    std::vector<char> str(static_cast<size_t>(len) + 1);
    va_start(args, fmt);
    std::vsnprintf(str.data(), str.size(), fmt, args);
    va_end(args);

    // Uncomment to see verbose SDK / NVAT logs:
    // printf("Level: %s Tag: %s %s:%d: %s\n",
    //        attest::AttestationLogger::LogLevelStrings[level].c_str(),
    //        log_tag, function, line, str.data());
}
