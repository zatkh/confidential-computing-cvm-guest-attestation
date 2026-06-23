#pragma once
#include <AttestationClient.h>

// Minimal logger for the CGPU attestation test app. Swallows library logs by
// default; uncomment the printf in Logger.cpp to see verbose SDK/NVAT logging.
class Logger : public attest::AttestationLogger
{
public:
    void Log(const char *log_tag,
             LogLevel level,
             const char *function,
             const int line,
             const char *fmt,
             ...);
};
