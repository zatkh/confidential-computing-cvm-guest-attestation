//-------------------------------------------------------------------------------------------------
// <copyright file="GpuConfigFile.cpp" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------
//
// JSON config-file loader for Plan C CGPU attestation. Lets an operator pin the
// full attestation policy once (mode, multi-GPU knobs, RIM/OCSP endpoints) and,
// crucially, supply the NRAS service key via a FILE path rather than on the
// command line, so the secret never appears in argv / /proc/<pid>/cmdline.
//
// Compiled into the guest attestation library only when AZURE_LOCAL is defined.
//

#ifdef AZURE_LOCAL

#include "GpuAttestation.h"

#include <cctype>
#include <fstream>
#include <sstream>
#include <string>

#include <json/json.h>

namespace cgpu
{
    namespace
    {
        // Service key files larger than this are almost certainly a mistake
        // (wrong path, a whole cert chain, etc.). Cap the read to keep a bad
        // config from pulling an arbitrarily large blob into the key.
        constexpr std::streamsize kMaxServiceKeyBytes = 64 * 1024;

        // Read the whole file at `path` into `out`. Returns false (and fills
        // `error`) if it cannot be opened.
        bool read_file(const std::string &path, std::string &out, std::string *error)
        {
            std::ifstream f(path.c_str(), std::ios::in | std::ios::binary);
            if (!f.is_open())
            {
                if (error)
                    *error = "cannot open file: " + path;
                return false;
            }
            std::ostringstream ss;
            ss << f.rdbuf();
            out = ss.str();
            return true;
        }

        // Trim leading/trailing ASCII whitespace (covers the trailing newline
        // that `echo "$KEY" > file` leaves behind).
        std::string trim(const std::string &s)
        {
            size_t b = 0;
            size_t e = s.size();
            while (b < e && std::isspace(static_cast<unsigned char>(s[b])))
                ++b;
            while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1])))
                --e;
            return s.substr(b, e - b);
        }

        // Read the NRAS service key from a file, trimming surrounding
        // whitespace. Enforces a sane size cap so a misconfigured path cannot
        // load a huge blob into the key.
        bool read_service_key_file(const std::string &path, std::string &out, std::string *error)
        {
            std::ifstream f(path.c_str(), std::ios::in | std::ios::binary);
            if (!f.is_open())
            {
                if (error)
                    *error = "cannot open service_key_file: " + path;
                return false;
            }
            std::string raw;
            char buf[4096];
            std::streamsize total = 0;
            while (f.read(buf, sizeof(buf)) || f.gcount() > 0)
            {
                const std::streamsize n = f.gcount();
                total += n;
                if (total > kMaxServiceKeyBytes)
                {
                    if (error)
                        *error = "service_key_file too large: " + path;
                    return false;
                }
                raw.append(buf, static_cast<size_t>(n));
            }
            out = trim(raw);
            if (out.empty())
            {
                if (error)
                    *error = "service_key_file is empty: " + path;
                return false;
            }
            return true;
        }

        // Fetch a string field, tolerating absent/null/non-string by returning
        // the supplied default.
        std::string get_str(const Json::Value &v, const char *key, const std::string &dflt = "")
        {
            const Json::Value &n = v[key];
            return n.isString() ? n.asString() : dflt;
        }
    } // namespace

    bool load_gpu_config_file(const std::string &path, GpuConfigFile &out, std::string *error)
    {
        std::string text;
        if (!read_file(path, text, error))
            return false;

        Json::Value root;
        Json::Reader reader;
        if (!reader.parse(text, root, false) || !root.isObject())
        {
            if (error)
                *error = "invalid JSON in config file: " + path;
            return false;
        }

        GpuConfigFile result;

        const Json::Value &enabled = root["enabled"];
        result.enabled = enabled.isBool() ? enabled.asBool() : false;

        const std::string mode_str = get_str(root, "mode", "remote");
        if (mode_str == "local")
            result.mode = GpuMode::Local;
        else if (mode_str == "outpost")
            result.mode = GpuMode::Outpost;
        else if (mode_str == "remote")
            result.mode = GpuMode::Remote;
        else
        {
            if (error)
                *error = "unknown mode '" + mode_str + "' in config file: " + path;
            return false;
        }

        GpuConfig &cfg = result.cfg;
        cfg.nras_url   = get_str(root, "nras_url");
        cfg.rim_dir    = get_str(root, "rim_dir");
        cfg.ocsp_dir   = get_str(root, "ocsp_dir");
        cfg.rim_uri    = get_str(root, "rim_uri");
        cfg.ocsp_uri   = get_str(root, "ocsp_uri");
        cfg.service_key = get_str(root, "service_key");

        // Binding toggle: default true (preserve Plan C binding). Set false to
        // attest the GPU without binding it to this CVM.
        const Json::Value &bind = root["bind"];
        cfg.bind = bind.isBool() ? bind.asBool() : true;

        const Json::Value &multi = root["multi_gpu"];
        cfg.multi_gpu = multi.isBool() ? multi.asBool() : false;

        const Json::Value &count = root["expected_gpu_count"];
        if (count.isIntegral() && count.asInt64() > 0)
            cfg.expected_gpu_count = static_cast<size_t>(count.asInt64());

        const Json::Value &nvswitch = root["attest_nvswitch"];
        cfg.attest_nvswitch = nvswitch.isBool() ? nvswitch.asBool() : false;

        const Json::Value &switch_count = root["expected_switch_count"];
        if (switch_count.isIntegral() && switch_count.asInt64() > 0)
            cfg.expected_switch_count = static_cast<size_t>(switch_count.asInt64());

        // Secret-via-file: a service_key_file path takes precedence over an
        // inline service_key so the NRAS key never has to appear in argv.
        const std::string key_file = get_str(root, "service_key_file");
        if (!key_file.empty())
        {
            std::string key;
            if (!read_service_key_file(key_file, key, error))
                return false;
            cfg.service_key = key;
        }

        out = result;
        return true;
    }

} // namespace cgpu

#endif // AZURE_LOCAL
