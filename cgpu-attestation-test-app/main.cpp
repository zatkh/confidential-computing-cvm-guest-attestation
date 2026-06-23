//-------------------------------------------------------------------------------------------------
// CGPU attestation test app.
//
// A tiny standalone harness for exercising every CGPU (NVIDIA confidential GPU)
// attestation flavour exposed by the Azure guest attestation library
// (libazguestattestation, AZURE_LOCAL build):
//
//   -t cvm   : CVM-only MAA attestation (baseline; no GPU involved).
//   -t gpu   : CGPU attestation ONLY, with NO CVM binding. Calls cgpu::gpu_attest
//              directly with a fresh random nonce. Use -m for the multi-GPU check.
//   -t bind  : CVM attestation + CGPU binding (Plan C). Gets an MAA token via
//              Attest(), then binds the GPU(s) to THIS CVM via CGpuAttest().
//
// Each GPU flow runs under a verifier mode (-M remote|local|outpost) and can be
// single- or multi-GPU (-m), so the matrix the user asked for is:
//
//   gpu  + remote   (single / -m multi)
//   gpu  + local    (single / -m multi)
//   bind + remote   (single / -m multi)
//   bind + local    (single / -m multi)
//
// The GPU binding protocol (tying the GPU to the CVM's MAA token) is therefore
// OPTIONAL: it only runs in -t bind. -t gpu attests the GPU on its own.
//
// This file deliberately depends only on <AttestationClient.h> + the C++ stdlib
// so it is easy to read and to link. Build instructions are in README.md.
//-------------------------------------------------------------------------------------------------

#include <AttestationClient.h>

#include <cstdint>
#include <cstring>
#include <iostream>
#include <random>
#include <string>
#include <vector>

#include "Logger.h"

#ifndef AZURE_LOCAL
#error "This sample must be built with -DAZURE_LOCAL to access the CGPU APIs."
#endif

namespace
{
    // The default Azure Attestation endpoint used for the CVM (MAA) leg.
    const std::string kDefaultAttestationUrl = "https://sharedeus2.eus2.attest.azure.net/";

    enum class TestType
    {
        Cvm,   // CVM-only MAA attestation.
        Gpu,   // CGPU attestation only, no CVM binding.
        Bind   // CVM attestation + CGPU binding (Plan C).
    };

    void usage(const char *prog)
    {
        std::cout <<
            "CGPU attestation test app\n"
            "\n"
            "Usage: " << prog << " -t <cvm|gpu|bind> [options]\n"
            "\n"
            "  -t <type>     Attestation flow to run:\n"
            "                  cvm   CVM-only MAA attestation (no GPU)\n"
            "                  gpu   CGPU attestation only, NO CVM binding\n"
            "                  bind  CVM attestation + CGPU binding (Plan C)\n"
            "  -M <mode>     GPU verifier mode: remote | local | outpost (default: remote)\n"
            "  -m            Multi-GPU: require EVERY GPU (not just GPU 0) to pass\n"
            "  -N <count>    Multi-GPU: require exactly <count> GPUs present (0 = any)\n"
            "  -a <url>      MAA attestation endpoint (cvm/bind; default shared EUS2)\n"
            "  -n <nonce>    Session nonce: skr_nonce (bind) or hex nonce (gpu; random if unset)\n"
            "  -R <path|uri> RIM source: RIM dir (local) or Trust Outpost RIM URL (outpost)\n"
            "  -O <path|uri> OCSP source: OCSP cache dir (local) or Trust Outpost OCSP URL (outpost)\n"
            "  -K <key>      NRAS service key (remote/outpost; or env NVAT_SERVICE_KEY)\n"
            "  -v            Verbose: print detached EAT (JWT) and full claims JSON\n"
            "  -h            Show this help\n"
            "\n"
            "Examples:\n"
            "  " << prog << " -t gpu  -M remote                 # single GPU, NRAS verifier\n"
            "  " << prog << " -t gpu  -M local  -R /opt/rim -m   # all GPUs, in-guest verifier\n"
            "  " << prog << " -t bind -M remote -m -N 8          # bind all 8 GPUs to this CVM\n"
            "  " << prog << " -t cvm                             # plain CVM attestation\n";
    }

    const char *mode_name(cgpu::GpuMode m)
    {
        switch (m)
        {
        case cgpu::GpuMode::Remote:  return "remote (NVIDIA NRAS cloud verifier)";
        case cgpu::GpuMode::Local:   return "local (in-guest verifier + RIM dir)";
        case cgpu::GpuMode::Outpost: return "outpost (NRAS + on-prem Trust Outpost RIM/OCSP)";
        }
        return "unknown";
    }

    std::string to_hex(const uint8_t *p, size_t n)
    {
        static const char kHex[] = "0123456789abcdef";
        std::string s;
        s.reserve(n * 2);
        for (size_t i = 0; i < n; ++i)
        {
            s.push_back(kHex[(p[i] >> 4) & 0xF]);
            s.push_back(kHex[p[i] & 0xF]);
        }
        return s;
    }

    // Fill a 32-byte nonce. If `hex` holds 64 hex chars we parse it (reproducible
    // runs); otherwise we generate a fresh random nonce (freshness for -t gpu).
    void make_nonce(uint8_t out[32], const std::string &hex)
    {
        if (hex.size() == 64)
        {
            bool ok = true;
            for (int i = 0; i < 32 && ok; ++i)
            {
                auto nibble = [&](char c, bool &good) -> int {
                    if (c >= '0' && c <= '9') return c - '0';
                    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                    good = false;
                    return 0;
                };
                out[i] = static_cast<uint8_t>((nibble(hex[2 * i], ok) << 4) | nibble(hex[2 * i + 1], ok));
            }
            if (ok)
                return;
        }
        std::random_device rd;
        for (int i = 0; i < 32; ++i)
            out[i] = static_cast<uint8_t>(rd() & 0xFF);
    }

    // Build the mode-specific GPU verifier config from the CLI options. Mirrors
    // the wiring done by the SKR app's Main.cpp so behaviour is identical.
    cgpu::GpuConfig build_gpu_cfg(cgpu::GpuMode mode,
                                  const std::string &rim,
                                  const std::string &ocsp,
                                  const std::string &key,
                                  bool multi,
                                  size_t expected_count)
    {
        cgpu::GpuConfig cfg{};
        cfg.multi_gpu = multi;
        cfg.expected_gpu_count = expected_count;
        switch (mode)
        {
        case cgpu::GpuMode::Local:
            cfg.rim_dir = rim;    // filesystem RIM directory
            cfg.ocsp_dir = ocsp;  // optional cached OCSP dir (file://)
            break;
        case cgpu::GpuMode::Outpost:
            cfg.rim_uri = rim;        // on-prem Trust Outpost RIM URL
            cfg.ocsp_uri = ocsp;      // on-prem Trust Outpost OCSP URL
            cfg.service_key = key;    // NRAS service key
            break;
        case cgpu::GpuMode::Remote:
        default:
            cfg.nras_url = rim;       // optional NRAS base URL override
            cfg.service_key = key;    // NRAS service key
            break;
        }
        return cfg;
    }

    // Print a GpuResult, including the multi-GPU aggregates.
    void print_gpu_result(const cgpu::GpuResult &g, cgpu::GpuMode mode, bool verbose)
    {
        std::cout << "  verifier mode            : " << mode_name(mode) << "\n";
        std::cout << "  GPU healthy (overall)    : " << (g.overall_result ? "true" : "false") << "\n";
        std::cout << "  evidence records         : " << g.num_evidences << "\n";
        std::cout << "  GPU claim records        : " << g.num_gpus << "\n";
        std::cout << "  GPUs nonce-bound         : " << g.num_gpus_bound << " of " << g.num_gpus << "\n";
        std::cout << "  GPU[0] nonce-match       : " << (g.nonce_match ? "true" : "false") << "\n";
        std::cout << "  ALL GPUs nonce-match     : " << (g.all_nonce_match ? "true" : "false") << "\n";
        std::cout << "  GPU[0] UEID              : " << (g.ueid.empty() ? "(none)" : g.ueid) << "\n";
        for (size_t i = 0; i < g.ueids.size(); ++i)
            std::cout << "    GPU[" << i << "] UEID            : "
                      << (g.ueids[i].empty() ? "(none)" : g.ueids[i]) << "\n";
        if (!g.nonce_hex.empty())
            std::cout << "  binding nonce (hex)      : " << g.nonce_hex << "\n";
        if (!g.error.empty())
            std::cout << "  error                    : " << g.error << "\n";
        if (verbose)
        {
            std::cout << "  detached EAT (JWT)       :\n    "
                      << (g.detached_eat.empty() ? "(none)" : g.detached_eat) << "\n";
            std::cout << "  claims JSON              :\n"
                      << (g.claims_json.empty() ? "(none)" : g.claims_json) << "\n";
        }
    }

    // Decide pass/fail for a standalone (no-binding) GPU attestation, applying
    // single- vs multi-GPU semantics ourselves (cgpu::gpu_attest always collects
    // every GPU; the binder is what normally enforces "all bound").
    bool gpu_only_pass(const cgpu::GpuResult &g, bool multi, size_t expected_count)
    {
        if (!g.overall_result)
            return false;
        if (multi)
        {
            if (g.num_evidences == 0 || g.num_gpus_bound != g.num_evidences)
                return false;
            if (expected_count > 0 && g.num_evidences != expected_count)
                return false;
            return true;
        }
        // single: GPU 0 must be healthy and have echoed our nonce.
        return g.nonce_match;
    }
}

int main(int argc, char *argv[])
{
    TestType type = TestType::Cvm;
    bool type_set = false;
    cgpu::GpuMode mode = cgpu::GpuMode::Remote;
    bool multi = false;
    size_t expected_count = 0;
    std::string attestation_url;
    std::string nonce;
    std::string rim, ocsp, key;
    bool verbose = false;

    for (int i = 1; i < argc; ++i)
    {
        std::string a = argv[i];
        auto next = [&](const char *name) -> std::string {
            if (i + 1 >= argc)
            {
                std::cerr << "Option " << name << " needs a value\n";
                std::exit(2);
            }
            return argv[++i];
        };

        if (a == "-h" || a == "--help") { usage(argv[0]); return 0; }
        else if (a == "-t")
        {
            std::string t = next("-t");
            if (t == "cvm") type = TestType::Cvm;
            else if (t == "gpu") type = TestType::Gpu;
            else if (t == "bind") type = TestType::Bind;
            else { std::cerr << "Unknown -t value: " << t << "\n"; return 2; }
            type_set = true;
        }
        else if (a == "-M")
        {
            std::string m = next("-M");
            if (m == "remote") mode = cgpu::GpuMode::Remote;
            else if (m == "local") mode = cgpu::GpuMode::Local;
            else if (m == "outpost") mode = cgpu::GpuMode::Outpost;
            else { std::cerr << "Unknown -M value: " << m << "\n"; return 2; }
        }
        else if (a == "-m") multi = true;
        else if (a == "-N") expected_count = static_cast<size_t>(std::stoul(next("-N")));
        else if (a == "-a") attestation_url = next("-a");
        else if (a == "-n") nonce = next("-n");
        else if (a == "-R") rim = next("-R");
        else if (a == "-O") ocsp = next("-O");
        else if (a == "-K") key = next("-K");
        else if (a == "-v") verbose = true;
        else { std::cerr << "Unknown arg: " << a << "\n"; usage(argv[0]); return 2; }
    }

    if (!type_set)
    {
        usage(argv[0]);
        return 2;
    }
    if (attestation_url.empty())
        attestation_url = kDefaultAttestationUrl;

    AttestationClient *client = nullptr;
    Logger *log_handle = new Logger();
    if (!Initialize(log_handle, &client))
    {
        std::cerr << "Failed to create attestation client object\n";
        Uninitialize();
        delete log_handle;
        return 1;
    }

    int exit_code = 0;
    try
    {
        // -------------------------------------------------------------------
        // 1. CGPU attestation ONLY (no CVM binding).
        // -------------------------------------------------------------------
        if (type == TestType::Gpu)
        {
            std::cout << "=== CGPU attestation (no CVM binding) ===\n";
            std::cout << "  scope                    : " << (multi ? "multi-GPU (all)" : "single GPU") << "\n";

            uint8_t gpu_nonce[32];
            make_nonce(gpu_nonce, nonce);
            std::cout << "  freshness nonce (hex)    : " << to_hex(gpu_nonce, 32) << "\n";

            cgpu::GpuConfig cfg = build_gpu_cfg(mode, rim, ocsp, key, multi, expected_count);
            cgpu::GpuResult g = cgpu::gpu_attest(gpu_nonce, mode, cfg);

            print_gpu_result(g, mode, verbose);
            bool pass = gpu_only_pass(g, multi, expected_count);
            std::cout << "  RESULT                   : " << (pass ? "PASS" : "FAIL") << "\n";
            exit_code = pass ? 0 : 1;
        }
        // -------------------------------------------------------------------
        // 2. CVM attestation, optionally followed by CGPU binding.
        // -------------------------------------------------------------------
        else
        {
            std::cout << "=== CVM (MAA) attestation ===\n";
            std::cout << "  endpoint                 : " << attestation_url << "\n";

            attest::ClientParameters params = {};
            params.attestation_endpoint_url = (unsigned char *)attestation_url.c_str();
            std::string client_payload = "{\"nonce\":\"" + nonce + "\"}";
            params.client_payload = (unsigned char *)client_payload.c_str();
            params.version = CLIENT_PARAMS_VERSION;

            unsigned char *jwt = nullptr;
            attest::AttestationResult result = client->Attest(params, &jwt);
            if (result.code_ != attest::AttestationResult::ErrorCode::SUCCESS)
            {
                std::cout << "  RESULT                   : FAIL (" << result.description_ << ")\n";
                Uninitialize();
                delete log_handle;
                return 1;
            }

            std::string maa_token = reinterpret_cast<char *>(jwt);
            client->Free(jwt);
            std::cout << "  MAA token                : received (" << maa_token.size() << " bytes)\n";
            std::cout << "  RESULT                   : PASS\n";

            if (type == TestType::Bind)
            {
                std::cout << "\n=== CGPU binding (gate GPU on THIS CVM) ===\n";
                std::cout << "  scope                    : " << (multi ? "multi-GPU (all)" : "single GPU") << "\n";

                cgpu::GpuConfig cfg = build_gpu_cfg(mode, rim, ocsp, key, multi, expected_count);
                // enabled=false: we do NOT want Attest() to re-run the gate; we
                // only need the configured mode/cfg for the explicit call below.
                client->ConfigureGpuBinding(false, mode, cfg);

                cgpu::GpuResult g;
                attest::AttestationResult bind = client->CGpuAttest(maa_token, nonce, &g);

                print_gpu_result(g, mode, verbose);
                bool pass = (bind.code_ == attest::AttestationResult::ErrorCode::SUCCESS);
                std::cout << "  RESULT                   : " << (pass ? "PASS" : "FAIL");
                if (!pass)
                    std::cout << " (" << bind.description_ << ")";
                std::cout << "\n";
                exit_code = pass ? 0 : 1;
            }
        }
    }
    catch (const std::exception &e)
    {
        std::cerr << "Exception: " << e.what() << "\n";
        exit_code = 1;
    }

    Uninitialize();
    delete log_handle;
    return exit_code;
}
