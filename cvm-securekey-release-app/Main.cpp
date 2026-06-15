//-------------------------------------------------------------------------------------------------
// <copyright file="Main.cpp" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------

// TODO: Run CodeQL, static analysis on the native code. Also enable it in the repo.

#ifdef _MSC_VER
#pragma warning(disable : 4996) // suppress MSVC deprecation of getenv
#endif

#include <iostream>
#include <sstream>
#include <stdarg.h>
#include <fstream>
#include <vector>
#include <iostream>
#include <string>
#include <algorithm>
#include <thread>
#include <boost/algorithm/string.hpp>
#include <nlohmann/json.hpp>
#include <AttestationClient.h>
#include "AttestationUtil.h"
#include "Constants.h"
#ifdef PLATFORM_UNIX
#include <unistd.h> // getopt, optarg, optind, symlink
#include <sys/stat.h>

// ---------------------------------------------------------------------------
// The attestation library (libazguestattestation.so) was built on Ubuntu
// where curl's compiled-in CA path is /etc/ssl/certs/ca-certificates.crt.
// Inside the library, AttestationLibUtils.cpp does:
//
//   curl_easy_getinfo(curl, CURLINFO_CAINFO, &cainfo);   // Ubuntu default
//   if (cainfo && stat(cainfo, &buf) == 0)
//       curl_easy_setopt(curl, CURLOPT_CAINFO, cainfo);  // use it
//   else
//       curl_easy_setopt(curl, CURLOPT_CAINFO, "curl-ca-bundle.crt"); // CWD
//
// On RHEL/Fedora the Ubuntu path doesn't exist, and neither does
// curl-ca-bundle.crt, so every HTTPS call (MAA, AAD) fails with
// "Problem with the SSL CA cert (path? access rights?)".
//
// Because the library explicitly sets CURLOPT_CAINFO, the CURL_CA_BUNDLE
// env var is ignored.
//
// Fix: create a curl-ca-bundle.crt symlink in CWD pointing to the real
// system CA bundle.  The library resolves the bare relative path from CWD.
// ---------------------------------------------------------------------------
static void ensure_ca_bundle()
{
    struct stat st;

    // If curl-ca-bundle.crt already exists in CWD, nothing to do.
    if (stat("curl-ca-bundle.crt", &st) == 0)
        return;

    // Ordered list of CA bundle paths across distros.
    static const char *candidates[] = {
        "/etc/ssl/certs/ca-certificates.crt",   // Debian / Ubuntu
        "/etc/pki/tls/certs/ca-bundle.crt",     // RHEL / Fedora / CentOS
        "/etc/ssl/ca-bundle.pem",               // SUSE
        "/etc/pki/tls/cacert.pem",              // older RHEL
        "/etc/ssl/cert.pem",                    // Alpine / macOS
        nullptr
    };

    for (const char **p = candidates; *p; ++p)
    {
        if (stat(*p, &st) == 0 && S_ISREG(st.st_mode))
        {
            if (symlink(*p, "curl-ca-bundle.crt") == 0)
                fprintf(stderr, "Info: created CA symlink ./curl-ca-bundle.crt -> %s\n", *p);
            return;
        }
    }
}
#endif // PLATFORM_UNIX

#ifndef PLATFORM_UNIX
// Simple getopt implementation for Windows (getopt is POSIX-only)
static char *optarg = nullptr;
static int optind = 1;
static int getopt(int argc, char *const argv[], const char *optstring)
{
    if ((argv == nullptr) ||
        (optind >= argc) ||
        (argv[optind][0] != '-') ||
        (argv[optind][0] == 0))
    {
        return -1;
    }

    int opt = argv[optind][1];
    const char *p = strchr(optstring, opt);

    if (p == nullptr)
    {
        return '?';
    }
    if (p[1] == ':')
    {
        optind++;
        if (optind >= argc)
        {
            return '?';
        }
        optarg = argv[optind];
        optind++;
    }
    else
    {
        optind++;
    }
    return opt;
}
#endif // !PLATFORM_UNIX

void usage(char *programName)
{
    printf("Usage: \n");
    printf("\tRelease RSA or EC key:\n");
    printf("\t\t%s -a <attestation-endpoint> -n <optional-nonce> -k KeyURL -c (imds|sp) -r \n", programName);
    printf("\n");
    printf("\tRelease RSA key and wrap symmetric key:\n");
    printf("\t\t%s -a <attestation-endpoint> -n <optional-nonce> -k KEYURL -c (imds|sp) -s symkey -w \n", programName);
    printf("\n");
    printf("\tRelease RSA key and unwrap symmetric key:\n");
    printf("\t\t%s -a <attestation-endpoint> -n <optional-nonce> -k KEYURL -c (imds|sp) -s base64(wrappedSymKey) -u [-H oaep_hash] [-G mgf1_hash]\n", programName);
    printf("\n");
    printf("\tBatch unwrap from JSON file (one SKR, many unwraps):\n");
    printf("\t\t%s -a <attestation-endpoint> -n <optional-nonce> -k KEYURL -c (imds|sp) -B <json-file|-|inline> [-H oaep_hash] [-G mgf1_hash]\n", programName);
    printf("\n");
    printf("\tBatch JSON format (input):\n");
    printf("\t  { \"keys\": [ { \"id\": \"label\", \"wrapped\": \"base64...\" }, ... ] }\n");
    printf("\tBatch JSON format (output on stdout):\n");
    printf("\t  { \"results\": [ { \"id\": \"label\", \"unwrapped\": \"plaintext\" }, ... ] }\n");
    printf("\n");
    printf("\tHash algorithm options (for -u/-B unwrap only):\n");
    printf("\t\t-H <hash>  OAEP hash algorithm: sha1, sha256, sha384, sha512 (default: sha256)\n");
    printf("\t\t-G <hash>  MGF1 hash algorithm: sha1, sha256, sha384, sha512 (default: same as -H)\n");
#ifdef AZURE_LOCAL
    printf("\n");
    printf("\tPlan C CVM<->CGPU binding (gate the SKR on a healthy, bound NVIDIA GPU):\n");
    printf("\t\t-g            Enable CGPU binding (gate AKV on GPU attestation)\n");
    printf("\t\t-M <mode>     GPU verifier mode: remote | local | outpost (default: remote)\n");
    printf("\t\t-R <path|uri> RIM source: RIM dir (local) or Trust Outpost RIM URL (outpost)\n");
    printf("\t\t-O <path|uri> OCSP source: cached-response dir (local) or Trust Outpost OCSP URL (outpost)\n");
    printf("\t\t-K <key>      NRAS service key (remote/outpost; or env NVAT_SERVICE_KEY)\n");
#endif
    printf("\n");
    printf("\tExport a binding-gated MAA token (no AKV; for the AKV-simulator PoC):\n");
    printf("\t\t%s -a <attestation-endpoint> -n <optional-nonce> -g -M <mode> -X <token-out-path>\n", programName);
    printf("\t\t (writes the verified MAA token to <token-out-path> and exits 0 only if attestation\n");
    printf("\t\t  and CGPU binding pass; otherwise exits non-zero and writes nothing)\n");
    printf("\n");
    printf("\tVerbose hardware / attestation details:\n");
    printf("\t\t-V            Print CVM SEV-SNP claims, MAA token info, GPU attestation\n");
    printf("\t\t              results and the derived CGPU binding nonce (or env SKR_SHOW_DETAILS=1)\n");
}

enum class Operation
{
    None,
    WrapKey,
    UnwrapKey,
    BatchUnwrap,
    ReleaseKey,
    ExportToken,
    Undefined
};

// Check if tracing is to be enabled for SKR in the env.
void set_tracing(void)
{
    auto skr_trace_flag = std::getenv("SKR_TRACE_ON");
    if(skr_trace_flag != nullptr && strlen(skr_trace_flag) > 0)
    {
        if(strcmp(skr_trace_flag, "1") ==0 || strcmp(skr_trace_flag, "2") ==0)
        {
            std::cout<< "Tracing is enabled" <<std::endl;
            Util::set_trace(true);
            Util::set_trace_level(atoi(skr_trace_flag));
        }
        else
        {
            std::cerr<<"Invalid value for SKR_TRACE_ON!"<<std::endl;
            exit(-1);
        }
    }
}

int main(int argc, char *argv[])
{
#ifdef PLATFORM_UNIX
    ensure_ca_bundle();
#endif
    set_tracing();
    TRACE_OUT("Main started");
    // Allow enabling verbose attestation details via env (in addition to -V).
    {
        const char *show = std::getenv("SKR_SHOW_DETAILS");
        if (show != nullptr && (strcmp(show, "1") == 0 || strcmp(show, "true") == 0))
            Util::g_print_details = true;
        const char *dump = std::getenv("SKR_DUMP_TOKENS");
        if (dump != nullptr && (strcmp(dump, "1") == 0 || strcmp(dump, "true") == 0))
        {
            Util::g_dump_tokens = true;
            Util::g_print_details = true; // dumping implies showing details
        }
    }
    std::string attestation_url;
    std::string nonce;
    std::string sym_key;
    std::string key_enc_key_url;
    std::string oaep_hash = "sha256"; // default OAEP hash
    std::string mgf1_hash;            // empty = same as oaep_hash
    std::string batch_input;           // -B: JSON file path, "-" for stdin, or inline JSON
    Operation op = Operation::None;
    Util::AkvCredentialSource akv_credential_source = Util::AkvCredentialSource::Imds;

#ifdef AZURE_LOCAL
    bool gpu_binding = false;
    std::string gpu_mode_str = "remote";
    std::string gpu_rim;   // -R: RIM dir (local) or Trust Outpost RIM URL (outpost)
    std::string gpu_ocsp;  // -O: OCSP cache dir (local) or Trust Outpost OCSP URL (outpost)
    std::string gpu_key;   // -K: NRAS service key (remote/outpost)
#define SKR_GETOPT_STR "a:n:k:c:s:uwrB:H:G:gM:R:O:K:X:V"
#else
#define SKR_GETOPT_STR "a:n:k:c:s:uwrB:H:G:X:V"
#endif
    std::string export_token_path; // -X: write binding-gated MAA token here (no AKV)

    int opt;
    while ((opt = getopt(argc, argv, SKR_GETOPT_STR)) != -1)
    {
        switch (opt)
        {
        case 'a':
            attestation_url.assign(optarg);
            TRACE_OUT("attestation_url: %s", attestation_url.c_str());
            break;
        case 'n':
            nonce.assign(optarg);
            TRACE_OUT("nonce: %s", nonce.c_str());
            break;
        case 'k':
            key_enc_key_url.assign(optarg);
            TRACE_OUT("key_enc_key_url: %s", key_enc_key_url.c_str());
            break;
        case 'c':
            if (strcmp(optarg, "imds") == 0)
            {
                akv_credential_source = Util::AkvCredentialSource::Imds;
            }
            else if (strcmp(optarg, "sp") == 0)
            {
                akv_credential_source = Util::AkvCredentialSource::EnvServicePrincipal;
            }
            TRACE_OUT("akv_credential_source: %d", static_cast<int>(akv_credential_source));
            break;
        case 'u':
            op = Operation::UnwrapKey;
            TRACE_OUT("op: %d", static_cast<int>(op));
            break;
        case 'w':
            op = Operation::WrapKey;
            TRACE_OUT("op: %d", static_cast<int>(op));
            break;
        case 's':
            sym_key.assign(optarg);
            TRACE_OUT("sym_key: %s", sym_key.c_str());
            break;
        case 'r':
            op = Operation::ReleaseKey;
            TRACE_OUT("op: %d", static_cast<int>(op));
            break;
        case 'B':
            batch_input.assign(optarg);
            op = Operation::BatchUnwrap;
            TRACE_OUT("op: BatchUnwrap, input: %s", batch_input.c_str());
            break;
        case 'H':
            oaep_hash.assign(optarg);
            TRACE_OUT("oaep_hash: %s", oaep_hash.c_str());
            break;
        case 'X':
            export_token_path.assign(optarg);
            op = Operation::ExportToken;
            TRACE_OUT("op: ExportToken, path: %s", export_token_path.c_str());
            break;
        case 'V':
            Util::g_print_details = true;
            TRACE_OUT("verbose attestation details: enabled");
            break;
        case 'G':
            mgf1_hash.assign(optarg);
            TRACE_OUT("mgf1_hash: %s", mgf1_hash.c_str());
            break;
#ifdef AZURE_LOCAL
        case 'g':
            gpu_binding = true;
            TRACE_OUT("gpu_binding: enabled");
            break;
        case 'M':
            gpu_mode_str.assign(optarg);
            TRACE_OUT("gpu_mode: %s", gpu_mode_str.c_str());
            break;
        case 'R':
            gpu_rim.assign(optarg);
            TRACE_OUT("gpu_rim: %s", gpu_rim.c_str());
            break;
        case 'O':
            gpu_ocsp.assign(optarg);
            TRACE_OUT("gpu_ocsp: %s", gpu_ocsp.c_str());
            break;
        case 'K':
            gpu_key.assign(optarg);
            TRACE_OUT("gpu_key: <set>");
            break;
#endif
        case ':':
            std::cerr << "Option needs a value" << std::endl;
            return EXIT_FAILURE;
        default:
            usage(argv[0]);
            return EXIT_FAILURE;
        }
    }

    bool success = false;
    int retVal = 0;
    try
    {
#ifdef AZURE_LOCAL
        // Wire Plan C CGPU binding config into Util. Consumed by GetMAAToken(),
        // which configures the library binding gate before calling Attest().
        if (gpu_binding)
        {
            Util::g_gpu_binding_enabled = true;
            if (gpu_mode_str == "local")
            {
                // Local = fully air-gapped in-guest verifier. -R is the
                // filesystem RIM directory; -O (optional) is a directory of
                // cached OCSP responses (turned into a file:// URL). With no
                // -O the NVIDIA default OCSP is used (needs network).
                Util::g_gpu_mode = cgpu::GpuMode::Local;
                Util::g_gpu_cfg.rim_dir = gpu_rim;
                Util::g_gpu_cfg.ocsp_dir = gpu_ocsp;
            }
            else if (gpu_mode_str == "outpost")
            {
                // Outpost = NRAS (remote) verifier with RIM/OCSP served by an
                // on-prem NVIDIA Trust Outpost. -R/-O point at the Outpost RIM/
                // OCSP; the NRAS base URL comes from NVAT_OUTPOST_NRAS_URL (env)
                // and the service key from -K / NVAT_SERVICE_KEY.
                Util::g_gpu_mode = cgpu::GpuMode::Outpost;
                Util::g_gpu_cfg.rim_uri = gpu_rim;
                Util::g_gpu_cfg.ocsp_uri = gpu_ocsp;
                Util::g_gpu_cfg.service_key = gpu_key;
            }
            else // remote (default)
            {
                Util::g_gpu_mode = cgpu::GpuMode::Remote;
                Util::g_gpu_cfg.nras_url = gpu_rim; // optional NRAS base URL override
                Util::g_gpu_cfg.service_key = gpu_key;
            }
        }
#endif
        std::string result;
        switch (op)
        {
        case Operation::WrapKey:
            result = Util::WrapKey(attestation_url, nonce, sym_key, key_enc_key_url, akv_credential_source);
            std::cout << result << std::endl;
            break;
        case Operation::UnwrapKey:
            result = Util::UnwrapKey(attestation_url, nonce, sym_key, key_enc_key_url, akv_credential_source,
                                    oaep_hash, mgf1_hash);
            std::cout << result << std::endl;
            break;
        case Operation::BatchUnwrap:
        {
            // Read batch JSON: from file, stdin ("-"), or inline JSON string
            std::string batch_json;
            if (batch_input == "-")
            {
                std::ostringstream ss;
                ss << std::cin.rdbuf();
                batch_json = ss.str();
            }
            else if (!batch_input.empty() && batch_input[0] == '{')
            {
                batch_json = batch_input; // inline JSON on command line
            }
            else
            {
                std::ifstream ifs(batch_input);
                if (!ifs.is_open())
                {
                    std::cerr << "Failed to open batch JSON file: " << batch_input << std::endl;
                    return EXIT_FAILURE;
                }
                std::ostringstream ss;
                ss << ifs.rdbuf();
                batch_json = ss.str();
            }
            result = Util::UnwrapKeyBatch(attestation_url, nonce, batch_json,
                                          key_enc_key_url, akv_credential_source,
                                          oaep_hash, mgf1_hash);
            std::cout << result << std::endl;
            break;
        }
        case Operation::ReleaseKey:
            success = Util::ReleaseKey(attestation_url, nonce, key_enc_key_url, akv_credential_source);
            retVal = success ? EXIT_SUCCESS : EXIT_FAILURE;
            break;
        case Operation::ExportToken:
            success = Util::ExportBoundToken(attestation_url, nonce, export_token_path);
            retVal = success ? EXIT_SUCCESS : EXIT_FAILURE;
            break;
        default:
            usage(argv[0]);
            retVal = EXIT_FAILURE;
        }
    }
    catch (skr_error &e)
    {
        std::cerr << e.what() << std::endl;
        retVal = e.exit_code;
    }
    catch (std::exception &e)
    {
        std::cerr << "Exception occured. Details: " << e.what() << std::endl;
        retVal = EXIT_FAILURE;
    }

    return retVal;
}
