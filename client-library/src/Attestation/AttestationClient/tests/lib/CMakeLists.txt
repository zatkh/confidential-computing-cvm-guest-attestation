cmake_minimum_required(VERSION 3.5)

set(CMAKE_PROJECT_TARGET AttestationClientLibTests)
project(${CMAKE_PROJECT_TARGET})

add_definitions (-DPLATFORM_UNIX)
add_definitions (-DG_TEST)

# Add Tss2
find_package(Tss2 REQUIRED)
include_directories(${TSS2_INCLUDE_DIRS})

# Add GTest
find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIRS})

# Add GMock
find_package(GMock REQUIRED)
include_directories(${GMOCK_INCLUDE_DIRS})

# Add local includes
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/../..
    ${CMAKE_CURRENT_SOURCE_DIR}/../../lib
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../LinuxTpm/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../lib/include
    ${CMAKE_SOURCE_DIR}/../external/jsoncpp-0.10.7/src
    ${CMAKE_SOURCE_DIR}/../external/SnpVmReport
)

find_path(CURL_INCLUDE_DIR NAMES curl PATHS /usr/local/attestationcurl/include
                                            NO_DEFAULT_PATH)
find_path(CRYPTO_INCLUDE_DIR NAMES openssl PATHS /usr/local/attestationssl/include
                                            NO_DEFAULT_PATH)
include_directories(${CURL_INCLUDE_DIR}
                    ${CRYPTO_INCLUDE_DIR}
)

add_executable(${CMAKE_PROJECT_TARGET} ClientLibTests.cpp
                                       ../../lib/AttestationClientImpl.cpp
                                       ../../lib/AttestationParameters.cpp
                                       ../../lib/TpmInfo.cpp
                                       ../../lib/TpmUnseal.cpp
                                       ../../AttestationHelper.cpp
                                       ../../lib/AttestationLibUtils.cpp
                                       ../../lib/NativeConverter.cpp
                                       ../../lib/Logging.cpp
                                       ../../lib/ImdsOperations.cpp
                                       ../../lib/IsolationInfo.cpp
                                       ../../lib/HclReportParser.cpp
                                       ../../lib/HttpClient.cpp
                                       ../../lib/TpmCertOperations.cpp
                                       ../../lib/ImdsClient.cpp
                                       ../../lib/AttestationLibTelemetry.cpp
                                       ../../lib/GpuAttestation.cpp
                                       ../../lib/GpuConfigFile.cpp
                                       ../../lib/CvmCgpuBinder.cpp
                                       ${CMAKE_SOURCE_DIR}/../external/jsoncpp-0.10.7/src/jsoncpp.cpp)

find_library(CURL_LIB NAMES curl PATHS /usr/local/attestationcurl/lib
                                           NO_DEFAULT_PATH)

find_library(SSL_LIB NAMES ssl PATHS /usr/local/attestationssl/lib64
                                           NO_DEFAULT_PATH)


target_link_libraries(${CMAKE_PROJECT_TARGET} ${GTEST_LIBRARIES} pthread)
target_link_libraries(${CMAKE_PROJECT_TARGET} ${GMOCK_LIBRARIES})
target_link_libraries(${CMAKE_PROJECT_TARGET} Tpm2)
target_link_libraries(${CMAKE_PROJECT_TARGET} ${TSS2_LIBRARIES})
target_link_libraries(${CMAKE_PROJECT_TARGET} ${CURL_LIB} z)
target_link_libraries(${CMAKE_PROJECT_TARGET} ${SSL_LIB})

if(AZURE_LOCAL)
    # The test exe compiles AttestationClientImpl.cpp (with the AZURE_LOCAL
    # CGPU binding gate) + GpuAttestation.cpp + CvmCgpuBinder.cpp directly, so
    # it must also find/link the NVIDIA attestation SDK (NVAT), same as the
    # DynamicLibrary build. NVAT_ROOT (cache var or env) hints the location.
    find_path(NVAT_INCLUDE_DIR
        NAMES nvat.h
        HINTS ${NVAT_ROOT} ENV NVAT_ROOT
        PATH_SUFFIXES include)
    find_library(NVAT_LIBRARY
        NAMES nvat libnvat
        HINTS ${NVAT_ROOT} ENV NVAT_ROOT
        PATH_SUFFIXES lib lib64)
    if(NOT NVAT_INCLUDE_DIR OR NOT NVAT_LIBRARY)
        message(FATAL_ERROR
            "AZURE_LOCAL=ON but NVAT not found.\n"
            "  Set NVAT_ROOT to the NVAT install prefix, e.g.\n"
            "  -DNVAT_ROOT=/path/to/nvat/install")
    endif()
    target_include_directories(${CMAKE_PROJECT_TARGET} PRIVATE ${NVAT_INCLUDE_DIR})
    target_link_libraries(${CMAKE_PROJECT_TARGET} edge-cc-base-attestation-sdk)
    target_link_libraries(${CMAKE_PROJECT_TARGET} ${NVAT_LIBRARY})
endif()
