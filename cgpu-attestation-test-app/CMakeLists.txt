cmake_minimum_required(VERSION 3.10)

project(CgpuAttestationTest)

set(CMAKE_PROJECT_TARGET cgpu-attest-test)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_definitions(-DPLATFORM_UNIX)

# The CGPU APIs (cgpu::gpu_attest / ConfigureGpuBinding / CGpuAttest) are only
# declared and exported when the guest attestation library is built with
# AZURE_LOCAL. This sample MUST match that build flavour.
add_definitions(-DAZURE_LOCAL)

# Headers shipped by the azguestattestation1 .deb:
#   /usr/include/azguestattestation1/{AttestationClient.h,GpuAttestation.h,...}
include_directories(
    /usr/include/azguestattestation1
    /usr/include/jsoncpp
)

link_directories(
    /usr/lib
    /usr/lib/x86_64-linux-gnu
)

add_executable(${CMAKE_PROJECT_TARGET}
    main.cpp
    Logger.cpp
)

# We only need the guest attestation library. The NVIDIA Attestation SDK (NVAT)
# is statically embedded inside libazguestattestation.so for the AZURE_LOCAL
# build, so cgpu::gpu_attest resolves without linking NVAT here.
target_link_libraries(${CMAKE_PROJECT_TARGET}
    azguestattestation
    curl
    jsoncpp
    z
)
