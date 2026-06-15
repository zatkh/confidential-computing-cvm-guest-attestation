#!/bin/bash

# repostiory marks scripts as non-executable, here are commands to find and apply executable permissions to all .sh files in the repository, you can run these commands in the root of the repository
#find . -type f -name "*.sh"
# apply
#find . -type f -name "*.sh" -exec chmod +x {} +

INSTALL_PREREQS=false

function Usage()
{
    echo "Usage: $0 [-h] [-p] --> where -p installs pre-requisites. By default pre-requisites are skipped.";
    exit 1;
}

while getopts ":hp" opt; do
  case ${opt} in
    h )
        Usage
      ;;
    p )
        INSTALL_PREREQS=true
      ;;
    \? )
        Usage
      ;;
  esac
done

sudo rm -rf ../client-library/src/Attestation/_build
sudo dpkg -r azguestattestation1 2>/dev/null || true

if [ "$INSTALL_PREREQS" = true ]; then
    sudo ../client-library/src/Attestation/pre-requisites-azure-local.sh
fi

# CGPU binding links the NVIDIA attestation SDK (NVAT) into the library .so.
# Forward NVAT_ROOT through sudo (which otherwise scrubs the environment) so
# the CMake find_path/find_library can locate nvat.h / libnvat.
sudo NVAT_ROOT="${NVAT_ROOT}" ../client-library/src/Attestation/build.sh -l
sudo dpkg -i ../client-library/src/Attestation/_build/x86_64/packages/attestationlibrary/deb/azguestattestation1_1.0.5_amd64.deb