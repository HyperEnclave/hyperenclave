#!/bin/sh

source /opt/intel/sgxsdk/environment
LINUX_SGX_DIR=/opt/intel/sgxsdk

preparation(){
    cp -r ${LINUX_SGX_DIR}/SampleCode/RemoteAttestation/sample_libcrypto/libsample_libcrypto.so ${LINUX_SGX_DIR}/sdk_libs/
    cd ${LINUX_SGX_DIR}/SampleCode/RemoteAttestation
    # set NO_CA mode
    sed -i "s/CERT_MODE ?= CFCA/CERT_MODE ?= NO_CA/g" ${LINUX_SGX_DIR}/SampleCode/RemoteAttestation/Makefile
    make clean
    make_result=$(make 2>&1)
    run_result=$(./app 2>&1)
    baseline=$(echo ${run_result} | grep -m 1 -Po '(?<=baseline =).*?(?=####hex len = 32)' | head -1)
    current=$(echo ${run_result} | grep -m 1 -Po '(?<=current value =).*?(?=####hex len = 32)' | head -1)
    baseline=${baseline// /}
    current=${current// /}
    # update enclave baseline
    if [ ${#baseline} -eq 64 ] && [ ${#current} -eq 64 ] && [ ${baseline} != ${current} ]; then
        sed -i "s/${baseline}/${current}/g" ${LINUX_SGX_DIR}/SampleCode/RemoteAttestation/service_provider/ias_ra.h
    fi
}

preparation
cd ${LINUX_SGX_DIR}/SampleCode/RemoteAttestation
make clean && make && ./app

