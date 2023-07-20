#!/bin/bash

patch_mstpm20ref() {
    # apply the patch set for ms-tpm-20-ref
    pushd ms-tpm-20-ref
    git reset --hard d638536
    git clean -f -d
    patch -p 1 -i ../patches/nv.diff
    patch -p 1 -i ../patches/openssl3.1.1.diff
    patch -p 1 -i ../patches/BaseTypes.diff
    popd
}

patch_musl() {
    pushd smallc/musl
    git reset --hard f5f55d65
    git clean -f -d
    popd
}

patch_mstpm20ref
patch_musl