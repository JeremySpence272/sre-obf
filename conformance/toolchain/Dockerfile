FROM ubuntu:24.04

ARG LLVM_PACKAGE_VERSION=1:22.1.8~++20260714014902+ca7933e47d3a-1~exp1~20260714135019.80

# Development-only image. It contains stock LLVM, never an old prebuilt xollvm.
# Record the resulting image ID and package versions with every run.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl gnupg cmake ninja-build g++ python3 binutils file \
    libzstd-dev zlib1g-dev libffi-dev libedit-dev libxml2-dev \
    && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL https://apt.llvm.org/llvm-snapshot.gpg.key \
    | gpg --dearmor -o /usr/share/keyrings/llvm-archive-keyring.gpg
COPY llvm22.list /etc/apt/sources.list.d/llvm22.list
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang-22="$LLVM_PACKAGE_VERSION" \
    llvm-22-dev="$LLVM_PACKAGE_VERSION" lld-22="$LLVM_PACKAGE_VERSION" \
    && rm -rf /var/lib/apt/lists/*
ENV PATH=/usr/lib/llvm-22/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1
WORKDIR /work
