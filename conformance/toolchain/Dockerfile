FROM ubuntu:24.04

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
    clang-22 llvm-22-dev lld-22 \
    && rm -rf /var/lib/apt/lists/*
ENV PATH=/usr/lib/llvm-22/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1
WORKDIR /work
