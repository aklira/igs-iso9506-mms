# SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
#
# SPDX-License-Identifier: Apache-2.0
#
# Reference peer of the bench: the example programs of libiec61850, built from a fixed commit.
# They run as black boxes (IMPLEMENTATION.md, rule 1): nobody reads the source, which stays in the
# build stage; only the executables reach the final image.

FROM docker.io/library/debian@sha256:c67e92c8099ba22853ab4cfda7cfb494d253d6012ca82dee98ba8976772af018 AS build
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates cmake g++ gcc git make \
    && rm -rf /var/lib/apt/lists/*
RUN git init /src \
    && git -C /src remote add origin https://github.com/mz-automation/libiec61850.git \
    && git -C /src fetch --depth 1 origin c28c27cb8dd56eb7cf577c68dfa6e6de556d8997 \
    && git -C /src checkout FETCH_HEAD
RUN cmake -S /src -B /build -DBUILD_EXAMPLES=ON -DBUILD_SHARED_LIBS=OFF \
    && cmake --build /build --parallel
RUN mkdir -p /peer \
    && find /build/examples -type f -executable ! -name '*.so*' ! -name '*.sh' \
        ! -path '*/CMakeFiles/*' -exec cp {} /peer/ \;

FROM docker.io/library/debian@sha256:c67e92c8099ba22853ab4cfda7cfb494d253d6012ca82dee98ba8976772af018
COPY --from=build /peer /peer
ENV PATH=/peer:$PATH
