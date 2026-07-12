<!-- SPDX-License-Identifier: Apache-2.0 -->

# C++ SDK

`neuron_hub.h` is the transport-neutral core header. It stays independent of Prodigy runtime-private code and only handles startup decode, frame parsing, frame building, and callback dispatch.

`aegis_session.h` is the portable paired-service header. It owns the Prodigy Aegis session contract: pairing hash derivation, TFO bytes, frame layout, and encrypt/decrypt helpers.

`opinionated/pairings.h` and `opinionated/aegis_stream.h` are the higher-level paired-service layer. They keep the transport-neutral Aegis contract in the SDK, but bind it onto the existing fast-path `TCPStream` substrate for C++ containers. This surface requires Basics and is installed through Prodigy's shipped `depos` depofile inventory.

`opinionated/dns_wire.h` defines the bounded resolver-service resolve, cancel, and authenticated-session protocol. `opinionated/dns_client.h` is the thin `AsyncDnsClient` adapter: each valid named lookup retains one logical request and may replay its frame after an authenticated reconnect, while numeric literals complete locally. The application supplies only a send hook and a deadline-change hook, then forwards pairing selection, stream connection/loss, and decrypted service frames. The client has no resolver backend, cache, singleflight, c-ares channel, fallback, thread, or blocking wait.

Installed-package boundary:

- the standalone C++ package exports `Prodigy::SdkCpp` and `Prodigy::SdkCppOpinionated`
- the public installed C++ headers are `prodigy/neuron_hub.h`, `prodigy/aegis_session.h`, and `prodigy/opinionated/*.h`
- `Prodigy::SdkCpp` always carries the portable Aegis session layer plus its Aegis/gxhash dependencies
- the installed package bootstraps its Aegis, gxhash, and Basics dependency targets through the SDK's shipped depofile inventory during `find_package(ProdigySDK)`

`io_uring_reactor.h` is the optional Linux adapter. It treats the neuron socket as one reactor source and lets the application add its own socket readiness sources beside it.

`io_uring_reactor.h` remains a source/build-tree header for now because it still depends directly on liburing without its own installed consumer target.

Recommended example order:

1. `examples/aegis_roundtrip.cpp`
   Small standalone portable Aegis example using `AegisSession` directly. This is the quickest way to validate the base installed C++ package.
2. `examples/io_uring_mesh_pingpong.cpp`
   One binary that becomes advertiser or subscriber from startup state, reacts to mesh pairings, exchanges a few ping/pong messages over IPv6, and signals ready after success. This example expects Prodigy runtime startup state or a deployment-plan-driven bring-up.
3. `examples/opinionated_aegis_roundtrip.cpp`
   Higher-level pairing-driven secure exchange using `PairingBook`, `AegisSession`, and the opinionated `AegisStream`.
4. `tests/opinionated_aegis_smoke.cpp`
   Fixture-backed smoke path covering portable Aegis compatibility plus the opinionated wrapper.

Direct compile shape used locally:

```bash
clang++ -std=gnu++26 -Wall -Wextra -Werror \
   -I/root/prodigy/prodigy/sdk/cpp \
   /root/prodigy/prodigy/sdk/cpp/examples/aegis_roundtrip.cpp \
   -o /tmp/aegis_roundtrip_cpp

clang++ -std=gnu++26 -Wall -Wextra -Werror \
   -I/root/prodigy/prodigy/sdk/cpp \
   $(pkg-config --cflags liburing) \
   /root/prodigy/prodigy/sdk/cpp/examples/io_uring_mesh_pingpong.cpp \
   $(pkg-config --libs liburing) \
   -o /tmp/io_uring_mesh_pingpong_cpp
```
