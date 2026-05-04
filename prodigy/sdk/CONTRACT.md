# Neuron <-> Container Contract

This file is the short lifecycle summary for the current Prodigy SDK contract.

Use [`INTERFACES.md`](./INTERFACES.md) as the canonical semantic reference and [`WIRE.md`](./WIRE.md) as the packed byte-format reference. This file exists to make the runtime callback model easy to scan.

## Current Sources Of Truth

The current contract is implemented by:

- the transport-agnostic SDKs under [`./`](./)
- the standard-library-only C++ SDK in [`cpp/neuron_hub.h`](./cpp/neuron_hub.h)
- the current packed writers in [`../wire.h`](../wire.h)

The older Ring-backed implementation in Prodigy follows the same control-topic model, but it is not the canonical contract source for new SDKs.

## Startup Contract

Bootstrap loading precedence:

1. `PRODIGY_PARAMS_FD`
2. `argv[1]`
3. fail if neither is present

Startup payload type:

- preferred path: packed `PRDPAR01` `ContainerParameters`
- compatibility path: legacy Bitsery bootstrap when wormholes or whiteholes are present

Before processing live control frames, runtimes should seed local state from startup pairings and initial parameters.

## Inbound Callback Mapping

These are the semantic callbacks every SDK should expose, even if the exact language names vary.

- `none`
  - callback: `endOfDynamicArgs`
  - note: payload is empty
- `stop`
  - callback: `beginShutdown`
  - note: set local shutdown state before or alongside callback delivery
- `advertisementPairing`
  - callback: `advertisementPairing`
- `subscriptionPairing`
  - callback: `subscriptionPairing`
- `resourceDelta`
  - callback: `resourceDelta`
- `credentialsRefresh`
  - callback: `credentialsRefresh`
  - note: only when payload is non-empty
- `message`
  - callback: `messageFromProdigy`
  - note: payload stays opaque bytes

No callback is required for:

- `ping`
- `pong`
- `healthy`
- `statistics`
- `resourceDeltaAck`
- `datacenterUniqueTag`
- empty inbound `credentialsRefresh` ack frames

## Default Frame-Handler Semantics

The shared frame handler should behave like this:

- `ping`
  - return one empty outbound `ping` frame
- `pong`
  - no-op
- `healthy`
  - no-op
- `statistics`
  - no-op
- `resourceDeltaAck`
  - no-op
- `datacenterUniqueTag`
  - update cached `parameters.datacenter_unique_tag`
- empty inbound `credentialsRefresh`
  - treat as ack or no-op, not as a callback

Ack behavior is policy-driven:

- `resourceDelta`
  - application may explicitly send `resourceDeltaAck`
  - or the SDK may auto-queue one if configured
- `credentialsRefresh`
  - application may explicitly send an empty `credentialsRefresh` ack
  - or the SDK may auto-queue one if configured

## Required Outbound Operations

Every SDK should provide helpers for:

- `signalReady`
  - sends `healthy`
- `publishStatistic`
  - sends one metric pair inside `statistics`
- `publishStatistics`
  - sends many metric pairs inside `statistics`
- `acknowledgeResourceDelta`
  - sends `resourceDeltaAck`
- `acknowledgeCredentialsRefresh`
  - sends an empty `credentialsRefresh` frame

If an SDK offers queueing helpers, queued responses should preserve caller order and should be encodable without rebuilding frame logic in user code.

## Transport Model

The transport-neutral SDK contract is intentionally scheduler-agnostic:

- borrowed transport is a first-class path
- the SDK should expose an incremental decoder and a frame handler
- owned blocking or reactor helpers are convenience layers, not the protocol boundary

The control contract should not require:

- Bitsery
- C++ object layout knowledge
- runtime-private headers
- a specific reactor, scheduler, or async framework

## Networking Rules

- Prodigy-managed container-to-container traffic stays IPv6-only.
- The SDK should not add a parallel control-plane protocol.
- The control stream is one shared framed byte stream for all current control topics.

## Supporting Documents

- [`AEGIS.md`](./AEGIS.md)
- [`INTERFACES.md`](./INTERFACES.md)
- [`WIRE.md`](./WIRE.md)
- [`README.md`](./README.md)
