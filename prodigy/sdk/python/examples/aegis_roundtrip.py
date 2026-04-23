# Copyright 2026 Victor Stewart
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import sys

from prodigy_sdk import AegisSession, ContainerParameters, SubscriptionPairing, U128


def main() -> int:
   pairing = SubscriptionPairing(
      secret=U128(bytes=bytes([
         0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
         0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
      ])),
      address=U128(bytes=bytes([
         0xFD, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
      ])),
      service=0x2233000000001001,
      port=3210,
      application_id=0x2233,
      activate=True,
   )
   parameters = ContainerParameters(
      uuid=U128(bytes=b"\0" * 16),
      memory_mb=0,
      storage_mb=0,
      logical_cores=0,
      neuron_fd=-1,
      low_cpu=0,
      high_cpu=0,
      subscription_pairings=[pairing],
   )

   writer = AegisSession.from_subscription(parameters.subscription_pairings[0])
   reader = AegisSession.from_subscription(parameters.subscription_pairings[0])
   tfo_data = writer.build_tfo_data(b"mesh-aegis")
   frame = writer.encrypt(b"ping from prodigy-sdk")
   plaintext, _header = reader.decrypt(frame)

   print(f"pairing_hash=0x{writer.pairing_hash():x} tfo_bytes={len(tfo_data)}")
   print(plaintext.decode("utf-8"))
   return 0


if __name__ == "__main__":
   sys.exit(main())
