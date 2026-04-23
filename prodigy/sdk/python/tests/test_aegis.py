# Copyright 2026 Victor Stewart
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import sys
import unittest
from pathlib import Path

SDK_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SDK_ROOT))

from neuron_hub import AegisSession, SubscriptionPairing, U128


class AegisSessionTest(unittest.TestCase):
   def test_fixtures(self) -> None:
      pairing = SubscriptionPairing(
         secret=U128(bytes(range(0x10, 0x20))),
         address=U128(bytes.fromhex("fd420000000000000000000000000001")),
         service=0x2233000000001001,
         port=3210,
         application_id=0x2233,
         activate=True,
      )
      session = AegisSession.from_subscription(pairing)
      fixtures = SDK_ROOT.parent / "fixtures"

      self.assertEqual(
         session.pairing_hash().to_bytes(8, "little"),
         (fixtures / "aegis.hash.demo.bin").read_bytes(),
      )
      self.assertEqual(
         session.build_tfo_data(b"mesh-aegis"),
         (fixtures / "aegis.tfo.demo.bin").read_bytes(),
      )

      nonce = U128(bytes(range(0x80, 0x90)))
      frame = session.encrypt_with_nonce(b"frame-one", nonce)
      self.assertEqual(frame, (fixtures / "aegis.frame.demo.bin").read_bytes())

      plaintext, header = session.decrypt(frame)
      self.assertEqual(plaintext, b"frame-one")
      self.assertEqual(header.size, len(frame))
      self.assertEqual(header.encrypted_data_size, len(b"frame-one") + 16)


if __name__ == "__main__":
   unittest.main()
