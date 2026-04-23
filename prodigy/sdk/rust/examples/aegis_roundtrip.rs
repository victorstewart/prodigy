// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0

use prodigy_sdk::aegis::AegisSession;
use prodigy_sdk::{SubscriptionPairing, U128};

fn main() -> Result<(), Box<dyn std::error::Error>>
{
   let pairing = SubscriptionPairing {
      secret: U128 {
         bytes: [
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
            0x1e, 0x1f,
         ],
      },
      address: U128 {
         bytes: [
            0xfd, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
         ],
      },
      service: 0x2233_0000_0000_1001,
      port: 3210,
      application_id: 0x2233,
      activate: true,
   };

   let writer = AegisSession::from_subscription(&pairing);
   let reader = AegisSession::from_subscription(&pairing);
   let nonce = [
      0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e,
      0x8f,
   ];
   let tfo_data = writer.build_tfo_data(b"mesh-aegis");
   let frame = writer.encrypt_with_nonce(b"ping from prodigy-sdk", nonce)?;
   let plaintext = reader.decrypt(&frame)?;

   println!(
      "pairing_hash={:#x} tfo_bytes={} frame_bytes={}",
      writer.pairing_hash(),
      tfo_data.len(),
      frame.len()
   );
   println!("{}", String::from_utf8(plaintext)?);
   Ok(())
}
