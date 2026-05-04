// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0

use prodigy_sdk::aegis::AegisSession;
use prodigy_sdk::opinionated::{ActivationAction, AegisStream, PairingBook};
use prodigy_sdk::{ContainerParameters, SubscriptionPairing, U128};

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

   let parameters = ContainerParameters {
      subscription_pairings: vec![pairing],
      ..ContainerParameters::default()
   };

   let mut book = PairingBook::default();
   for action in book.seed_from_parameters(&parameters)
   {
      match action
      {
         ActivationAction::ConnectSubscriber(pairing) =>
         {
            let session = AegisSession::from_subscription(&pairing);
            let mut writer = AegisStream::with_session(session);
            let mut reader = AegisStream::with_session(session);

            let tfo_data = writer.build_tfo_data(b"mesh-aegis");
            println!("pairing_hash={:#x} tfo_bytes={}", writer.pairing_hash(), tfo_data.len());

            writer.queue_encrypted(b"ping from prodigy-sdk-opinionated")?;
            let outbound = writer.take_pending_buffer();
            reader.push_inbound(&outbound)?;
            let inbound = reader.next_inbound_message()?.expect("missing inbound message");

            println!("{}", String::from_utf8(inbound.plaintext)?);
         }
         other =>
         {
            println!("ignored startup action: {other:?}");
         }
      }
   }

   Ok(())
}
