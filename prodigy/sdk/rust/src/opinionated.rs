// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0

use std::collections::{HashMap, VecDeque};
use std::io;
use std::sync::OnceLock;
use std::time::Instant;

use crate::aegis::{
   decode_frame_header,
   AegisSession,
   AEGIS_MAX_FRAME_BYTES,
   AEGIS_MIN_FRAME_BYTES,
};
use crate::{AdvertisementPairing, ContainerParameters, SubscriptionPairing, U128};

const INBOUND_COMPACT_THRESHOLD: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PairingKey
{
   pub secret: U128,
   pub service: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActivationAction
{
   RegisterAdvertiser(AdvertisementPairing),
   ConnectSubscriber(SubscriptionPairing),
   DeactivateAdvertiser(PairingKey),
   DeactivateSubscriber(PairingKey),
}

#[derive(Clone, Debug, Default)]
pub struct PairingBook
{
   advertisements: HashMap<PairingKey, AdvertisementPairing>,
   subscriptions: HashMap<PairingKey, SubscriptionPairing>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InboundMessage
{
   pub queued_at_ns: i64,
   pub plaintext: Vec<u8>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AegisStream
{
   pub session: AegisSession,
   pending_buffer: Vec<u8>,
   inbound_buffer: Vec<u8>,
   inbound_head: usize,
   inbound_queued_at_ns: VecDeque<i64>,
}

impl PairingKey
{
   pub fn from_advertisement(pairing: &AdvertisementPairing) -> Self
   {
      Self {
         secret: pairing.secret,
         service: pairing.service,
      }
   }

   pub fn from_subscription(pairing: &SubscriptionPairing) -> Self
   {
      Self {
         secret: pairing.secret,
         service: pairing.service,
      }
   }
}

impl PairingBook
{
   pub fn advertisements(&self) -> &HashMap<PairingKey, AdvertisementPairing>
   {
      &self.advertisements
   }

   pub fn subscriptions(&self) -> &HashMap<PairingKey, SubscriptionPairing>
   {
      &self.subscriptions
   }

   pub fn seed_from_parameters(&mut self, parameters: &ContainerParameters) -> Vec<ActivationAction>
   {
      let mut actions = Vec::with_capacity(
         parameters.advertisement_pairings.len() + parameters.subscription_pairings.len(),
      );

      for pairing in &parameters.advertisement_pairings
      {
         if let Some(action) = self.apply_advertisement_pairing(*pairing)
         {
            actions.push(action);
         }
      }

      for pairing in &parameters.subscription_pairings
      {
         if let Some(action) = self.apply_subscription_pairing(*pairing)
         {
            actions.push(action);
         }
      }

      actions
   }

   pub fn apply_advertisement_pairing(
      &mut self,
      pairing: AdvertisementPairing,
   ) -> Option<ActivationAction>
   {
      let key = PairingKey::from_advertisement(&pairing);
      if pairing.activate
      {
         self.advertisements.insert(key, pairing);
         return Some(ActivationAction::RegisterAdvertiser(pairing));
      }

      self.advertisements.remove(&key)?;
      Some(ActivationAction::DeactivateAdvertiser(key))
   }

   pub fn apply_subscription_pairing(
      &mut self,
      pairing: SubscriptionPairing,
   ) -> Option<ActivationAction>
   {
      let key = PairingKey::from_subscription(&pairing);
      if pairing.activate
      {
         self.subscriptions.insert(key, pairing);
         return Some(ActivationAction::ConnectSubscriber(pairing));
      }

      self.subscriptions.remove(&key)?;
      Some(ActivationAction::DeactivateSubscriber(key))
   }
}

impl AegisStream
{
   pub fn with_session(session: AegisSession) -> Self
   {
      Self {
         session,
         pending_buffer: Vec::new(),
         inbound_buffer: Vec::new(),
         inbound_head: 0,
         inbound_queued_at_ns: VecDeque::new(),
      }
   }

   pub fn from_advertisement(pairing: &AdvertisementPairing) -> Self
   {
      Self::with_session(AegisSession::from_advertisement(pairing))
   }

   pub fn from_subscription(pairing: &SubscriptionPairing) -> Self
   {
      Self::with_session(AegisSession::from_subscription(pairing))
   }

   pub fn pending_buffer(&self) -> &[u8]
   {
      &self.pending_buffer
   }

   pub fn take_pending_buffer(&mut self) -> Vec<u8>
   {
      std::mem::take(&mut self.pending_buffer)
   }

   pub fn pending_inbound_queued_timestamps(&self) -> usize
   {
      self.inbound_queued_at_ns.len()
   }

   pub fn pop_inbound_queued_timestamp(&mut self) -> Option<i64>
   {
      self.inbound_queued_at_ns.pop_front()
   }

   pub fn reset(&mut self)
   {
      self.session = AegisSession::default();
      self.pending_buffer.clear();
      self.inbound_buffer.clear();
      self.inbound_head = 0;
      self.inbound_queued_at_ns.clear();
   }

   pub fn queue_encrypted(&mut self, plaintext: &[u8]) -> io::Result<()>
   {
      let mut frame = Vec::new();
      self.session.encrypt_into(plaintext, &mut frame)?;
      self.pending_buffer.extend_from_slice(&frame);
      Ok(())
   }

   pub fn build_tfo_data(&self, aux: &[u8]) -> Vec<u8>
   {
      self.session.build_tfo_data(aux)
   }

   pub fn pairing_hash(&self) -> u64
   {
      self.session.pairing_hash()
   }

   pub fn push_inbound(&mut self, bytes: &[u8]) -> io::Result<()>
   {
      if self.inbound_head == self.inbound_buffer.len()
      {
         self.inbound_buffer.clear();
         self.inbound_head = 0;
      }

      self.inbound_buffer.extend_from_slice(bytes);
      self.stamp_queued_inbound_messages()
   }

   pub fn next_inbound_message(&mut self) -> io::Result<Option<InboundMessage>>
   {
      let complete_size = match self.peek_complete_frame_size()?
      {
         Some(size) => size,
         None => return Ok(None),
      };

      let frame = &self.inbound_buffer[self.inbound_head..(self.inbound_head + complete_size)];
      let plaintext = self.session.decrypt(frame)?;
      self.inbound_head += complete_size;
      let queued_at_ns = self
         .pop_inbound_queued_timestamp()
         .unwrap_or_else(monotonic_now_ns);
      self.compact_inbound_if_needed();

      Ok(Some(InboundMessage {
         queued_at_ns,
         plaintext,
      }))
   }

   pub fn stamp_queued_inbound_messages(&mut self) -> io::Result<()>
   {
      let complete_messages = self.count_complete_frames()?;
      while self.inbound_queued_at_ns.len() > complete_messages
      {
         self.inbound_queued_at_ns.pop_front();
      }

      if complete_messages > self.inbound_queued_at_ns.len()
      {
         let queued_at_ns = monotonic_now_ns();
         for _ in self.inbound_queued_at_ns.len()..complete_messages
         {
            self.inbound_queued_at_ns.push_back(queued_at_ns);
         }
      }

      Ok(())
   }

   fn peek_complete_frame_size(&self) -> io::Result<Option<usize>>
   {
      let available = &self.inbound_buffer[self.inbound_head..];
      if available.len() < std::mem::size_of::<u32>()
      {
         return Ok(None);
      }

      let size = u32::from_le_bytes(
         available[..4]
            .try_into()
            .map_err(|_| protocol_error("Aegis inbound frame size is truncated"))?,
      );
      let size = usize::try_from(size)
         .map_err(|_| protocol_error("Aegis inbound frame size exceeds usize"))?;
      if size < AEGIS_MIN_FRAME_BYTES || size > AEGIS_MAX_FRAME_BYTES
      {
         return Err(protocol_error("Aegis inbound frame size is outside the supported range"));
      }

      if available.len() < size
      {
         return Ok(None);
      }

      decode_frame_header(&available[..size])?;
      Ok(Some(size))
   }

   fn count_complete_frames(&self) -> io::Result<usize>
   {
      let mut count = 0usize;
      let available = &self.inbound_buffer[self.inbound_head..];
      let mut offset = 0usize;

      while (available.len() - offset) >= std::mem::size_of::<u32>()
      {
         let size = u32::from_le_bytes(
            available[offset..(offset + 4)]
               .try_into()
               .map_err(|_| protocol_error("Aegis inbound frame size is truncated"))?,
         );
         let size = usize::try_from(size)
            .map_err(|_| protocol_error("Aegis inbound frame size exceeds usize"))?;
         if size < AEGIS_MIN_FRAME_BYTES || size > AEGIS_MAX_FRAME_BYTES
         {
            return Err(protocol_error("Aegis inbound frame size is outside the supported range"));
         }

         if (available.len() - offset) < size
         {
            break;
         }

         decode_frame_header(&available[offset..(offset + size)])?;
         offset += size;
         count += 1;
      }

      Ok(count)
   }

   fn compact_inbound_if_needed(&mut self)
   {
      if self.inbound_head == 0
      {
         return;
      }

      if self.inbound_head == self.inbound_buffer.len()
      {
         self.inbound_buffer.clear();
         self.inbound_head = 0;
         return;
      }

      if self.inbound_head < INBOUND_COMPACT_THRESHOLD &&
         (self.inbound_head * 2) < self.inbound_buffer.len()
      {
         return;
      }

      self.inbound_buffer.copy_within(self.inbound_head.., 0);
      self.inbound_buffer.truncate(self.inbound_buffer.len() - self.inbound_head);
      self.inbound_head = 0;
   }
}

fn monotonic_now_ns() -> i64
{
   static START: OnceLock<Instant> = OnceLock::new();
   let start = START.get_or_init(Instant::now);
   let elapsed_ns = start.elapsed().as_nanos();
   elapsed_ns.min(i64::MAX as u128) as i64
}

fn protocol_error(message: impl Into<String>) -> io::Error
{
   io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests
{
   use super::*;
   use crate::aegis::{AegisSession, ServiceRole};

   fn advertisement_pairing() -> AdvertisementPairing
   {
      AdvertisementPairing {
         secret: U128 { bytes: [0x31; 16] },
         address: U128 { bytes: [0x41; 16] },
         service: 0x5566_0000_0000_3003,
         application_id: 0x5566,
         activate: true,
      }
   }

   fn subscription_pairing() -> SubscriptionPairing
   {
      SubscriptionPairing {
         secret: U128 { bytes: [0x51; 16] },
         address: U128 { bytes: [0x61; 16] },
         service: 0x6677_0000_0000_4004,
         port: 8123,
         application_id: 0x6677,
         activate: true,
      }
   }

   #[test]
   fn pairing_book_emits_activation_actions()
   {
      let mut book = PairingBook::default();
      let advertisement = advertisement_pairing();
      let subscription = subscription_pairing();

      assert_eq!(
         book.apply_advertisement_pairing(advertisement),
         Some(ActivationAction::RegisterAdvertiser(advertisement)),
      );
      assert_eq!(
         book.apply_subscription_pairing(subscription),
         Some(ActivationAction::ConnectSubscriber(subscription)),
      );

      let mut removed_advertisement = advertisement;
      removed_advertisement.activate = false;
      let mut removed_subscription = subscription;
      removed_subscription.activate = false;

      assert_eq!(
         book.apply_advertisement_pairing(removed_advertisement),
         Some(ActivationAction::DeactivateAdvertiser(PairingKey::from_advertisement(&advertisement))),
      );
      assert_eq!(
         book.apply_subscription_pairing(removed_subscription),
         Some(ActivationAction::DeactivateSubscriber(PairingKey::from_subscription(&subscription))),
      );
   }

   #[test]
   fn opinionated_stream_roundtrips_and_tracks_timestamps()
   {
      let session = AegisSession {
         secret: U128 { bytes: [0x71; 16] },
         service: 0x7788_0000_0000_5005,
         role: ServiceRole::Subscriber,
      };
      let mut advertiser = AegisStream::with_session(session);
      let mut subscriber = AegisStream::with_session(session);

      advertiser.queue_encrypted(b"frame-one").unwrap();
      advertiser.queue_encrypted(b"frame-two").unwrap();
      let outbound = advertiser.take_pending_buffer();

      subscriber.push_inbound(&outbound[..32]).unwrap();
      assert_eq!(subscriber.pending_inbound_queued_timestamps(), 0);
      subscriber.push_inbound(&outbound[32..]).unwrap();
      assert_eq!(subscriber.pending_inbound_queued_timestamps(), 2);

      let first = subscriber.next_inbound_message().unwrap().unwrap();
      let second = subscriber.next_inbound_message().unwrap().unwrap();
      assert_eq!(first.plaintext, b"frame-one");
      assert_eq!(second.plaintext, b"frame-two");
      assert!(second.queued_at_ns >= first.queued_at_ns);
      assert!(subscriber.next_inbound_message().unwrap().is_none());
   }

   #[test]
   fn seed_from_parameters_drives_activation_flow()
   {
      let advertisement = advertisement_pairing();
      let subscription = subscription_pairing();
      let parameters = ContainerParameters {
         advertisement_pairings: vec![advertisement],
         subscription_pairings: vec![subscription],
         ..ContainerParameters::default()
      };

      let mut book = PairingBook::default();
      let actions = book.seed_from_parameters(&parameters);
      assert_eq!(
         actions,
         vec![
            ActivationAction::RegisterAdvertiser(advertisement),
            ActivationAction::ConnectSubscriber(subscription),
         ],
      );
   }
}
