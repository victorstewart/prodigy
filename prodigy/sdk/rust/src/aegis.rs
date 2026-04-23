// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0

use std::io;

use aegis::aegis128l::Aegis128L;
use getrandom::fill as fill_random;
use gxhash::gxhash64;

use crate::{AdvertisementPairing, SubscriptionPairing, U128};

pub const AEGIS_ALIGNMENT: usize = 16;
pub const AEGIS_HEADER_BYTES: usize = 24;
pub const AEGIS_MAX_FRAME_BYTES: usize = 2 * 1024 * 1024;
pub const AEGIS_MIN_FRAME_BYTES: usize = 48;
pub const AEGIS_NONCE_BYTES: usize = 16;
pub const AEGIS_PAIRING_HASH_SEED: i64 = 0x4d59_5df4_d0f3_3173;
pub const AEGIS_TAG_BYTES: usize = 16;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ServiceRole
{
   #[default]
   None,
   Advertiser,
   Subscriber,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AegisFrameHeader
{
   pub size: u32,
   pub nonce: [u8; AEGIS_NONCE_BYTES],
   pub encrypted_data_size: u32,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AegisSession
{
   pub secret: U128,
   pub service: u64,
   pub role: ServiceRole,
}

impl AegisSession
{
   pub fn from_advertisement(pairing: &AdvertisementPairing) -> Self
   {
      Self {
         secret: pairing.secret,
         service: pairing.service,
         role: ServiceRole::Advertiser,
      }
   }

   pub fn from_subscription(pairing: &SubscriptionPairing) -> Self
   {
      Self {
         secret: pairing.secret,
         service: pairing.service,
         role: ServiceRole::Subscriber,
      }
   }

   pub fn pairing_hash(&self) -> u64
   {
      pairing_hash(&self.secret, self.service)
   }

   pub fn build_tfo_data(&self, aux: &[u8]) -> Vec<u8>
   {
      let mut tfo_data = Vec::with_capacity(std::mem::size_of::<u64>() + aux.len());
      self.build_tfo_data_into(aux, &mut tfo_data);
      tfo_data
   }

   pub fn build_tfo_data_into(&self, aux: &[u8], out: &mut Vec<u8>)
   {
      out.clear();
      out.reserve(std::mem::size_of::<u64>() + aux.len());
      out.extend_from_slice(&self.pairing_hash().to_le_bytes());
      out.extend_from_slice(aux);
   }

   pub fn encrypt(&self, plaintext: &[u8]) -> io::Result<Vec<u8>>
   {
      let mut frame = Vec::new();
      self.encrypt_into(plaintext, &mut frame)?;
      Ok(frame)
   }

   pub fn encrypt_into(&self, plaintext: &[u8], out: &mut Vec<u8>) -> io::Result<[u8; AEGIS_NONCE_BYTES]>
   {
      let mut nonce = [0u8; AEGIS_NONCE_BYTES];
      fill_random(&mut nonce)
         .map_err(|error| io::Error::new(io::ErrorKind::Other, format!("nonce generation failed: {error}")))?;
      self.encrypt_with_nonce_into(plaintext, nonce, out)?;
      Ok(nonce)
   }

   pub fn encrypt_with_nonce(&self, plaintext: &[u8], nonce: [u8; AEGIS_NONCE_BYTES]) -> io::Result<Vec<u8>>
   {
      let mut frame = Vec::new();
      self.encrypt_with_nonce_into(plaintext, nonce, &mut frame)?;
      Ok(frame)
   }

   pub fn encrypt_with_nonce_into(
      &self,
      plaintext: &[u8],
      nonce: [u8; AEGIS_NONCE_BYTES],
      out: &mut Vec<u8>,
   ) -> io::Result<()>
   {
      let encrypted_data_size = plaintext
         .len()
         .checked_add(AEGIS_TAG_BYTES)
         .ok_or_else(|| protocol_error("Aegis plaintext length overflows frame size"))?;
      let message_size = round_up_to_alignment(
         AEGIS_HEADER_BYTES
            .checked_add(encrypted_data_size)
            .ok_or_else(|| protocol_error("Aegis frame size overflows"))?,
      );
      validate_message_size(message_size)?;

      let message_size_u32 = u32::try_from(message_size)
         .map_err(|_| protocol_error("Aegis message size exceeds wire limit"))?;
      let encrypted_data_size_u32 = u32::try_from(encrypted_data_size)
         .map_err(|_| protocol_error("Aegis encrypted payload exceeds wire limit"))?;

      out.clear();
      out.reserve(message_size);
      out.extend_from_slice(&message_size_u32.to_le_bytes());
      out.extend_from_slice(&nonce);
      out.extend_from_slice(&encrypted_data_size_u32.to_le_bytes());

      let ciphertext_offset = out.len();
      out.extend_from_slice(plaintext);
      let tag = Aegis128L::<AEGIS_TAG_BYTES>::new(&self.secret.bytes, &nonce)
         .encrypt_in_place(&mut out[ciphertext_offset..], &message_size_u32.to_le_bytes());
      out.extend_from_slice(&tag);
      out.resize(message_size, 0);
      Ok(())
   }

   pub fn decrypt(&self, frame: &[u8]) -> io::Result<Vec<u8>>
   {
      let mut plaintext = Vec::new();
      self.decrypt_into(frame, &mut plaintext)?;
      Ok(plaintext)
   }

   pub fn decrypt_into(&self, frame: &[u8], plaintext: &mut Vec<u8>) -> io::Result<AegisFrameHeader>
   {
      let header = decode_frame_header(frame)?;
      let encrypted_data_size = usize::try_from(header.encrypted_data_size)
         .map_err(|_| protocol_error("Aegis encrypted payload exceeds usize"))?;
      let ciphertext_size = encrypted_data_size - AEGIS_TAG_BYTES;
      let ciphertext_offset = AEGIS_HEADER_BYTES;
      let tag_offset = ciphertext_offset + ciphertext_size;
      let tag: [u8; AEGIS_TAG_BYTES] = frame[tag_offset..(tag_offset + AEGIS_TAG_BYTES)]
         .try_into()
         .map_err(|_| protocol_error("Aegis tag is truncated"))?;

      plaintext.clear();
      plaintext.reserve(ciphertext_size);
      plaintext.extend_from_slice(&frame[ciphertext_offset..tag_offset]);

      Aegis128L::<AEGIS_TAG_BYTES>::new(&self.secret.bytes, &header.nonce)
         .decrypt_in_place(plaintext, &tag, &header.size.to_le_bytes())
         .map_err(|_| protocol_error("Aegis authentication failed"))?;

      Ok(header)
   }
}

pub fn pairing_hash(secret: &U128, service: u64) -> u64
{
   let mut input = [0u8; 24];
   input[..16].copy_from_slice(&secret.bytes);
   input[16..].copy_from_slice(&service.to_le_bytes());
   gxhash64(&input, AEGIS_PAIRING_HASH_SEED)
}

pub fn decode_frame_header(frame: &[u8]) -> io::Result<AegisFrameHeader>
{
   if frame.len() < AEGIS_HEADER_BYTES
   {
      return Err(protocol_error("Aegis frame is truncated"));
   }

   let size = u32::from_le_bytes(
      frame[..4]
         .try_into()
         .map_err(|_| protocol_error("Aegis frame size field is truncated"))?,
   );
   let size_usize = usize::try_from(size)
      .map_err(|_| protocol_error("Aegis frame size exceeds usize"))?;
   validate_message_size(size_usize)?;

   if frame.len() != size_usize
   {
      return Err(protocol_error("Aegis frame byte length does not match declared size"));
   }

   let mut nonce = [0u8; AEGIS_NONCE_BYTES];
   nonce.copy_from_slice(&frame[4..20]);

   let encrypted_data_size = u32::from_le_bytes(
      frame[20..24]
         .try_into()
         .map_err(|_| protocol_error("Aegis encrypted payload size field is truncated"))?,
   );
   let encrypted_data_size_usize = usize::try_from(encrypted_data_size)
      .map_err(|_| protocol_error("Aegis encrypted payload size exceeds usize"))?;
   if encrypted_data_size_usize < AEGIS_TAG_BYTES
   {
      return Err(protocol_error("Aegis encrypted payload is smaller than the authentication tag"));
   }

   let max_encrypted_data_size = size_usize - AEGIS_HEADER_BYTES;
   if encrypted_data_size_usize > max_encrypted_data_size
   {
      return Err(protocol_error("Aegis encrypted payload exceeds the declared frame size"));
   }

   Ok(AegisFrameHeader {
      size,
      nonce,
      encrypted_data_size,
   })
}

fn round_up_to_alignment(size: usize) -> usize
{
   (size + (AEGIS_ALIGNMENT - 1)) & !(AEGIS_ALIGNMENT - 1)
}

fn validate_message_size(message_size: usize) -> io::Result<()>
{
   if message_size < AEGIS_MIN_FRAME_BYTES
   {
      return Err(protocol_error("Aegis frame is smaller than the minimum supported size"));
   }

   if message_size > AEGIS_MAX_FRAME_BYTES
   {
      return Err(protocol_error("Aegis frame exceeds the maximum supported size"));
   }

   if message_size % AEGIS_ALIGNMENT != 0
   {
      return Err(protocol_error("Aegis frame is not aligned to 16 bytes"));
   }

   Ok(())
}

fn protocol_error(message: impl Into<String>) -> io::Error
{
   io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests
{
   use super::*;

   const FIXTURE_AEGIS_FRAME: &[u8] = include_bytes!("../../fixtures/aegis.frame.demo.bin");
   const FIXTURE_AEGIS_HASH: &[u8] = include_bytes!("../../fixtures/aegis.hash.demo.bin");
   const FIXTURE_AEGIS_TFO: &[u8] = include_bytes!("../../fixtures/aegis.tfo.demo.bin");
   const FIXTURE_PLAINTEXT: &[u8] = b"frame-one";
   const FIXTURE_AUX: &[u8] = b"mesh-aegis";
   const FIXTURE_NONCE: [u8; AEGIS_NONCE_BYTES] = [
      0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e,
      0x8f,
   ];

   fn demo_session() -> AegisSession
   {
      AegisSession {
         secret: U128 {
            bytes: [
               0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
               0x1e, 0x1f,
            ],
         },
         service: 0x2233_0000_0000_1001,
         role: ServiceRole::Subscriber,
      }
   }

   #[test]
   fn pairing_hash_and_tfo_fixture_match()
   {
      let session = demo_session();
      assert_eq!(session.pairing_hash().to_le_bytes().as_slice(), FIXTURE_AEGIS_HASH);
      assert_eq!(session.build_tfo_data(FIXTURE_AUX), FIXTURE_AEGIS_TFO);
   }

   #[test]
   fn encrypt_decrypt_and_layout_match_fixture()
   {
      let session = demo_session();
      let frame = session
         .encrypt_with_nonce(FIXTURE_PLAINTEXT, FIXTURE_NONCE)
         .unwrap();
      assert_eq!(frame, FIXTURE_AEGIS_FRAME);

      let header = decode_frame_header(&frame).unwrap();
      assert_eq!(usize::try_from(header.size).unwrap(), frame.len());
      assert_eq!(header.encrypted_data_size, (FIXTURE_PLAINTEXT.len() + AEGIS_TAG_BYTES) as u32);

      let plaintext = session.decrypt(FIXTURE_AEGIS_FRAME).unwrap();
      assert_eq!(plaintext, FIXTURE_PLAINTEXT);
   }

   #[test]
   fn malformed_frame_fails_closed()
   {
      let session = demo_session();
      let mut frame = session
         .encrypt_with_nonce(FIXTURE_PLAINTEXT, FIXTURE_NONCE)
         .unwrap();
      let invalid_encrypted_data_size = u32::try_from(frame.len()).unwrap();
      frame[20..24].copy_from_slice(&invalid_encrypted_data_size.to_le_bytes());
      assert!(session.decrypt(&frame).is_err());
   }
}
