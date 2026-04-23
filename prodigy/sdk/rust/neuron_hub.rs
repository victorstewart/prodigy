// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::env;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;

pub const SDK_VERSION: &str = "1.0.0";
pub const WIRE_SERIES: &str = "WIRE_V1";
pub const WIRE_PROTOCOL_VERSION: u32 = 1;

const CONTAINER_PARAMETERS_MAGIC: &[u8; 8] = b"PRDPAR01";
const CREDENTIAL_BUNDLE_MAGIC: &[u8; 8] = b"PRDBUN01";
const CREDENTIAL_DELTA_MAGIC: &[u8; 8] = b"PRDDEL01";
const FRAME_HEADER_SIZE: usize = 8;
const FRAME_ALIGNMENT: usize = 16;

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct U128
{
   pub bytes: [u8; 16],
}

impl U128
{
   fn decode(reader: &mut Reader<'_>) -> io::Result<Self>
   {
      let mut bytes = [0u8; 16];
      bytes.copy_from_slice(reader.raw(16)?);
      Ok(Self { bytes })
   }

   fn encode(&self, writer: &mut Writer)
   {
      writer.raw(&self.bytes);
   }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct IpAddress
{
   pub bytes: [u8; 16],
   pub is_ipv6: bool,
}

impl IpAddress
{
   fn decode(reader: &mut Reader<'_>) -> io::Result<Self>
   {
      let mut bytes = [0u8; 16];
      bytes.copy_from_slice(reader.raw(16)?);
      Ok(Self {
         bytes,
         is_ipv6: reader.boolean()?,
      })
   }

   fn encode(&self, writer: &mut Writer)
   {
      writer.raw(&self.bytes);
      writer.boolean(self.is_ipv6);
   }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct IpPrefix
{
   pub address: IpAddress,
   pub cidr: u8,
}

impl IpPrefix
{
   fn decode(reader: &mut Reader<'_>) -> io::Result<Self>
   {
      Ok(Self {
         address: IpAddress::decode(reader)?,
         cidr: reader.u8()?,
      })
   }

   fn encode(&self, writer: &mut Writer)
   {
      self.address.encode(writer);
      writer.u8(self.cidr);
   }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TlsIdentity
{
   pub name: String,
   pub generation: u64,
   pub not_before_ms: i64,
   pub not_after_ms: i64,
   pub cert_pem: String,
   pub key_pem: String,
   pub chain_pem: String,
   pub dns_sans: Vec<String>,
   pub ip_sans: Vec<IpAddress>,
   pub tags: Vec<String>,
}

impl TlsIdentity
{
   fn decode_fields(reader: &mut Reader<'_>) -> io::Result<Self>
   {
      Ok(Self {
         name: reader.string()?,
         generation: reader.u64()?,
         not_before_ms: reader.i64()?,
         not_after_ms: reader.i64()?,
         cert_pem: reader.string()?,
         key_pem: reader.string()?,
         chain_pem: reader.string()?,
         dns_sans: decode_string_vec(reader)?,
         ip_sans: decode_vec(reader, IpAddress::decode)?,
         tags: decode_string_vec(reader)?,
      })
   }

   fn encode_fields(&self, writer: &mut Writer) -> io::Result<()>
   {
      writer.string(&self.name)?;
      writer.u64(self.generation);
      writer.i64(self.not_before_ms);
      writer.i64(self.not_after_ms);
      writer.string(&self.cert_pem)?;
      writer.string(&self.key_pem)?;
      writer.string(&self.chain_pem)?;
      encode_string_vec(writer, &self.dns_sans)?;
      encode_vec(writer, &self.ip_sans, |item, inner| {
         item.encode(inner);
         Ok(())
      })?;
      encode_string_vec(writer, &self.tags)?;
      Ok(())
   }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ApiCredential
{
   pub name: String,
   pub provider: String,
   pub generation: u64,
   pub expires_at_ms: i64,
   pub active_from_ms: i64,
   pub sunset_at_ms: i64,
   pub material: String,
   pub metadata: BTreeMap<String, String>,
}

impl ApiCredential
{
   fn decode_fields(reader: &mut Reader<'_>) -> io::Result<Self>
   {
      let name = reader.string()?;
      let provider = reader.string()?;
      let generation = reader.u64()?;
      let expires_at_ms = reader.i64()?;
      let active_from_ms = reader.i64()?;
      let sunset_at_ms = reader.i64()?;
      let material = reader.string()?;

      let metadata_count = reader.u32()? as usize;
      let mut metadata = BTreeMap::new();
      for _ in 0..metadata_count
      {
         metadata.insert(reader.string()?, reader.string()?);
      }

      Ok(Self {
         name,
         provider,
         generation,
         expires_at_ms,
         active_from_ms,
         sunset_at_ms,
         material,
         metadata,
      })
   }

   fn encode_fields(&self, writer: &mut Writer) -> io::Result<()>
   {
      writer.string(&self.name)?;
      writer.string(&self.provider)?;
      writer.u64(self.generation);
      writer.i64(self.expires_at_ms);
      writer.i64(self.active_from_ms);
      writer.i64(self.sunset_at_ms);
      writer.string(&self.material)?;
      writer.u32(checked_u32(self.metadata.len())?);
      for (key, value) in &self.metadata
      {
         writer.string(key)?;
         writer.string(value)?;
      }

      Ok(())
   }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CredentialBundle
{
   pub tls_identities: Vec<TlsIdentity>,
   pub api_credentials: Vec<ApiCredential>,
   pub bundle_generation: u64,
}

impl CredentialBundle
{
   pub fn decode(bytes: &[u8]) -> io::Result<Self>
   {
      let mut reader = Reader::new(bytes);
      reader.header(CREDENTIAL_BUNDLE_MAGIC)?;

      let bundle = Self {
         tls_identities: decode_vec(&mut reader, TlsIdentity::decode_fields)?,
         api_credentials: decode_vec(&mut reader, ApiCredential::decode_fields)?,
         bundle_generation: reader.u64()?,
      };

      reader.finish()?;
      Ok(bundle)
   }

   pub fn encode(&self) -> io::Result<Vec<u8>>
   {
      let mut writer = Writer::new();
      writer.header(CREDENTIAL_BUNDLE_MAGIC);
      encode_vec(&mut writer, &self.tls_identities, TlsIdentity::encode_fields)?;
      encode_vec(&mut writer, &self.api_credentials, ApiCredential::encode_fields)?;
      writer.u64(self.bundle_generation);
      Ok(writer.finish())
   }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CredentialDelta
{
   pub bundle_generation: u64,
   pub updated_tls: Vec<TlsIdentity>,
   pub removed_tls_names: Vec<String>,
   pub updated_api: Vec<ApiCredential>,
   pub removed_api_names: Vec<String>,
   pub reason: String,
}

impl CredentialDelta
{
   pub fn decode(bytes: &[u8]) -> io::Result<Self>
   {
      let mut reader = Reader::new(bytes);
      reader.header(CREDENTIAL_DELTA_MAGIC)?;

      let delta = Self {
         bundle_generation: reader.u64()?,
         updated_tls: decode_vec(&mut reader, TlsIdentity::decode_fields)?,
         removed_tls_names: decode_string_vec(&mut reader)?,
         updated_api: decode_vec(&mut reader, ApiCredential::decode_fields)?,
         removed_api_names: decode_string_vec(&mut reader)?,
         reason: reader.string()?,
      };

      reader.finish()?;
      Ok(delta)
   }

   pub fn encode(&self) -> io::Result<Vec<u8>>
   {
      let mut writer = Writer::new();
      writer.header(CREDENTIAL_DELTA_MAGIC);
      writer.u64(self.bundle_generation);
      encode_vec(&mut writer, &self.updated_tls, TlsIdentity::encode_fields)?;
      encode_string_vec(&mut writer, &self.removed_tls_names)?;
      encode_vec(&mut writer, &self.updated_api, ApiCredential::encode_fields)?;
      encode_string_vec(&mut writer, &self.removed_api_names)?;
      writer.string(&self.reason)?;
      Ok(writer.finish())
   }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AdvertisedPort
{
   pub service: u64,
   pub port: u16,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AdvertisementPairing
{
   pub secret: U128,
   pub address: U128,
   pub service: u64,
   pub application_id: u16,
   pub activate: bool,
}

impl AdvertisementPairing
{
   fn decode_payload(bytes: &[u8]) -> io::Result<Self>
   {
      let mut reader = Reader::new(bytes);
      let pairing = Self {
         secret: U128::decode(&mut reader)?,
         address: U128::decode(&mut reader)?,
         service: reader.u64()?,
         application_id: reader.u16()?,
         activate: reader.boolean()?,
      };

      reader.finish()?;
      Ok(pairing)
   }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SubscriptionPairing
{
   pub secret: U128,
   pub address: U128,
   pub service: u64,
   pub port: u16,
   pub application_id: u16,
   pub activate: bool,
}

impl SubscriptionPairing
{
   fn decode_payload(bytes: &[u8]) -> io::Result<Self>
   {
      let mut reader = Reader::new(bytes);
      let pairing = Self {
         secret: U128::decode(&mut reader)?,
         address: U128::decode(&mut reader)?,
         service: reader.u64()?,
         port: reader.u16()?,
         application_id: reader.u16()?,
         activate: reader.boolean()?,
      };

      reader.finish()?;
      Ok(pairing)
   }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ResourceDelta
{
   pub logical_cores: u16,
   pub memory_mb: u32,
   pub storage_mb: u32,
   pub is_downscale: bool,
   pub grace_seconds: u32,
}

impl ResourceDelta
{
   fn decode_payload(bytes: &[u8]) -> io::Result<Self>
   {
      let mut reader = Reader::new(bytes);
      let delta = Self {
         logical_cores: reader.u16()?,
         memory_mb: reader.u32()?,
         storage_mb: reader.u32()?,
         is_downscale: reader.boolean()?,
         grace_seconds: reader.u32()?,
      };

      reader.finish()?;
      Ok(delta)
   }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MetricPair
{
   pub key: u64,
   pub value: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ContainerParameters
{
   pub uuid: U128,
   pub memory_mb: u32,
   pub storage_mb: u32,
   pub logical_cores: u16,
   pub neuron_fd: i32,
   pub low_cpu: i32,
   pub high_cpu: i32,
   pub advertises: Vec<AdvertisedPort>,
   pub subscription_pairings: Vec<SubscriptionPairing>,
   pub advertisement_pairings: Vec<AdvertisementPairing>,
   pub private6: IpPrefix,
   pub just_crashed: bool,
   pub datacenter_unique_tag: u8,
   pub flags: Vec<u64>,
   pub credential_bundle: Option<CredentialBundle>,
}

impl ContainerParameters
{
   pub fn decode(bytes: &[u8]) -> io::Result<Self>
   {
      let mut reader = Reader::new(bytes);
      reader.header(CONTAINER_PARAMETERS_MAGIC)?;

      let uuid = U128::decode(&mut reader)?;
      let memory_mb = reader.u32()?;
      let storage_mb = reader.u32()?;
      let logical_cores = reader.u16()?;
      let neuron_fd = reader.i32()?;
      let low_cpu = reader.i32()?;
      let high_cpu = reader.i32()?;

      let advertises = decode_vec(&mut reader, |inner| {
         Ok(AdvertisedPort {
            service: inner.u64()?,
            port: inner.u16()?,
         })
      })?;

      let subscription_pairings = decode_vec(&mut reader, |inner| {
         Ok(SubscriptionPairing {
            secret: U128::decode(inner)?,
            address: U128::decode(inner)?,
            service: inner.u64()?,
            port: inner.u16()?,
            application_id: 0,
            activate: true,
         })
      })?;

      let advertisement_pairings = decode_vec(&mut reader, |inner| {
         Ok(AdvertisementPairing {
            secret: U128::decode(inner)?,
            address: U128::decode(inner)?,
            service: inner.u64()?,
            application_id: 0,
            activate: true,
         })
      })?;

      let private6 = IpPrefix::decode(&mut reader)?;
      let just_crashed = reader.boolean()?;
      let datacenter_unique_tag = reader.u8()?;
      let flags = decode_vec(&mut reader, |inner| inner.u64())?;
      let has_credential_bundle = reader.boolean()?;
      let credential_bundle = if has_credential_bundle
      {
         Some(CredentialBundle {
            tls_identities: decode_vec(&mut reader, TlsIdentity::decode_fields)?,
            api_credentials: decode_vec(&mut reader, ApiCredential::decode_fields)?,
            bundle_generation: reader.u64()?,
         })
      }
      else
      {
         None
      };

      reader.finish()?;
      Ok(Self {
         uuid,
         memory_mb,
         storage_mb,
         logical_cores,
         neuron_fd,
         low_cpu,
         high_cpu,
         advertises,
         subscription_pairings: subscription_pairings
            .into_iter()
            .map(|mut pairing| {
               pairing.application_id = u16::try_from(pairing.service >> 48).unwrap_or(0);
               pairing
            })
            .collect(),
         advertisement_pairings: advertisement_pairings
            .into_iter()
            .map(|mut pairing| {
               pairing.application_id = u16::try_from(pairing.service >> 48).unwrap_or(0);
               pairing
            })
            .collect(),
         private6,
         just_crashed,
         datacenter_unique_tag,
         flags,
         credential_bundle,
      })
   }

   pub fn encode(&self) -> io::Result<Vec<u8>>
   {
      let mut writer = Writer::new();
      writer.header(CONTAINER_PARAMETERS_MAGIC);
      self.uuid.encode(&mut writer);
      writer.u32(self.memory_mb);
      writer.u32(self.storage_mb);
      writer.u16(self.logical_cores);
      writer.i32(self.neuron_fd);
      writer.i32(self.low_cpu);
      writer.i32(self.high_cpu);

      encode_vec(&mut writer, &self.advertises, |item, inner| {
         inner.u64(item.service);
         inner.u16(item.port);
         Ok(())
      })?;

      encode_vec(&mut writer, &self.subscription_pairings, |item, inner| {
         item.secret.encode(inner);
         item.address.encode(inner);
         inner.u64(item.service);
         inner.u16(item.port);
         Ok(())
      })?;

      encode_vec(&mut writer, &self.advertisement_pairings, |item, inner| {
         item.secret.encode(inner);
         item.address.encode(inner);
         inner.u64(item.service);
         Ok(())
      })?;

      self.private6.encode(&mut writer);
      writer.boolean(self.just_crashed);
      writer.u8(self.datacenter_unique_tag);
      encode_vec(&mut writer, &self.flags, |item, inner| {
         inner.u64(*item);
         Ok(())
      })?;

      writer.boolean(self.credential_bundle.is_some());
      if let Some(bundle) = &self.credential_bundle
      {
         encode_vec(&mut writer, &bundle.tls_identities, TlsIdentity::encode_fields)?;
         encode_vec(&mut writer, &bundle.api_credentials, ApiCredential::encode_fields)?;
         writer.u64(bundle.bundle_generation);
      }

      Ok(writer.finish())
   }

   pub fn from_process() -> io::Result<Self>
   {
      if let Ok(fd_text) = env::var("PRODIGY_PARAMS_FD")
      {
         let fd = fd_text
            .parse::<RawFd>()
            .map_err(|_| invalid_data("invalid PRODIGY_PARAMS_FD"))?;
         let bytes = read_all_from_fd(fd)?;
         return Self::decode(&bytes);
      }

      if let Some(arg) = env::args_os().nth(1)
      {
         return Self::decode(arg.as_bytes());
      }

      Err(invalid_data("missing Prodigy startup parameters"))
   }
}

#[repr(u16)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContainerTopic
{
   None = 0,
   Ping = 1,
   Pong = 2,
   Stop = 3,
   AdvertisementPairing = 4,
   SubscriptionPairing = 5,
   Healthy = 6,
   Message = 7,
   ResourceDelta = 8,
   DatacenterUniqueTag = 9,
   Statistics = 10,
   ResourceDeltaAck = 11,
   CredentialsRefresh = 12,
}

impl ContainerTopic
{
   fn from_u16(value: u16) -> io::Result<Self>
   {
      match value
      {
         0 => Ok(Self::None),
         1 => Ok(Self::Ping),
         2 => Ok(Self::Pong),
         3 => Ok(Self::Stop),
         4 => Ok(Self::AdvertisementPairing),
         5 => Ok(Self::SubscriptionPairing),
         6 => Ok(Self::Healthy),
         7 => Ok(Self::Message),
         8 => Ok(Self::ResourceDelta),
         9 => Ok(Self::DatacenterUniqueTag),
         10 => Ok(Self::Statistics),
         11 => Ok(Self::ResourceDeltaAck),
         12 => Ok(Self::CredentialsRefresh),
         _ => Err(invalid_data(format!("unknown container topic {value}"))),
      }
   }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageFrame
{
   pub topic: ContainerTopic,
   pub payload: Vec<u8>,
}

#[derive(Default)]
pub struct FrameDecoder
{
   buffer: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct DefaultDispatch;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ControlPolicy
{
   pub resource_delta_ack: Option<bool>,
   pub credentials_refresh_ack: bool,
}

pub trait Dispatch: Sized
{
   fn begin_shutdown(&mut self, hub: &mut NeuronHub<Self>);

   fn end_of_dynamic_args(&mut self, _hub: &mut NeuronHub<Self>)
   {
   }

   fn advertisement_pairing(
      &mut self,
      _hub: &mut NeuronHub<Self>,
      _pairing: AdvertisementPairing)
   {
   }

   fn subscription_pairing(
      &mut self,
      _hub: &mut NeuronHub<Self>,
      _pairing: SubscriptionPairing)
   {
   }

   fn resource_delta(&mut self, _hub: &mut NeuronHub<Self>, _delta: ResourceDelta)
   {
   }

   fn credentials_refresh(
      &mut self,
      _hub: &mut NeuronHub<Self>,
      _delta: CredentialDelta)
   {
   }

   fn message_from_prodigy(&mut self, _hub: &mut NeuronHub<Self>, _payload: &[u8])
   {
   }
}

impl Dispatch for DefaultDispatch
{
   fn begin_shutdown(&mut self, _hub: &mut NeuronHub<Self>)
   {
   }
}

pub struct NeuronHub<D: Dispatch>
{
   stream: Option<File>,
   dispatch: Option<D>,
   control_policy: ControlPolicy,
   queued_outbound: Vec<MessageFrame>,
   shutdown_requested: bool,
   pub parameters: ContainerParameters,
}

impl<D: Dispatch> NeuronHub<D>
{
   pub fn new(parameters: ContainerParameters, dispatch: D) -> io::Result<Self>
   {
      if parameters.neuron_fd < 0
      {
         return Err(invalid_data("invalid neuron fd"));
      }

      let stream = unsafe { File::from_raw_fd(parameters.neuron_fd) };
      Ok(Self {
         stream: Some(stream),
         dispatch: Some(dispatch),
         control_policy: ControlPolicy::default(),
         queued_outbound: Vec::new(),
         shutdown_requested: false,
         parameters,
      })
   }

   pub fn new_without_transport(parameters: ContainerParameters, dispatch: D) -> io::Result<Self>
   {
      Self::new_borrowed_transport(parameters, dispatch)
   }

   pub fn new_borrowed_transport(parameters: ContainerParameters, dispatch: D) -> io::Result<Self>
   {
      Ok(Self {
         stream: None,
         dispatch: Some(dispatch),
         control_policy: ControlPolicy::default(),
         queued_outbound: Vec::new(),
         shutdown_requested: false,
         parameters,
      })
   }

   pub fn from_process(dispatch: D) -> io::Result<Self>
   {
      Self::new(ContainerParameters::from_process()?, dispatch)
   }

   pub fn from_process_without_transport(dispatch: D) -> io::Result<Self>
   {
      Self::from_process_borrowed_transport(dispatch)
   }

   pub fn from_process_borrowed_transport(dispatch: D) -> io::Result<Self>
   {
      Self::new_borrowed_transport(ContainerParameters::from_process()?, dispatch)
   }

   pub fn raw_fd(&self) -> RawFd
   {
      self.stream
         .as_ref()
         .map(|stream| stream.as_raw_fd())
         .unwrap_or(self.parameters.neuron_fd)
   }

   pub fn run_once(&mut self) -> io::Result<bool>
   {
      let stream = self
         .stream
         .as_mut()
         .ok_or_else(|| invalid_data("hub has no owned transport"))?;
      let Some(frame) = read_frame(stream)? else {
         return Ok(false);
      };

      for outbound in self.handle_message_frame(&frame)?
      {
         self.send_message_frame(&outbound)?;
      }
      Ok(true)
   }

   pub fn run_forever(&mut self) -> io::Result<()>
   {
      while self.run_once()?
      {
      }

      Ok(())
   }

   pub fn handle_decoded_frame(&mut self, frame: &MessageFrame) -> io::Result<Vec<Vec<u8>>>
   {
      let mut outbound = Vec::new();
      for frame in self.handle_message_frame(frame)?
      {
         outbound.push(build_message_frame(frame.topic, &frame.payload)?);
      }

      Ok(outbound)
   }

   pub fn handle_bytes(&mut self, decoder: &mut FrameDecoder, bytes: &[u8]) -> io::Result<Vec<Vec<u8>>>
   {
      let mut outbound = Vec::new();
      for frame in decoder.feed(bytes)?
      {
         outbound.extend(self.handle_decoded_frame(&frame)?);
      }

      Ok(outbound)
   }

   pub fn signal_ready(&mut self) -> io::Result<()>
   {
      self.send_empty(ContainerTopic::Healthy)
   }

   pub fn with_control_policy(mut self, control_policy: ControlPolicy) -> Self
   {
      self.control_policy = control_policy;
      self
   }

   pub fn with_resource_delta_ack(mut self, accepted: bool) -> Self
   {
      self.control_policy.resource_delta_ack = Some(accepted);
      self
   }

   pub fn with_credentials_refresh_ack(mut self) -> Self
   {
      self.control_policy.credentials_refresh_ack = true;
      self
   }

   pub fn shutdown_requested(&self) -> bool
   {
      self.shutdown_requested
   }

   pub fn publish_statistic(&mut self, metric: MetricPair) -> io::Result<()>
   {
      self.publish_statistics(&[metric])
   }

   pub fn publish_statistics(&mut self, metrics: &[MetricPair]) -> io::Result<()>
   {
      self.send_frame(ContainerTopic::Statistics, &encode_metric_pairs(metrics))
   }

   pub fn acknowledge_resource_delta(&mut self, accepted: bool) -> io::Result<()>
   {
      self.send_frame(ContainerTopic::ResourceDeltaAck, &[u8::from(accepted)])
   }

   pub fn acknowledge_credentials_refresh(&mut self) -> io::Result<()>
   {
      self.send_empty(ContainerTopic::CredentialsRefresh)
   }

   pub fn queue_ready(&mut self)
   {
      self.queue_empty(ContainerTopic::Healthy);
   }

   pub fn queue_statistics(&mut self, metrics: &[MetricPair])
   {
      self.queue_message_frame(MessageFrame {
         topic: ContainerTopic::Statistics,
         payload: encode_metric_pairs(metrics),
      });
   }

   pub fn queue_resource_delta_ack(&mut self, accepted: bool)
   {
      self.queue_message_frame(MessageFrame {
         topic: ContainerTopic::ResourceDeltaAck,
         payload: vec![u8::from(accepted)],
      });
   }

   pub fn queue_credentials_refresh_ack(&mut self)
   {
      self.queue_empty(ContainerTopic::CredentialsRefresh);
   }

   pub fn queue_message_frame(&mut self, frame: MessageFrame)
   {
      self.queued_outbound.push(frame);
   }

   pub fn drain_outbound(&mut self) -> Vec<MessageFrame>
   {
      self.drain_queued_outbound()
   }

   pub fn drain_outbound_bytes(&mut self) -> io::Result<Vec<Vec<u8>>>
   {
      encode_message_frames(&self.drain_queued_outbound())
   }

   pub fn handle_message_frame(&mut self, frame: &MessageFrame) -> io::Result<Vec<MessageFrame>>
   {
      match frame.topic
      {
         ContainerTopic::None =>
         {
            self.with_dispatch(|dispatch, hub| dispatch.end_of_dynamic_args(hub));
         }
         ContainerTopic::Ping =>
         {
            self.queue_empty(ContainerTopic::Ping);
         }
         ContainerTopic::Pong | ContainerTopic::Healthy | ContainerTopic::Statistics | ContainerTopic::ResourceDeltaAck =>
         {
         }
         ContainerTopic::Stop =>
         {
            self.shutdown_requested = true;
            self.with_dispatch(|dispatch, hub| dispatch.begin_shutdown(hub));
         }
         ContainerTopic::AdvertisementPairing =>
         {
            let pairing = AdvertisementPairing::decode_payload(&frame.payload)?;
            self.with_dispatch(|dispatch, hub| dispatch.advertisement_pairing(hub, pairing));
         }
         ContainerTopic::SubscriptionPairing =>
         {
            let pairing = SubscriptionPairing::decode_payload(&frame.payload)?;
            self.with_dispatch(|dispatch, hub| dispatch.subscription_pairing(hub, pairing));
         }
         ContainerTopic::Message =>
         {
            self.with_dispatch(|dispatch, hub| dispatch.message_from_prodigy(hub, &frame.payload));
         }
         ContainerTopic::ResourceDelta =>
         {
            let delta = ResourceDelta::decode_payload(&frame.payload)?;
            self.with_dispatch(|dispatch, hub| dispatch.resource_delta(hub, delta));
            if let Some(accepted) = self.control_policy.resource_delta_ack
            {
               self.queue_resource_delta_ack(accepted);
            }
         }
         ContainerTopic::DatacenterUniqueTag =>
         {
            let mut reader = Reader::new(&frame.payload);
            self.parameters.datacenter_unique_tag = reader.u8()?;
            reader.finish()?;
         }
         ContainerTopic::CredentialsRefresh =>
         {
            if !frame.payload.is_empty()
            {
               let delta = CredentialDelta::decode(&frame.payload)?;
               self.with_dispatch(|dispatch, hub| dispatch.credentials_refresh(hub, delta));
               if self.control_policy.credentials_refresh_ack
               {
                  self.queue_credentials_refresh_ack();
               }
            }
         }
      }

      Ok(self.drain_queued_outbound())
   }

   fn with_dispatch<T>(&mut self, f: impl FnOnce(&mut D, &mut Self) -> T) -> T
   {
      let mut dispatch = self.dispatch.take().expect("missing dispatch");
      let result = f(&mut dispatch, self);
      self.dispatch = Some(dispatch);
      result
   }

   fn send_empty(&mut self, topic: ContainerTopic) -> io::Result<()>
   {
      self.send_frame(topic, &[])
   }

   fn queue_empty(&mut self, topic: ContainerTopic)
   {
      self.queue_message_frame(MessageFrame {
         topic,
         payload: Vec::new(),
      });
   }

   fn drain_queued_outbound(&mut self) -> Vec<MessageFrame>
   {
      std::mem::take(&mut self.queued_outbound)
   }

   pub fn send_message_frame(&mut self, frame: &MessageFrame) -> io::Result<()>
   {
      self.send_frame(frame.topic, &frame.payload)
   }

   fn send_frame(&mut self, topic: ContainerTopic, payload: &[u8]) -> io::Result<()>
   {
      let stream = self
         .stream
         .as_mut()
         .ok_or_else(|| invalid_data("hub has no owned transport"))?;
      let encoded = build_message_frame(topic, payload)?;
      stream.write_all(&encoded)
   }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FrameHeader
{
   size: u32,
   topic: ContainerTopic,
   padding: u8,
   header_size: u8,
}

impl FrameHeader
{
   fn decode(bytes: &[u8; FRAME_HEADER_SIZE]) -> io::Result<Self>
   {
      let size = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
      let topic = ContainerTopic::from_u16(u16::from_le_bytes(bytes[4..6].try_into().unwrap()))?;
      let padding = bytes[6];
      let header_size = bytes[7];

      if header_size as usize != FRAME_HEADER_SIZE
      {
         return Err(invalid_data("invalid frame header size"));
      }

      if size < FRAME_HEADER_SIZE as u32
      {
         return Err(invalid_data("invalid frame size"));
      }

      if padding as usize >= FRAME_ALIGNMENT
      {
         return Err(invalid_data("invalid frame padding"));
      }

      if usize::try_from(size).map_err(|_| invalid_data("frame too large"))? % FRAME_ALIGNMENT != 0
      {
         return Err(invalid_data("frame size must be 16-byte aligned"));
      }

      if padding as u32 > size - FRAME_HEADER_SIZE as u32
      {
         return Err(invalid_data("frame padding exceeds payload"));
      }

      Ok(Self {
         size,
         topic,
         padding,
         header_size,
      })
   }
}

pub fn build_message_frame(topic: ContainerTopic, payload: &[u8]) -> io::Result<Vec<u8>>
{
   let message_bytes = FRAME_HEADER_SIZE
      .checked_add(payload.len())
      .ok_or_else(|| invalid_data("frame too large"))?;
   let padding = (FRAME_ALIGNMENT - (message_bytes % FRAME_ALIGNMENT)) % FRAME_ALIGNMENT;
   let total_size = message_bytes
      .checked_add(padding)
      .ok_or_else(|| invalid_data("frame too large"))?;
   let total_size_u32 = checked_u32(total_size)?;

   let mut frame = Vec::with_capacity(total_size);
   frame.extend_from_slice(&total_size_u32.to_le_bytes());
   frame.extend_from_slice(&(topic as u16).to_le_bytes());
   frame.push(padding as u8);
   frame.push(FRAME_HEADER_SIZE as u8);
   frame.extend_from_slice(payload);
   frame.resize(total_size, 0);
   Ok(frame)
}

pub fn build_ready_frame() -> io::Result<Vec<u8>>
{
   build_message_frame(ContainerTopic::Healthy, &[])
}

pub fn build_statistics_frame(metrics: &[MetricPair]) -> io::Result<Vec<u8>>
{
   build_message_frame(ContainerTopic::Statistics, &encode_metric_pairs(metrics))
}

pub fn build_resource_delta_ack_frame(accepted: bool) -> io::Result<Vec<u8>>
{
   build_message_frame(ContainerTopic::ResourceDeltaAck, &[u8::from(accepted)])
}

pub fn build_credentials_refresh_ack_frame() -> io::Result<Vec<u8>>
{
   build_message_frame(ContainerTopic::CredentialsRefresh, &[])
}

pub fn encode_message_frames(frames: &[MessageFrame]) -> io::Result<Vec<Vec<u8>>>
{
   let mut encoded = Vec::with_capacity(frames.len());
   for frame in frames
   {
      encoded.push(build_message_frame(frame.topic, &frame.payload)?);
   }

   Ok(encoded)
}

pub fn parse_message_frame(bytes: &[u8]) -> io::Result<MessageFrame>
{
   if bytes.len() < FRAME_HEADER_SIZE
   {
      return Err(invalid_data("truncated frame"));
   }

   let header = FrameHeader::decode(bytes[0..FRAME_HEADER_SIZE].try_into().unwrap())?;
   let remaining = usize::try_from(header.size).map_err(|_| invalid_data("frame too large"))?;
   if remaining != bytes.len()
   {
      return Err(invalid_data("frame size does not match buffer length"));
   }

   let payload_len = remaining - FRAME_HEADER_SIZE - header.padding as usize;
   Ok(MessageFrame {
      topic: header.topic,
      payload: bytes[FRAME_HEADER_SIZE..FRAME_HEADER_SIZE + payload_len].to_vec(),
   })
}

impl FrameDecoder
{
   pub fn feed(&mut self, bytes: &[u8]) -> io::Result<Vec<MessageFrame>>
   {
      self.buffer.extend_from_slice(bytes);
      let mut frames = Vec::new();
      while let Some((frame, consumed)) = try_extract_frame(&self.buffer)?
      {
         frames.push(frame);
         self.buffer.drain(0..consumed);
      }

      Ok(frames)
   }
}

fn read_frame(reader: &mut impl Read) -> io::Result<Option<MessageFrame>>
{
   let mut header_bytes = [0u8; FRAME_HEADER_SIZE];
   if !read_exact_or_eof(reader, &mut header_bytes)?
   {
      return Ok(None);
   }

   let header = FrameHeader::decode(&header_bytes)?;
   let remaining = usize::try_from(header.size).map_err(|_| invalid_data("frame too large"))? - FRAME_HEADER_SIZE;
   let payload_len = remaining - header.padding as usize;

   let mut payload_and_padding = vec![0u8; remaining];
   reader.read_exact(&mut payload_and_padding)?;
   payload_and_padding.truncate(payload_len);
   Ok(Some(MessageFrame {
      topic: header.topic,
      payload: payload_and_padding,
   }))
}

fn encode_metric_pairs(metrics: &[MetricPair]) -> Vec<u8>
{
   let mut writer = Writer::new();
   for metric in metrics
   {
      writer.u64(metric.key);
      writer.u64(metric.value);
   }
   writer.finish()
}

fn try_extract_frame(bytes: &[u8]) -> io::Result<Option<(MessageFrame, usize)>>
{
   if bytes.len() < FRAME_HEADER_SIZE
   {
      return Ok(None);
   }

   let header = FrameHeader::decode(bytes[0..FRAME_HEADER_SIZE].try_into().unwrap())?;
   let total_size = usize::try_from(header.size).map_err(|_| invalid_data("frame too large"))?;
   if total_size > bytes.len()
   {
      return Ok(None);
   }

   let frame = parse_message_frame(&bytes[..total_size])?;
   Ok(Some((frame, total_size)))
}

fn read_exact_or_eof(reader: &mut impl Read, buffer: &mut [u8]) -> io::Result<bool>
{
   let mut offset = 0usize;
   while offset < buffer.len()
   {
      match reader.read(&mut buffer[offset..])?
      {
         0 if offset == 0 => return Ok(false),
         0 => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected eof")),
         read => offset += read,
      }
   }

   Ok(true)
}

fn read_all_from_fd(fd: RawFd) -> io::Result<Vec<u8>>
{
   let mut file = unsafe { File::from_raw_fd(fd) };
   file.seek(SeekFrom::Start(0))?;
   let mut bytes = Vec::new();
   file.read_to_end(&mut bytes)?;
   Ok(bytes)
}

fn encode_vec<T>(
   writer: &mut Writer,
   items: &[T],
   encode_item: impl Fn(&T, &mut Writer) -> io::Result<()>)
   -> io::Result<()>
{
   writer.u32(checked_u32(items.len())?);
   for item in items
   {
      encode_item(item, writer)?;
   }

   Ok(())
}

fn decode_vec<T>(
   reader: &mut Reader<'_>,
   decode_item: impl Fn(&mut Reader<'_>) -> io::Result<T>)
   -> io::Result<Vec<T>>
{
   let count = reader.u32()? as usize;
   let mut items = Vec::with_capacity(count);
   for _ in 0..count
   {
      items.push(decode_item(reader)?);
   }

   Ok(items)
}

fn encode_string_vec(writer: &mut Writer, values: &[String]) -> io::Result<()>
{
   encode_vec(writer, values, |value, inner| inner.string(value))
}

fn decode_string_vec(reader: &mut Reader<'_>) -> io::Result<Vec<String>>
{
   decode_vec(reader, |inner| inner.string())
}

fn checked_u32(value: usize) -> io::Result<u32>
{
   u32::try_from(value).map_err(|_| invalid_data("value exceeds u32"))
}

fn invalid_data(message: impl Into<String>) -> io::Error
{
   io::Error::new(io::ErrorKind::InvalidData, message.into())
}

struct Reader<'a>
{
   bytes: &'a [u8],
   offset: usize,
}

impl<'a> Reader<'a>
{
   fn new(bytes: &'a [u8]) -> Self
   {
      Self { bytes, offset: 0 }
   }

   fn raw(&mut self, count: usize) -> io::Result<&'a [u8]>
   {
      let end = self.offset.checked_add(count).ok_or_else(|| invalid_data("overflow"))?;
      if end > self.bytes.len()
      {
         return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "truncated input"));
      }

      let slice = &self.bytes[self.offset..end];
      self.offset = end;
      Ok(slice)
   }

   fn header(&mut self, expected: &[u8; 8]) -> io::Result<()>
   {
      let found = self.raw(8)?;
      if found != expected
      {
         return Err(invalid_data("invalid wire magic"));
      }

      Ok(())
   }

   fn finish(&self) -> io::Result<()>
   {
      if self.offset == self.bytes.len()
      {
         Ok(())
      }
      else
      {
         Err(invalid_data("trailing bytes"))
      }
   }

   fn u8(&mut self) -> io::Result<u8>
   {
      Ok(self.raw(1)?[0])
   }

   fn boolean(&mut self) -> io::Result<bool>
   {
      match self.u8()?
      {
         0 => Ok(false),
         1 => Ok(true),
         value => Err(invalid_data(format!("invalid bool value {value}"))),
      }
   }

   fn u16(&mut self) -> io::Result<u16>
   {
      Ok(u16::from_le_bytes(self.raw(2)?.try_into().unwrap()))
   }

   fn u32(&mut self) -> io::Result<u32>
   {
      Ok(u32::from_le_bytes(self.raw(4)?.try_into().unwrap()))
   }

   fn i32(&mut self) -> io::Result<i32>
   {
      Ok(self.u32()? as i32)
   }

   fn u64(&mut self) -> io::Result<u64>
   {
      Ok(u64::from_le_bytes(self.raw(8)?.try_into().unwrap()))
   }

   fn i64(&mut self) -> io::Result<i64>
   {
      Ok(self.u64()? as i64)
   }

   fn string(&mut self) -> io::Result<String>
   {
      let bytes = self.bytes()?;
      String::from_utf8(bytes).map_err(|_| invalid_data("invalid utf-8 string"))
   }

   fn bytes(&mut self) -> io::Result<Vec<u8>>
   {
      let length = self.u32()? as usize;
      Ok(self.raw(length)?.to_vec())
   }
}

struct Writer
{
   bytes: Vec<u8>,
}

impl Writer
{
   fn new() -> Self
   {
      Self { bytes: Vec::new() }
   }

   fn finish(self) -> Vec<u8>
   {
      self.bytes
   }

   fn raw(&mut self, bytes: &[u8])
   {
      self.bytes.extend_from_slice(bytes);
   }

   fn header(&mut self, magic: &[u8; 8])
   {
      self.raw(magic);
   }

   fn u8(&mut self, value: u8)
   {
      self.bytes.push(value);
   }

   fn boolean(&mut self, value: bool)
   {
      self.u8(u8::from(value));
   }

   fn u16(&mut self, value: u16)
   {
      self.raw(&value.to_le_bytes());
   }

   fn u32(&mut self, value: u32)
   {
      self.raw(&value.to_le_bytes());
   }

   fn i32(&mut self, value: i32)
   {
      self.raw(&value.to_le_bytes());
   }

   fn u64(&mut self, value: u64)
   {
      self.raw(&value.to_le_bytes());
   }

   fn i64(&mut self, value: i64)
   {
      self.raw(&value.to_le_bytes());
   }

   fn string(&mut self, value: &str) -> io::Result<()>
   {
      self.bytes(value.as_bytes())
   }

   fn bytes(&mut self, value: &[u8]) -> io::Result<()>
   {
      self.u32(checked_u32(value.len())?);
      self.raw(value);
      Ok(())
   }
}

#[cfg(test)]
mod tests
{
   use super::*;
   use std::io::Cursor;

   const FIXTURE_CREDENTIAL_BUNDLE: &[u8] =
      include_bytes!("../fixtures/startup.credential_bundle.full.bin");
   const FIXTURE_CREDENTIAL_DELTA: &[u8] =
      include_bytes!("../fixtures/startup.credential_delta.full.bin");
   const FIXTURE_CONTAINER_PARAMETERS: &[u8] =
      include_bytes!("../fixtures/startup.container_parameters.full.bin");
   const FIXTURE_HEALTHY_FRAME: &[u8] =
      include_bytes!("../fixtures/frame.healthy.empty.bin");
   const FIXTURE_CREDENTIALS_REFRESH_ACK_FRAME: &[u8] =
      include_bytes!("../fixtures/frame.credentials_refresh_ack.empty.bin");
   const FIXTURE_RESOURCE_DELTA_ACK_FRAME: &[u8] =
      include_bytes!("../fixtures/frame.resource_delta_ack.accepted.bin");
   const FIXTURE_STATISTICS_FRAME: &[u8] =
      include_bytes!("../fixtures/frame.statistics.demo.bin");

   struct NoopDispatch;

   impl Dispatch for NoopDispatch
   {
      fn begin_shutdown(&mut self, _hub: &mut NeuronHub<Self>)
      {
      }
   }

   struct QueueDispatch;

   impl Dispatch for QueueDispatch
   {
      fn begin_shutdown(&mut self, _hub: &mut NeuronHub<Self>)
      {
      }

      fn resource_delta(&mut self, hub: &mut NeuronHub<Self>, _delta: ResourceDelta)
      {
         hub.queue_resource_delta_ack(true);
      }
   }

   #[test]
   fn credential_delta_roundtrip()
   {
      let mut metadata = BTreeMap::new();
      metadata.insert("scope".into(), "sms".into());

      let delta = CredentialDelta {
         bundle_generation: 7,
         updated_tls: vec![TlsIdentity {
            name: "container.internal".into(),
            generation: 3,
            not_before_ms: 11,
            not_after_ms: 22,
            cert_pem: "cert".into(),
            key_pem: "key".into(),
            chain_pem: "chain".into(),
            dns_sans: vec!["a.internal".into()],
            ip_sans: vec![IpAddress {
               bytes: [0xAA; 16],
               is_ipv6: true,
            }],
            tags: vec!["inbound".into()],
         }],
         removed_tls_names: vec!["old.internal".into()],
         updated_api: vec![ApiCredential {
            name: "telnyx_bearer".into(),
            provider: "telnyx".into(),
            generation: 4,
            expires_at_ms: 33,
            active_from_ms: 44,
            sunset_at_ms: 55,
            material: "secret".into(),
            metadata,
         }],
         removed_api_names: vec!["legacy_token".into()],
         reason: "rotation".into(),
      };

      let encoded = delta.encode().unwrap();
      let decoded = CredentialDelta::decode(&encoded).unwrap();
      assert_eq!(decoded, delta);
   }

   #[test]
   fn container_parameters_roundtrip()
   {
      let parameters = ContainerParameters {
         uuid: U128 { bytes: [0x11; 16] },
         memory_mb: 1024,
         storage_mb: 2048,
         logical_cores: 3,
         neuron_fd: 9,
         low_cpu: 1,
         high_cpu: 3,
         advertises: vec![AdvertisedPort {
            service: 0xABCD_0000_0000_0001,
            port: 19111,
         }],
         subscription_pairings: vec![SubscriptionPairing {
            secret: U128 { bytes: [0x21; 16] },
            address: U128 { bytes: [0x22; 16] },
            service: 0x1234_0000_0000_0102,
            port: 3210,
            application_id: 0x1234,
            activate: true,
         }],
         advertisement_pairings: vec![AdvertisementPairing {
            secret: U128 { bytes: [0x31; 16] },
            address: U128 { bytes: [0x32; 16] },
            service: 0x5678_0000_0000_0103,
            application_id: 0x5678,
            activate: true,
         }],
         private6: IpPrefix {
            address: IpAddress {
               bytes: [0x41; 16],
               is_ipv6: true,
            },
            cidr: 64,
         },
         just_crashed: true,
         datacenter_unique_tag: 17,
         flags: vec![44, 55],
         credential_bundle: Some(CredentialBundle {
            tls_identities: Vec::new(),
            api_credentials: Vec::new(),
            bundle_generation: 123,
         }),
      };

      let encoded = parameters.encode().unwrap();
      let decoded = ContainerParameters::decode(&encoded).unwrap();
      assert_eq!(decoded, parameters);
   }

   fn encode_current_container_parameters(parameters: &ContainerParameters) -> Vec<u8>
   {
      let mut writer = Writer::new();
      writer.header(CONTAINER_PARAMETERS_MAGIC);
      parameters.uuid.encode(&mut writer);
      writer.u32(parameters.memory_mb);
      writer.u32(parameters.storage_mb);
      writer.u16(parameters.logical_cores);
      writer.i32(parameters.neuron_fd);
      writer.i32(parameters.low_cpu);
      writer.i32(parameters.high_cpu);

      encode_vec(&mut writer, &parameters.advertises, |item, inner| {
         inner.u64(item.service);
         inner.u16(item.port);
         Ok(())
      })
      .unwrap();

      encode_vec(&mut writer, &parameters.subscription_pairings, |item, inner| {
         item.secret.encode(inner);
         item.address.encode(inner);
         inner.u64(item.service);
         inner.u16(item.port);
         Ok(())
      })
      .unwrap();

      encode_vec(&mut writer, &parameters.advertisement_pairings, |item, inner| {
         item.secret.encode(inner);
         item.address.encode(inner);
         inner.u64(item.service);
         Ok(())
      })
      .unwrap();

      parameters.private6.encode(&mut writer);
      writer.boolean(parameters.just_crashed);
      writer.u8(parameters.datacenter_unique_tag);
      encode_vec(&mut writer, &parameters.flags, |item, inner| {
         inner.u64(*item);
         Ok(())
      })
      .unwrap();

      writer.boolean(parameters.credential_bundle.is_some());
      if let Some(bundle) = &parameters.credential_bundle
      {
         encode_vec(&mut writer, &bundle.tls_identities, TlsIdentity::encode_fields).unwrap();
         encode_vec(&mut writer, &bundle.api_credentials, ApiCredential::encode_fields).unwrap();
         writer.u64(bundle.bundle_generation);
      }

      writer.finish()
   }

   #[test]
   fn container_parameters_current_wire_decode()
   {
      let parameters = ContainerParameters {
         uuid: U128 { bytes: [0x61; 16] },
         memory_mb: 3072,
         storage_mb: 4096,
         logical_cores: 4,
         neuron_fd: 7,
         low_cpu: 2,
         high_cpu: 5,
         advertises: vec![AdvertisedPort {
            service: 0xABCD_0000_0000_0011,
            port: 19121,
         }],
         subscription_pairings: vec![SubscriptionPairing {
            secret: U128 { bytes: [0x71; 16] },
            address: U128 { bytes: [0x72; 16] },
            service: 0x2233_0000_0000_0102,
            port: 3201,
            application_id: 0x2233,
            activate: true,
         }],
         advertisement_pairings: vec![AdvertisementPairing {
            secret: U128 { bytes: [0x81; 16] },
            address: U128 { bytes: [0x82; 16] },
            service: 0x3344_0000_0000_0103,
            application_id: 0x3344,
            activate: true,
         }],
         private6: IpPrefix {
            address: IpAddress {
               bytes: [0x91; 16],
               is_ipv6: true,
            },
            cidr: 64,
         },
         just_crashed: false,
         datacenter_unique_tag: 23,
         flags: vec![44, 55, 66],
         credential_bundle: Some(CredentialBundle {
            tls_identities: Vec::new(),
            api_credentials: Vec::new(),
            bundle_generation: 101,
         }),
      };

      let encoded = encode_current_container_parameters(&parameters);
      let decoded = ContainerParameters::decode(&encoded).unwrap();
      assert_eq!(decoded, parameters);
   }

   #[test]
   fn frame_roundtrip()
   {
      let payload = vec![1u8, 2, 3, 4, 5];
      let encoded = build_message_frame(ContainerTopic::Message, &payload).unwrap();

      let mut cursor = io::Cursor::new(encoded.clone());
      let frame = read_frame(&mut cursor).unwrap().unwrap();
      assert_eq!(frame.topic, ContainerTopic::Message);
      assert_eq!(frame.payload, payload);

      let header = FrameHeader::decode(encoded[0..FRAME_HEADER_SIZE].try_into().unwrap()).unwrap();
      assert_eq!(header.topic, ContainerTopic::Message);
      assert_eq!(header.header_size as usize, FRAME_HEADER_SIZE);
      assert_eq!(usize::try_from(header.size).unwrap() % FRAME_ALIGNMENT, 0);
   }

   #[test]
   fn ping_response_frame_is_empty_ping()
   {
      let parameters = ContainerParameters {
         neuron_fd: -1,
         ..ContainerParameters::default()
      };

      assert!(NeuronHub::new(parameters, NoopDispatch).is_err());
   }

   #[test]
   fn fixture_credential_bundle_decode()
   {
      let bundle = CredentialBundle::decode(FIXTURE_CREDENTIAL_BUNDLE).unwrap();
      assert_eq!(bundle.bundle_generation, 101);
      assert_eq!(bundle.tls_identities.len(), 1);
      assert_eq!(bundle.tls_identities[0].name, "demo-cert");
      assert_eq!(bundle.api_credentials[0].metadata.get("scope").unwrap(), "demo");
   }

   #[test]
   fn fixture_credential_delta_decode()
   {
      let delta = CredentialDelta::decode(FIXTURE_CREDENTIAL_DELTA).unwrap();
      assert_eq!(delta.bundle_generation, 102);
      assert_eq!(delta.removed_tls_names, vec!["legacy-cert"]);
      assert_eq!(delta.removed_api_names, vec!["legacy-token"]);
      assert_eq!(delta.reason, "fixture-rotation");
   }

   #[test]
   fn fixture_container_parameters_decode()
   {
      let parameters = ContainerParameters::decode(FIXTURE_CONTAINER_PARAMETERS).unwrap();
      assert_eq!(parameters.memory_mb, 1536);
      assert_eq!(parameters.advertises[0].port, 24001);
      assert_eq!(parameters.subscription_pairings[0].application_id, 0x2233);
      assert_eq!(parameters.advertisement_pairings[0].application_id, 0x3344);
      assert_eq!(parameters.datacenter_unique_tag, 23);
      assert_eq!(parameters.flags, vec![44, 55, 66]);
      assert_eq!(parameters.credential_bundle.unwrap().bundle_generation, 101);
   }

   #[test]
   fn fixture_frames_parse()
   {
      let frame = read_frame(&mut Cursor::new(FIXTURE_RESOURCE_DELTA_ACK_FRAME))
         .unwrap()
         .unwrap();
      assert_eq!(frame.topic, ContainerTopic::ResourceDeltaAck);
      assert_eq!(frame.payload, vec![1]);

      let frame = read_frame(&mut Cursor::new(FIXTURE_STATISTICS_FRAME))
         .unwrap()
         .unwrap();
      assert_eq!(frame.topic, ContainerTopic::Statistics);
      assert_eq!(frame.payload.len(), 32);
      assert_eq!(u64::from_le_bytes(frame.payload[0..8].try_into().unwrap()), 1);
      assert_eq!(u64::from_le_bytes(frame.payload[8..16].try_into().unwrap()), 2);
      assert_eq!(u64::from_le_bytes(frame.payload[16..24].try_into().unwrap()), 3);
      assert_eq!(u64::from_le_bytes(frame.payload[24..32].try_into().unwrap()), 4);
      assert_eq!(build_ready_frame().unwrap(), FIXTURE_HEALTHY_FRAME);
      assert_eq!(
         build_statistics_frame(&[
            MetricPair { key: 1, value: 2 },
            MetricPair { key: 3, value: 4 },
         ]).unwrap(),
         FIXTURE_STATISTICS_FRAME);
      assert_eq!(build_resource_delta_ack_frame(true).unwrap(), FIXTURE_RESOURCE_DELTA_ACK_FRAME);
      assert_eq!(
         build_credentials_refresh_ack_frame().unwrap(),
         FIXTURE_CREDENTIALS_REFRESH_ACK_FRAME);
   }

   #[test]
   fn frame_decoder_and_handle_message_frame()
   {
      let parameters = ContainerParameters::decode(FIXTURE_CONTAINER_PARAMETERS).unwrap();
      let mut hub = NeuronHub::new_borrowed_transport(parameters, NoopDispatch).unwrap();
      let ping = build_message_frame(ContainerTopic::Ping, &[]).unwrap();
      let mut decoder = FrameDecoder::default();

      assert!(decoder.feed(&ping[..5]).unwrap().is_empty());
      let frames = decoder.feed(&ping[5..]).unwrap();
      assert_eq!(frames.len(), 1);

      let outbound = hub.handle_message_frame(&frames[0]).unwrap();
      assert_eq!(outbound.len(), 1);
      assert_eq!(outbound[0].topic, ContainerTopic::Ping);
      assert!(outbound[0].payload.is_empty());
   }

   #[test]
   fn handle_decoded_frame_encodes_ping_response()
   {
      let parameters = ContainerParameters::decode(FIXTURE_CONTAINER_PARAMETERS).unwrap();
      let mut hub = NeuronHub::new_borrowed_transport(parameters, NoopDispatch).unwrap();
      let frame = MessageFrame {
         topic: ContainerTopic::Ping,
         payload: Vec::new(),
      };

      let outbound = hub.handle_decoded_frame(&frame).unwrap();
      assert_eq!(outbound, vec![build_message_frame(ContainerTopic::Ping, &[]).unwrap()]);
   }

   #[test]
   fn handle_bytes_drains_dispatch_queued_frames()
   {
      let parameters = ContainerParameters::decode(FIXTURE_CONTAINER_PARAMETERS).unwrap();
      let mut hub = NeuronHub::new_borrowed_transport(parameters, QueueDispatch).unwrap();
      let mut decoder = FrameDecoder::default();
      let delta = build_message_frame(
         ContainerTopic::ResourceDelta,
         &[1, 0, 2, 0, 0, 0, 3, 0, 0, 0, 1, 4, 0, 0, 0],
      )
      .unwrap();

      let outbound = hub.handle_bytes(&mut decoder, &delta).unwrap();
      assert_eq!(outbound, vec![FIXTURE_RESOURCE_DELTA_ACK_FRAME.to_vec()]);
   }

   #[test]
   fn control_policy_auto_acks_and_tracks_shutdown()
   {
      let parameters = ContainerParameters::decode(FIXTURE_CONTAINER_PARAMETERS).unwrap();
      let mut hub = NeuronHub::new_borrowed_transport(parameters, DefaultDispatch)
         .unwrap()
         .with_resource_delta_ack(true)
         .with_credentials_refresh_ack();

      let resource_delta = MessageFrame {
         topic: ContainerTopic::ResourceDelta,
         payload: vec![1, 0, 2, 0, 0, 0, 3, 0, 0, 0, 1, 4, 0, 0, 0],
      };
      assert_eq!(
         hub.handle_decoded_frame(&resource_delta).unwrap(),
         vec![FIXTURE_RESOURCE_DELTA_ACK_FRAME.to_vec()],
      );

      let credentials_refresh = MessageFrame {
         topic: ContainerTopic::CredentialsRefresh,
         payload: FIXTURE_CREDENTIAL_DELTA.to_vec(),
      };
      assert_eq!(
         hub.handle_decoded_frame(&credentials_refresh).unwrap(),
         vec![FIXTURE_CREDENTIALS_REFRESH_ACK_FRAME.to_vec()],
      );

      assert!(!hub.shutdown_requested());
      assert!(hub.handle_decoded_frame(&MessageFrame {
         topic: ContainerTopic::Stop,
         payload: Vec::new(),
      }).unwrap().is_empty());
      assert!(hub.shutdown_requested());
   }
}
