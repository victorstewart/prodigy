// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::net::{Ipv6Addr, SocketAddr};
use std::time::Duration;

use prodigy_sdk::tokio_support::{
   NeuronEvent,
   ReactorEvent,
   ReactorSink,
   TokioNeuron,
   TokioReactor,
};
use prodigy_sdk::{
   AdvertisementPairing,
   ContainerParameters,
   CredentialDelta,
   Dispatch,
   MetricPair,
   NeuronHub,
   ResourceDelta,
   SubscriptionPairing,
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::time::{sleep, timeout, Instant};

const PINGPONG_ROUNDS: u32 = 3;
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const PAIRING_TIMEOUT: Duration = Duration::from_secs(45);
const STAT_DATACENTER_TAG: u64 = 0x6d65_7368_0001;
const STAT_STARTUP_PAIRINGS: u64 = 0x6d65_7368_0002;
const STAT_ADVERTISEMENT_PAIRING: u64 = 0x6d65_7368_0010;
const STAT_SUBSCRIPTION_PAIRING: u64 = 0x6d65_7368_0011;
const STAT_RESOURCE_LOGICAL_CORES: u64 = 0x6d65_7368_0020;
const STAT_RESOURCE_MEMORY_MB: u64 = 0x6d65_7368_0021;
const STAT_RESOURCE_STORAGE_MB: u64 = 0x6d65_7368_0022;
const STAT_RESOURCE_DOWNSCALE: u64 = 0x6d65_7368_0023;
const STAT_RESOURCE_GRACE_SECONDS: u64 = 0x6d65_7368_0024;
const STAT_CREDENTIAL_GENERATION: u64 = 0x6d65_7368_0030;
const STAT_CREDENTIAL_TLS_UPDATES: u64 = 0x6d65_7368_0031;
const STAT_CREDENTIAL_API_UPDATES: u64 = 0x6d65_7368_0032;
const STAT_CREDENTIAL_REMOVALS: u64 = 0x6d65_7368_0033;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Role
{
   Advertiser { port: u16 },
   Subscriber,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Event
{
   AdvertisementPairing(AdvertisementPairing),
   SubscriptionPairing(SubscriptionPairing),
   MeshComplete,
}

#[derive(Clone)]
struct MeshDispatch
{
   sink: ReactorSink<Event>,
}

impl Dispatch for MeshDispatch
{
   fn end_of_dynamic_args(&mut self, hub: &mut NeuronHub<Self>)
   {
      queue_stats(
         hub,
         &[
            metric(STAT_DATACENTER_TAG, u64::from(hub.parameters.datacenter_unique_tag)),
            metric(
               STAT_STARTUP_PAIRINGS,
               (hub.parameters.advertisement_pairings.len() + hub.parameters.subscription_pairings.len()) as u64,
            ),
         ],
      );
   }

   fn begin_shutdown(&mut self, _hub: &mut NeuronHub<Self>)
   {
   }

   fn advertisement_pairing(
      &mut self,
      hub: &mut NeuronHub<Self>,
      pairing: AdvertisementPairing)
   {
      queue_stats(
         hub,
         &[
            metric(STAT_DATACENTER_TAG, u64::from(hub.parameters.datacenter_unique_tag)),
            metric(STAT_ADVERTISEMENT_PAIRING, u64::from(pairing.activate)),
         ],
      );
      let _ = self.sink.app(Event::AdvertisementPairing(pairing));
   }

   fn subscription_pairing(
      &mut self,
      hub: &mut NeuronHub<Self>,
      pairing: SubscriptionPairing)
   {
      queue_stats(
         hub,
         &[
            metric(STAT_DATACENTER_TAG, u64::from(hub.parameters.datacenter_unique_tag)),
            metric(STAT_SUBSCRIPTION_PAIRING, u64::from(pairing.activate)),
         ],
      );
      let _ = self.sink.app(Event::SubscriptionPairing(pairing));
   }

   fn resource_delta(&mut self, hub: &mut NeuronHub<Self>, delta: ResourceDelta)
   {
      hub.queue_resource_delta_ack(true);
      queue_stats(
         hub,
         &[
            metric(STAT_DATACENTER_TAG, u64::from(hub.parameters.datacenter_unique_tag)),
            metric(STAT_RESOURCE_LOGICAL_CORES, u64::from(delta.logical_cores)),
            metric(STAT_RESOURCE_MEMORY_MB, u64::from(delta.memory_mb)),
            metric(STAT_RESOURCE_STORAGE_MB, u64::from(delta.storage_mb)),
            metric(STAT_RESOURCE_DOWNSCALE, if delta.is_downscale { 1 } else { 0 }),
            metric(STAT_RESOURCE_GRACE_SECONDS, u64::from(delta.grace_seconds)),
         ],
      );
   }

   fn credentials_refresh(
      &mut self,
      hub: &mut NeuronHub<Self>,
      delta: CredentialDelta)
   {
      hub.queue_credentials_refresh_ack();
      queue_stats(
         hub,
         &[
            metric(STAT_DATACENTER_TAG, u64::from(hub.parameters.datacenter_unique_tag)),
            metric(STAT_CREDENTIAL_GENERATION, delta.bundle_generation),
            metric(STAT_CREDENTIAL_TLS_UPDATES, delta.updated_tls.len() as u64),
            metric(STAT_CREDENTIAL_API_UPDATES, delta.updated_api.len() as u64),
            metric(
               STAT_CREDENTIAL_REMOVALS,
               (delta.removed_tls_names.len() + delta.removed_api_names.len()) as u64,
            ),
         ],
      );
   }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> io::Result<()>
{
   let mut reactor = TokioReactor::new();
   let dispatch = MeshDispatch {
      sink: reactor.sink(),
   };
   let mut neuron = reactor.attach_neuron(TokioNeuron::from_process(dispatch)?);
   let parameters = neuron.parameters().clone();
   let role = role_from_parameters(&parameters)?;
   let private6 = private6_addr(&parameters)?;

   let bootstrap_sink = reactor.sink();
   for pairing in parameters.advertisement_pairings.iter().copied()
   {
      let _ = bootstrap_sink.app(Event::AdvertisementPairing(pairing));
   }
   for pairing in parameters.subscription_pairings.iter().copied()
   {
      let _ = bootstrap_sink.app(Event::SubscriptionPairing(pairing));
   }

   let mut saw_pairing = false;
   let mut mesh_started = matches!(role, Role::Advertiser { .. });
   let mut mesh_complete = false;
   let mut ready_sent = false;

   if let Role::Advertiser { port } = role
   {
      let listener = TcpListener::bind(SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), port)).await?;
      neuron.ready().await?;
      ready_sent = true;
      reactor.once(Event::MeshComplete, run_advertiser(listener));
   }

   while let Some(event) = reactor.next().await
   {
      match event?
      {
         ReactorEvent::App(Event::AdvertisementPairing(pairing)) =>
         {
            if pairing.activate
            {
               saw_pairing = true;
            }
         }
         ReactorEvent::App(Event::SubscriptionPairing(pairing)) =>
         {
            if pairing.activate
            {
               saw_pairing = true;
               if mesh_started == false
               {
                  mesh_started = true;
                  reactor.once(Event::MeshComplete, run_subscriber(private6, pairing));
               }
            }
         }
         ReactorEvent::App(Event::MeshComplete) =>
         {
            mesh_complete = true;
         }
         ReactorEvent::Neuron(NeuronEvent::Shutdown | NeuronEvent::Closed) =>
         {
            return Ok(());
         }
      }

      if ready_sent == false && saw_pairing && mesh_complete
      {
         neuron.ready().await?;
         ready_sent = true;
      }
   }

   Ok(())
}

fn role_from_parameters(parameters: &ContainerParameters) -> io::Result<Role>
{
   if let Some(advertise) = parameters.advertises.first()
   {
      return Ok(Role::Advertiser { port: advertise.port });
   }

   Ok(Role::Subscriber)
}

fn private6_addr(parameters: &ContainerParameters) -> io::Result<Ipv6Addr>
{
   if parameters.private6.address.is_ipv6 == false
   {
      return Err(io::Error::new(
         io::ErrorKind::InvalidInput,
         "container did not receive an IPv6 private address",
      ));
   }

   let address = Ipv6Addr::from(parameters.private6.address.bytes);
   if address.is_unspecified()
   {
      return Err(io::Error::new(
         io::ErrorKind::InvalidInput,
         "container private6 address is unspecified",
      ));
   }

   Ok(address)
}

async fn run_advertiser(listener: TcpListener) -> io::Result<()>
{
   let (stream, _) = listener.accept().await?;
   serve_pingpong(stream).await
}

async fn run_subscriber(source: Ipv6Addr, pairing: SubscriptionPairing) -> io::Result<()>
{
   let target = SocketAddr::new(Ipv6Addr::from(pairing.address.bytes).into(), pairing.port);
   let deadline = Instant::now() + PAIRING_TIMEOUT;

   loop
   {
      let socket = TcpSocket::new_v6()?;
      socket.bind(SocketAddr::new(source.into(), 0))?;

      let error = match timeout(Duration::from_secs(1), socket.connect(target)).await
      {
         Ok(Ok(stream)) =>
         {
            return client_pingpong(stream).await;
         }
         Ok(Err(error)) => error,
         Err(_) => io::Error::new(io::ErrorKind::TimedOut, "mesh connect timeout"),
      };

      if Instant::now() >= deadline
      {
         return Err(error);
      }

      sleep(Duration::from_millis(250)).await;
   }
}

async fn serve_pingpong(stream: TcpStream) -> io::Result<()>
{
   let mut stream = BufReader::new(stream);

   for round in 0..PINGPONG_ROUNDS
   {
      let line = read_line(&mut stream).await?;
      if line.trim_end() != format!("ping {round}")
      {
         return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected ping line: {line:?}"),
         ));
      }

      timeout(
         IO_TIMEOUT,
         stream
            .get_mut()
            .write_all(format!("pong {round}\n").as_bytes()),
      )
      .await
      .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "mesh send timeout"))??;
   }

   Ok(())
}

async fn client_pingpong(stream: TcpStream) -> io::Result<()>
{
   let mut stream = BufReader::new(stream);

   for round in 0..PINGPONG_ROUNDS
   {
      timeout(
         IO_TIMEOUT,
         stream
            .get_mut()
            .write_all(format!("ping {round}\n").as_bytes()),
      )
      .await
      .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "mesh send timeout"))??;

      let line = read_line(&mut stream).await?;
      if line.trim_end() != format!("pong {round}")
      {
         return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected pong line: {line:?}"),
         ));
      }
   }

   Ok(())
}

async fn read_line(stream: &mut BufReader<TcpStream>) -> io::Result<String>
{
   let mut line = String::new();
   let bytes = timeout(IO_TIMEOUT, stream.read_line(&mut line))
      .await
      .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "mesh receive timeout"))??;

   if bytes == 0
   {
      return Err(io::Error::new(
         io::ErrorKind::UnexpectedEof,
         "mesh peer closed connection",
      ));
   }

   Ok(line)
}

fn metric(key: u64, value: u64) -> MetricPair
{
   MetricPair { key, value }
}

fn queue_stats<D: Dispatch>(hub: &mut NeuronHub<D>, metrics: &[MetricPair])
{
   hub.queue_statistics(metrics);
}
