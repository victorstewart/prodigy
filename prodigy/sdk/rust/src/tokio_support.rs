// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0

use std::future::Future;
use std::io;
use std::os::fd::FromRawFd;
use std::os::unix::net::UnixStream as StdUnixStream;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::mpsc;

use crate::{ContainerParameters, ControlPolicy, Dispatch, FrameDecoder, NeuronHub};

const READ_BUFFER_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NeuronEvent
{
   Shutdown,
   Closed,
}

#[derive(Debug)]
pub enum ReactorEvent<E>
{
   Neuron(NeuronEvent),
   App(E),
}

pub struct ReactorSink<E>
{
   tx: mpsc::UnboundedSender<io::Result<ReactorEvent<E>>>,
}

impl<E> Clone for ReactorSink<E>
{
   fn clone(&self) -> Self
   {
      Self {
         tx: self.tx.clone(),
      }
   }
}

pub struct TokioReactor<E>
{
   tx: mpsc::UnboundedSender<io::Result<ReactorEvent<E>>>,
   rx: mpsc::UnboundedReceiver<io::Result<ReactorEvent<E>>>,
}

enum Command
{
   Ready,
}

pub struct TokioNeuron<D: Dispatch>
{
   hub: NeuronHub<D>,
   reader: tokio::net::unix::OwnedReadHalf,
   writer: tokio::net::unix::OwnedWriteHalf,
   decoder: FrameDecoder,
   read_buffer: [u8; READ_BUFFER_BYTES],
}

pub struct TokioNeuronHandle
{
   parameters: ContainerParameters,
   command_tx: mpsc::Sender<Command>,
   ready_sent: bool,
}

impl<E> ReactorSink<E>
{
   pub fn app(&self, event: E) -> io::Result<()>
   {
      self.send(Ok(ReactorEvent::App(event)))
   }

   fn neuron(&self, event: NeuronEvent) -> io::Result<()>
   {
      self.send(Ok(ReactorEvent::Neuron(event)))
   }

   fn error(&self, error: io::Error) -> io::Result<()>
   {
      self.send(Err(error))
   }

   fn send(&self, event: io::Result<ReactorEvent<E>>) -> io::Result<()>
   {
      self.tx
         .send(event)
         .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "reactor closed"))
   }
}

impl<E> TokioReactor<E>
{
   pub fn new() -> Self
   {
      let (tx, rx) = mpsc::unbounded_channel();
      Self { tx, rx }
   }

   pub fn sink(&self) -> ReactorSink<E>
   {
      ReactorSink {
         tx: self.tx.clone(),
      }
   }

   pub async fn next(&mut self) -> Option<io::Result<ReactorEvent<E>>>
   {
      self.rx.recv().await
   }
}

impl<E> Default for TokioReactor<E>
{
   fn default() -> Self
   {
      Self::new()
   }
}

impl<E> TokioReactor<E>
where
   E: Send + 'static,
{
   pub fn once<F, T>(&self, event: E, future: F)
   where
      F: Future<Output = io::Result<T>> + Send + 'static,
      T: Send + 'static,
   {
      let sink = self.sink();
      tokio::spawn(async move {
         match future.await
         {
            Ok(_) =>
            {
               let _ = sink.app(event);
            }
            Err(error) =>
            {
               let _ = sink.error(error);
            }
         }
      });
   }

   pub fn attach_neuron<D>(&self, neuron: TokioNeuron<D>) -> TokioNeuronHandle
   where
      D: Dispatch + Send + 'static,
   {
      neuron.attach(self.sink())
   }
}

impl<D: Dispatch> TokioNeuron<D>
{
   pub fn new(parameters: ContainerParameters, dispatch: D) -> io::Result<Self>
   {
      let std_neuron = unsafe { StdUnixStream::from_raw_fd(parameters.neuron_fd) };
      std_neuron.set_nonblocking(true)?;
      let (reader, writer) = UnixStream::from_std(std_neuron)?.into_split();
      Ok(Self {
         hub: NeuronHub::new_borrowed_transport(parameters, dispatch)?,
         reader,
         writer,
         decoder: FrameDecoder::default(),
         read_buffer: [0; READ_BUFFER_BYTES],
      })
   }

   pub fn from_process(dispatch: D) -> io::Result<Self>
   {
      Self::new(ContainerParameters::from_process()?, dispatch)
   }

   pub fn with_control_policy(mut self, control_policy: ControlPolicy) -> Self
   {
      self.hub = self.hub.with_control_policy(control_policy);
      self
   }

   pub fn with_resource_delta_ack(mut self, accepted: bool) -> Self
   {
      self.hub = self.hub.with_resource_delta_ack(accepted);
      self
   }

   pub fn with_credentials_refresh_ack(mut self) -> Self
   {
      self.hub = self.hub.with_credentials_refresh_ack();
      self
   }

   pub fn with_auto_acks(self) -> Self
   {
      self.with_resource_delta_ack(true).with_credentials_refresh_ack()
   }

   pub fn parameters(&self) -> &ContainerParameters
   {
      &self.hub.parameters
   }
}

impl<D> TokioNeuron<D>
where
   D: Dispatch + Send + 'static,
{
   fn attach<E>(self, sink: ReactorSink<E>) -> TokioNeuronHandle
   where
      E: Send + 'static,
   {
      let parameters = self.hub.parameters.clone();
      let (command_tx, command_rx) = mpsc::channel(4);
      tokio::spawn(async move {
         if let Err(error) = self.run(command_rx, sink.clone()).await
         {
            let _ = sink.error(error);
         }
      });
      TokioNeuronHandle {
         parameters,
         command_tx,
         ready_sent: false,
      }
   }

   async fn run<E>(
      mut self,
      mut command_rx: mpsc::Receiver<Command>,
      sink: ReactorSink<E>,
   ) -> io::Result<()>
   where
      E: Send + 'static,
   {
      let mut commands_open = true;
      loop
      {
         tokio::select!
         {
            maybe_command = command_rx.recv(), if commands_open =>
            {
               match maybe_command
               {
                  Some(Command::Ready) =>
                  {
                     self.hub.queue_ready();
                     self.flush_outbound().await?;
                  }
                  None =>
                  {
                     commands_open = false;
                  }
               }
            }
            alive = self.pump_once() =>
            {
               if !alive?
               {
                  let _ = sink.neuron(NeuronEvent::Closed);
                  return Ok(());
               }

               if self.hub.shutdown_requested()
               {
                  let _ = sink.neuron(NeuronEvent::Shutdown);
                  return Ok(());
               }
            }
         }
      }
   }
}

impl TokioNeuronHandle
{
   pub fn parameters(&self) -> &ContainerParameters
   {
      &self.parameters
   }

   pub async fn ready(&mut self) -> io::Result<()>
   {
      if self.ready_sent
      {
         return Ok(());
      }

      self.command_tx
         .send(Command::Ready)
         .await
         .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "neuron reactor closed"))?;
      self.ready_sent = true;
      Ok(())
   }
}

impl<D: Dispatch> TokioNeuron<D>
{
   async fn flush_outbound(&mut self) -> io::Result<()>
   {
      write_frames(&mut self.writer, self.hub.drain_outbound_bytes()?).await
   }

   async fn pump_once(&mut self) -> io::Result<bool>
   {
      let bytes_read = self.reader.read(&mut self.read_buffer).await?;
      if bytes_read == 0
      {
         return Ok(false);
      }

      write_frames(
         &mut self.writer,
         self.hub
            .handle_bytes(&mut self.decoder, &self.read_buffer[..bytes_read])?,
      )
      .await?;
      Ok(true)
   }
}

async fn write_frames(
   writer: &mut tokio::net::unix::OwnedWriteHalf,
   frames: Vec<Vec<u8>>,
) -> io::Result<()>
{
   for frame in frames
   {
      writer.write_all(&frame).await?;
   }

   Ok(())
}

#[cfg(test)]
mod tests
{
   use std::os::fd::IntoRawFd;
   use std::os::unix::net::UnixStream as StdUnixStream;

   use crate::{build_message_frame, DefaultDispatch};

   use super::*;

   #[derive(Clone, Copy, Debug, Eq, PartialEq)]
   enum AppEvent
   {
      ProbeReady,
   }

   #[tokio::test(flavor = "current_thread")]
   async fn reactor_receives_app_and_neuron_events()
   {
      let (container_end, neuron_end) = StdUnixStream::pair().unwrap();
      neuron_end.set_nonblocking(true).unwrap();

      let parameters = ContainerParameters {
         neuron_fd: container_end.into_raw_fd(),
         ..ContainerParameters::default()
      };

      let mut reactor = TokioReactor::new();
      let mut neuron = reactor.attach_neuron(TokioNeuron::new(parameters, DefaultDispatch).unwrap());
      let mut neuron_stream = UnixStream::from_std(neuron_end).unwrap();

      reactor.once(AppEvent::ProbeReady, async { Ok::<_, io::Error>(()) });

      match reactor.next().await.unwrap().unwrap()
      {
         ReactorEvent::App(AppEvent::ProbeReady) =>
         {
            neuron.ready().await.unwrap();
         }
         event => panic!("unexpected reactor event: {event:?}"),
      }

      let mut bytes = vec![0u8; 16];
      neuron_stream.read_exact(&mut bytes).await.unwrap();

      neuron_stream
         .write_all(&build_message_frame(crate::ContainerTopic::Stop, &[]).unwrap())
         .await
         .unwrap();

      match reactor.next().await.unwrap().unwrap()
      {
         ReactorEvent::Neuron(NeuronEvent::Shutdown) =>
         {
         }
         event => panic!("unexpected reactor event: {event:?}"),
      }
   }
}
