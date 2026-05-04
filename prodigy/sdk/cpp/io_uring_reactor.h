/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include "neuron_hub.h"

#include <liburing.h>

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <deque>
#include <fcntl.h>
#include <memory>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <variant>
#include <vector>

namespace ProdigySDK::IOUring
{
   enum class NeuronEvent : std::uint8_t
   {
      activity = 1,
      shutdown = 2,
      closed = 3,
   };

   enum class Interest : std::uint16_t
   {
      readable = POLLIN | POLLERR | POLLHUP,
      writable = POLLOUT | POLLERR | POLLHUP,
   };

   template <typename AppEvent>
   using ReactorEvent = std::variant<NeuronEvent, AppEvent>;

   namespace Detail
   {
      enum class Operation : std::uint8_t
      {
         neuronRecv = 1,
         neuronSend = 2,
         watchFD = 3,
      };

      inline std::uint64_t packUserData(Operation operation, std::size_t index)
      {
         return (static_cast<std::uint64_t>(index) << 8u) | static_cast<std::uint64_t>(operation);
      }

      inline Operation unpackOperation(std::uint64_t userData)
      {
         return static_cast<Operation>(userData & 0xffu);
      }

      inline std::size_t unpackIndex(std::uint64_t userData)
      {
         return static_cast<std::size_t>(userData >> 8u);
      }

      inline Result setNonBlocking(int fd)
      {
         const int flags = ::fcntl(fd, F_GETFL, 0);
         if (flags < 0)
         {
            return Result::io;
         }

         if (::fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
         {
            return Result::io;
         }

         return Result::ok;
      }

      inline Result readAllFromFD(int fd, Bytes& output)
      {
         output.clear();
         if (::lseek(fd, 0, SEEK_SET) < 0)
         {
            (void)::close(fd);
            return Result::io;
         }
         std::array<std::uint8_t, 65536> buffer {};

         while (true)
         {
            const ssize_t bytesRead = ::read(fd, buffer.data(), buffer.size());
            if (bytesRead == 0)
            {
               (void)::close(fd);
               return Result::ok;
            }

            if (bytesRead < 0)
            {
               if (errno == EINTR)
               {
                  continue;
               }

               (void)::close(fd);
               return Result::io;
            }

            output.insert(output.end(), buffer.begin(), buffer.begin() + bytesRead);
         }
      }

      inline short interestMask(Interest interest)
      {
         return static_cast<short>(interest);
      }
   }

   inline Result loadContainerParametersFromProcess(
      int argc,
      char *argv[],
      ContainerParameters& parameters)
   {
      return loadContainerParametersFromEnvOrArgv(argc, argv, parameters, Detail::readAllFromFD);
   }

   struct AttachedNeuron
   {
      NeuronHub hub;
      FrameDecoder decoder;
      int fd = -1;
      std::array<std::uint8_t, 4096> readBuffer {};

      AttachedNeuron(NeuronHub inputHub, int inputFD = -1)
         : hub(std::move(inputHub)),
           fd(inputFD >= 0 ? inputFD : hub.parameters.neuronFD)
      {
      }

      static Result fromProcess(
         Dispatch *dispatch,
         int argc,
         char *argv[],
         AttachedNeuron& output)
      {
         ContainerParameters parameters;
         Result result = loadContainerParametersFromProcess(argc, argv, parameters);
         if (result != Result::ok)
         {
            return result;
         }

         output = AttachedNeuron(NeuronHub(dispatch, std::move(parameters)));
         return Result::ok;
      }

      NeuronHub& endpoint(void)
      {
         return hub;
      }

      const NeuronHub& endpoint(void) const
      {
         return hub;
      }

   };

   template <typename AppEvent>
   class Reactor
   {
   private:

      struct NeuronSource
      {
         AttachedNeuron *neuron = nullptr;
      };

      struct SendOperation
      {
         int fd = -1;
         Bytes bytes;
      };

      struct WatchOperation
      {
         int fd = -1;
         short mask = 0;
         bool checkConnect = false;
         AppEvent event;
      };

      io_uring ring {};
      bool initialized = false;
      std::deque<AppEvent> immediateEvents;
      std::vector<NeuronSource> neurons;
      std::vector<std::unique_ptr<SendOperation>> sends;
      std::vector<std::unique_ptr<WatchOperation>> watches;

      Result queueReady(std::size_t neuronIndex)
      {
         neurons[neuronIndex].neuron->hub.queueReady();
         return drainQueuedResponses(neuronIndex);
      }

      Result queueSend(int fd, Bytes bytes)
      {
         auto operation = std::make_unique<SendOperation>();
         operation->fd = fd;
         operation->bytes = std::move(bytes);
         const std::size_t index = sends.size();
         sends.push_back(std::move(operation));

         io_uring_sqe *sqe = io_uring_get_sqe(&ring);
         if (sqe == nullptr)
         {
            return Result::io;
         }

         io_uring_prep_send(
            sqe,
            sends[index]->fd,
            sends[index]->bytes.data(),
            static_cast<unsigned>(sends[index]->bytes.size()),
            0);
         io_uring_sqe_set_data64(sqe, Detail::packUserData(Detail::Operation::neuronSend, index));
         return Result::ok;
      }

      Result queueFrames(int fd, std::vector<Bytes>& frames)
      {
         for (Bytes& frame : frames)
         {
            Result result = queueSend(fd, std::move(frame));
            if (result != Result::ok)
            {
               return result;
            }
         }

         return Result::ok;
      }

      Result queueAutomaticResponses(std::size_t neuronIndex, std::vector<MessageFrame>& frames)
      {
         std::vector<Bytes> encoded;
         Result result = encodeMessageFrames(frames, encoded);
         if (result != Result::ok)
         {
            return result;
         }

         return queueFrames(neurons[neuronIndex].neuron->fd, encoded);
      }

      Result drainQueuedResponses(std::size_t neuronIndex)
      {
         std::vector<Bytes> encoded;
         Result result = neurons[neuronIndex].neuron->hub.drainQueuedResponseBytes(encoded);
         if (result != Result::ok)
         {
            return result;
         }

         return queueFrames(neurons[neuronIndex].neuron->fd, encoded);
      }

      Result armWatch(std::size_t watchIndex)
      {
         if (watchIndex >= watches.size() || watches[watchIndex] == nullptr)
         {
            return Result::argument;
         }

         io_uring_sqe *sqe = io_uring_get_sqe(&ring);
         if (sqe == nullptr)
         {
            return Result::io;
         }

         WatchOperation& watch = *watches[watchIndex];
         io_uring_prep_poll_add(sqe, watch.fd, watch.mask);
         io_uring_sqe_set_data64(sqe, Detail::packUserData(Detail::Operation::watchFD, watchIndex));
         return Result::ok;
      }

      Result armNeuronRecv(std::size_t neuronIndex)
      {
         io_uring_sqe *sqe = io_uring_get_sqe(&ring);
         if (sqe == nullptr)
         {
            return Result::io;
         }

         AttachedNeuron& neuron = *neurons[neuronIndex].neuron;
         io_uring_prep_recv(
            sqe,
            neuron.fd,
            neuron.readBuffer.data(),
            static_cast<unsigned>(neuron.readBuffer.size()),
            0);
         io_uring_sqe_set_data64(sqe, Detail::packUserData(Detail::Operation::neuronRecv, neuronIndex));
         return Result::ok;
      }

   public:

      class NeuronHandle
      {
      private:

         Reactor *reactor = nullptr;
         std::size_t index = 0;

         friend class Reactor<AppEvent>;

         NeuronHandle(Reactor *owner, std::size_t sourceIndex)
            : reactor(owner),
              index(sourceIndex)
         {
         }

      public:

         NeuronHandle(void) = default;

         Result ready(void)
         {
            if (reactor == nullptr || index >= reactor->neurons.size() || reactor->neurons[index].neuron == nullptr)
            {
               return Result::argument;
            }

            return reactor->queueReady(index);
         }

      };

      Reactor(void)
      {
         if (io_uring_queue_init(64, &ring, 0) == 0)
         {
            initialized = true;
         }
      }

      ~Reactor(void)
      {
         if (initialized)
         {
            io_uring_queue_exit(&ring);
         }
      }

      bool valid(void) const
      {
         return initialized;
      }

      Result emit(AppEvent event)
      {
         immediateEvents.push_back(std::move(event));
         return Result::ok;
      }

      Result attachNeuron(AttachedNeuron& neuron, NeuronHandle& handle)
      {
         if (initialized == false)
         {
            return Result::io;
         }

         if (neuron.fd < 0)
         {
            return Result::argument;
         }

         Result result = Detail::setNonBlocking(neuron.fd);
         if (result != Result::ok)
         {
            return result;
         }

         const std::size_t index = neurons.size();
         neurons.push_back(NeuronSource {&neuron});
         handle = NeuronHandle(this, index);
         return armNeuronRecv(index);
      }

      Result once(int fd, Interest interest, AppEvent event, bool checkConnect = false)
      {
         if (initialized == false || fd < 0)
         {
            return Result::argument;
         }

         auto operation = std::make_unique<WatchOperation>();
         operation->fd = fd;
         operation->mask = Detail::interestMask(interest);
         operation->checkConnect = checkConnect;
         operation->event = std::move(event);
         const std::size_t index = watches.size();
         watches.push_back(std::move(operation));
         return armWatch(index);
      }

      Result onceReadable(int fd, AppEvent event)
      {
         return once(fd, Interest::readable, std::move(event), false);
      }

      Result onceWritable(int fd, AppEvent event)
      {
         return once(fd, Interest::writable, std::move(event), false);
      }

      Result onceConnect(int fd, AppEvent event)
      {
         return once(fd, Interest::writable, std::move(event), true);
      }

      Result next(ReactorEvent<AppEvent>& event)
      {
         if (initialized == false)
         {
            return Result::io;
         }

         while (true)
         {
            if (immediateEvents.empty() == false)
            {
               event = std::move(immediateEvents.front());
               immediateEvents.pop_front();
               return Result::ok;
            }

            if (io_uring_submit(&ring) < 0)
            {
               return Result::io;
            }

            io_uring_cqe *cqe = nullptr;
            if (io_uring_wait_cqe(&ring, &cqe) < 0 || cqe == nullptr)
            {
               return Result::io;
            }

            const std::int32_t result = cqe->res;
            const std::uint64_t userData = io_uring_cqe_get_data64(cqe);
            io_uring_cqe_seen(&ring, cqe);

            const Detail::Operation operation = Detail::unpackOperation(userData);
            const std::size_t index = Detail::unpackIndex(userData);

            switch (operation)
            {
               case Detail::Operation::neuronRecv:
               {
                  if (index >= neurons.size() || neurons[index].neuron == nullptr)
                  {
                     return Result::protocol;
                  }

                  AttachedNeuron& neuron = *neurons[index].neuron;
                  if (result == 0)
                  {
                     event = NeuronEvent::closed;
                     return Result::ok;
                  }

                  if (result < 0)
                  {
                     if (result == -EAGAIN || result == -EINTR)
                     {
                        Result rearm = armNeuronRecv(index);
                        if (rearm != Result::ok)
                        {
                           return rearm;
                        }

                        continue;
                     }

                     return Result::io;
                  }

                  std::vector<MessageFrame> frames;
                  Result feedResult = neuron.decoder.feed(
                     neuron.readBuffer.data(),
                     static_cast<std::size_t>(result),
                     frames);
                  if (feedResult != Result::ok)
                  {
                     return feedResult;
                  }

                  bool processedFrame = false;
                  for (const MessageFrame& frame : frames)
                  {
                     processedFrame = true;
                     std::vector<MessageFrame> automaticResponses;
                     Result handleResult = neuron.hub.handleFrame(frame, automaticResponses);
                     if (handleResult != Result::ok)
                     {
                        return handleResult;
                     }

                     handleResult = queueAutomaticResponses(index, automaticResponses);
                     if (handleResult != Result::ok)
                     {
                        return handleResult;
                     }

                     handleResult = drainQueuedResponses(index);
                     if (handleResult != Result::ok)
                     {
                        return handleResult;
                     }

                     if (neuron.hub.shutdownRequested())
                     {
                        event = NeuronEvent::shutdown;
                        return Result::ok;
                     }
                  }

                  Result rearm = armNeuronRecv(index);
                  if (rearm != Result::ok)
                  {
                     return rearm;
                  }

                  if (processedFrame)
                  {
                     event = NeuronEvent::activity;
                     return Result::ok;
                  }
                  break;
               }
               case Detail::Operation::neuronSend:
               {
                  if (index < sends.size())
                  {
                     sends[index].reset();
                  }

                  if (result < 0)
                  {
                     return Result::io;
                  }
                  break;
               }
               case Detail::Operation::watchFD:
               {
                  if (index >= watches.size() || watches[index] == nullptr)
                  {
                     return Result::protocol;
                  }

                  std::unique_ptr<WatchOperation> watch = std::move(watches[index]);
                  if (result < 0)
                  {
                     return Result::io;
                  }

                  if (watch->checkConnect)
                  {
                     int socketError = 0;
                     socklen_t socketErrorSize = sizeof(socketError);
                     if (::getsockopt(watch->fd, SOL_SOCKET, SO_ERROR, &socketError, &socketErrorSize) != 0)
                     {
                        return Result::io;
                     }

                     if (socketError != 0)
                     {
                        errno = socketError;
                        return Result::io;
                     }
                  }

                  event = std::move(watch->event);
                  return Result::ok;
               }
            }
         }
      }
   };
}
