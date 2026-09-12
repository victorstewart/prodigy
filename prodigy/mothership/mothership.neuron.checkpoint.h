#pragma once

#include <prodigy/persistent.state.h>
#include <prodigy/ingress.validation.h>
#include <prodigy/wire.h>
#include <ebpf/common/structs.h>
#include <prodigy/transport.tls.h>
#include <networking/message.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/time.h>

using MothershipNeuronCheckpointReady = bool (*)(void *context, ProdigyLocalContainerCheckpoint& checkpoint, String *failure);

static inline bool mothershipNeuronCheckpointReadExact(SSL *tls, uint8_t *data, uint64_t size)
{
  while (size > 0)
  {
    int received = SSL_read(tls, data, int(std::min<uint64_t>(size, INT_MAX)));
    if (received <= 0) return false;
    data += received;
    size -= uint64_t(received);
  }
  return true;
}

static inline bool mothershipNeuronCheckpointWriteExact(SSL *tls, const uint8_t *data, uint64_t size)
{
  while (size > 0)
  {
    int sent = SSL_write(tls, data, int(std::min<uint64_t>(size, INT_MAX)));
    if (sent <= 0) return false;
    data += sent;
    size -= uint64_t(sent);
  }
  return true;
}

static inline bool mothershipNeuronCheckpointReadFrame(SSL *tls, String& frame, String *failure)
{
  constexpr uint32_t headerBytes = sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint8_t) + sizeof(uint8_t);
  uint8_t header[headerBytes] = {};
  if (mothershipNeuronCheckpointReadExact(tls, header, sizeof(header)) == false)
  {
    if (failure) failure->assign("neuron checkpoint receive header failed"_ctv);
    return false;
  }
  uint32_t size = 0;
  memcpy(&size, header, sizeof(size));
  if (size < headerBytes || size > ProdigyWire::maxControlFrameBytes)
  {
    if (failure) failure->assign("neuron checkpoint frame size invalid"_ctv);
    return false;
  }
  frame.clear();
  frame.append(header, sizeof(header));
  if (size > headerBytes)
  {
    if (frame.reserve(size) == false)
    {
      if (failure) failure->assign("neuron checkpoint frame allocation failed"_ctv);
      return false;
    }
    frame.resize(size);
    if (mothershipNeuronCheckpointReadExact(tls, frame.data() + headerBytes, size - headerBytes) == false)
    {
      if (failure) failure->assign("neuron checkpoint receive body failed"_ctv);
      return false;
    }
  }
  return true;
}

static inline bool mothershipNeuronCheckpointDecodeStateUpload(const String& frame, ProdigyLocalContainerCheckpoint& checkpoint, String *failure)
{
  if (frame.size() < sizeof(Message))
  {
    if (failure) failure->assign("neuron checkpoint state frame too small"_ctv);
    return false;
  }
  Message *message = reinterpret_cast<Message *>(const_cast<uint8_t *>(frame.data()));
  if (message->size != frame.size() || message->padding > message->size)
  {
    if (failure) failure->assign("neuron checkpoint state frame bounds invalid"_ctv);
    return false;
  }
  if (NeuronTopic(message->topic) != NeuronTopic::stateUpload ||
      ProdigyIngressValidation::validateNeuronPayloadForBrain(message->topic, message->args, message->terminal()) == false)
  {
    if (failure) failure->assign("neuron checkpoint state frame invalid"_ctv);
    return false;
  }
  uint8_t *args = message->args;
  ProdigyLocalContainerCheckpoint decoded = {};
  struct local_container_subnet6 fragment = {};
  Message::extractBytes<Alignment::one>(args, reinterpret_cast<uint8_t *>(&fragment), sizeof(fragment));
  decoded.datacenterFragment = fragment.dpfx;
  decoded.machineFragment = (uint32_t(fragment.mpfx[0]) << 16) | (uint32_t(fragment.mpfx[1]) << 8) | uint32_t(fragment.mpfx[2]);
  while (args < message->terminal())
  {
    String serialized = {};
    Message::extractToStringView(args, serialized);
    ContainerPlan plan = {};
    if (BitseryEngine::deserializeSafe(serialized, plan) == false || plan.uuid == 0)
    {
      if (failure) failure->assign("neuron checkpoint container plan invalid"_ctv);
      return false;
    }
    decoded.plans.push_back(std::move(plan));
  }
  checkpoint = std::move(decoded);
  return true;
}

// The caller provides TLS material from a private crash-consistent local Brain
// state copy. ready() fences the exact runtime before this releases Neuron control.
static inline bool mothershipCaptureNeuronCheckpoint(
    const ProdigyPersistentLocalBrainState& localBrainState,
    const String& targetIPv6,
    const String& expectedBundleDigest,
    ProdigyLocalContainerCheckpoint& checkpoint,
    MothershipNeuronCheckpointReady ready,
    void *readyContext,
    String *failure = nullptr)
{
  if (failure) failure->clear();
  checkpoint = {};
  if (localBrainState.transportTLSConfigured() == false || targetIPv6.empty() || expectedBundleDigest.empty() || ready == nullptr)
  {
    if (failure) failure->assign("neuron checkpoint input incomplete"_ctv);
    return false;
  }
  ProdigyPersistentLocalBrainState recoveryIdentity = localBrainState;
  recoveryIdentity.uuid = Random::generateNumberWithNBits<128, uint128_t>();
  Vector<String> addresses = {};
  if (prodigyGenerateTransportNodeCertificateEd25519(localBrainState.transportTLS.clusterRootCertPem, localBrainState.transportTLS.clusterRootKeyPem, recoveryIdentity.uuid, addresses, recoveryIdentity.transportTLS.localCertPem, recoveryIdentity.transportTLS.localKeyPem, failure) == false) return false;
  ProdigyTransportTLSBootstrap bootstrap = {};
  prodigyBuildTransportTLSBootstrap(recoveryIdentity, bootstrap);
  if (ProdigyTransportTLSRuntime::configure(bootstrap, failure) == false) return false;

  int fd = ::socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0);
  struct sockaddr_in6 address = {};
  address.sin6_family = AF_INET6;
  address.sin6_port = htons(uint16_t(ReservedPorts::neuron));
  struct timeval timeout = {15, 0};
  (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
  if (fd < 0 || inet_pton(AF_INET6, const_cast<String &>(targetIPv6).c_str(), &address.sin6_addr) != 1 ||
      ::connect(fd, reinterpret_cast<const sockaddr *>(&address), sizeof(address)) != 0)
  {
    if (fd >= 0) ::close(fd);
    if (failure) failure->assign("neuron checkpoint connect failed"_ctv);
    return false;
  }
  SSL *tls = SSL_new(ProdigyTransportTLSRuntime::context());
  bool okay = tls != nullptr && SSL_set_fd(tls, fd) == 1 && SSL_connect(tls) == 1 && SSL_get_verify_result(tls) == X509_V_OK;
  uint128_t peerUUID = 0;
  if (okay && (ProdigyTransportTLSRuntime::extractPeerUUID(tls, peerUUID) == false || peerUUID != localBrainState.uuid))
  {
    if (failure) failure->assign("neuron checkpoint TLS machine identity mismatch"_ctv);
    okay = false;
  }
  if (okay == false)
  {
    if (tls) SSL_free(tls);
    ::close(fd);
    if (failure) failure->assign("neuron checkpoint transport TLS failed"_ctv);
    return false;
  }

  bool sawRegistration = false;
  String frame = {};
  for (uint32_t frameCount = 0; okay && frameCount < 64; frameCount += 1)
  {
    if (mothershipNeuronCheckpointReadFrame(tls, frame, failure) == false) { okay = false; break; }
    Message *message = reinterpret_cast<Message *>(frame.data());
    if (NeuronTopic(message->topic) == NeuronTopic::registration)
    {
      if (ProdigyIngressValidation::validateNeuronPayloadForBrain(message->topic, message->args, message->terminal()) == false)
      {
        if (failure) failure->assign("neuron checkpoint registration invalid"_ctv);
        okay = false;
        break;
      }
      uint8_t *args = message->args;
      uint64_t bootTime = 0;
      String kernel = {}, osID = {}, osVersion = {}, digest = {};
      bool haveFragments = false;
      Message::extractArg<ArgumentNature::fixed>(args, bootTime);
      Message::extractToStringView(args, kernel);
      Message::extractToStringView(args, osID);
      Message::extractToStringView(args, osVersion);
      Message::extractArg<ArgumentNature::fixed>(args, haveFragments);
      Message::extractToStringView(args, digest);
      (void)bootTime; (void)kernel; (void)osID; (void)osVersion; (void)haveFragments;
      if (digest != expectedBundleDigest)
      {
        if (failure) failure->assign("neuron checkpoint bundle digest mismatch"_ctv);
        okay = false;
        break;
      }
      String request = {};
      Message::construct(request, NeuronTopic::registration, true);
      if (mothershipNeuronCheckpointWriteExact(tls, request.data(), request.size()) == false)
      {
        if (failure) failure->assign("neuron checkpoint state request failed"_ctv);
        okay = false;
      }
      sawRegistration = true;
      continue;
    }
    if (NeuronTopic(message->topic) == NeuronTopic::stateUpload)
    {
      if (sawRegistration == false || mothershipNeuronCheckpointDecodeStateUpload(frame, checkpoint, failure) == false)
      {
        okay = false;
      }
      else
      {
        checkpoint.machineUUID = peerUUID;
        if (ready(readyContext, checkpoint, failure) == false) okay = false;
      }
      break;
    }
  }
  // The freeze callback may have stopped the peer; do not wait for a TLS close-notify.
  SSL_free(tls);
  ::close(fd);
  if (okay == false && failure && failure->empty()) failure->assign("neuron checkpoint capture incomplete"_ctv);
  return okay;
}
