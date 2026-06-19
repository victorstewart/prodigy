#pragma once

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>

#include <services/filesystem.h>

enum class SystemContainerKind : uint8_t {
  none = 0,
  mothershipTunnelProvider = 1
};

constexpr static uint8_t prodigyMothershipTunnelProviderRuntimeFragment = 254;
constexpr static uint32_t prodigyMothershipTunnelProviderRuntimeUID = 65'535u * uint32_t(prodigyMothershipTunnelProviderRuntimeFragment);

static inline String prodigyContainerErrnoString(int err)
{
  String text = {};
  text.assign(strerror(err));
  return text;
}

constexpr static uint32_t prodigyDiscombobulatorAppContractVersion = 1;
constexpr static uint32_t prodigyDiscombobulatorMothershipTunnelProviderContractVersion = 1;

static inline String prodigyDiscombobulatorBlobHeaderText(void)
{
  String text = {};
  text.assign("PRODIGY-DISCOMBOBULATOR-APP-CONTAINER\n"_ctv);
  text.append("contract=prodigy-container-artifact\n"_ctv);
  text.append("contract_version=1\n"_ctv);
  text.append("\n"_ctv);
  return text;
}

static inline String prodigyDiscombobulatorMothershipTunnelProviderBlobHeaderText(void)
{
  String text = {};
  text.assign("PRODIGY-DISCOMBOBULATOR-MOTHERSHIP-TUNNEL-PROVIDER\n"_ctv);
  text.append("contract=prodigy-mothership-tunnel-provider\n"_ctv);
  text.append("contract_version=1\n"_ctv);
  text.append("container_kind=mothershipTunnelProvider\n"_ctv);
  text.append("requires_standard_neuron_socket=false\n"_ctv);
  text.append("requires_mothership_tunnel_gateway=true\n"_ctv);
  text.append("network_policy=tcpEgressOnly\n"_ctv);
  text.append("\n"_ctv);
  return text;
}

static inline bool prodigyValidateDiscombobulatorBlobHeaderText(
    const String& header,
    String *failureReport = nullptr)
{
  if (header.equal(prodigyDiscombobulatorBlobHeaderText()) == false)
  {
    if (failureReport)
    {
      failureReport->assign("container blob is missing the supported Discombobulator app-container contract header"_ctv);
    }
    return false;
  }

  return true;
}

static inline bool prodigyValidateDiscombobulatorMothershipTunnelProviderBlobHeaderText(
    const String& header,
    String *failureReport = nullptr)
{
  if (header.equal(prodigyDiscombobulatorMothershipTunnelProviderBlobHeaderText()) == false)
  {
    if (failureReport)
    {
      failureReport->assign("container blob is missing the supported Discombobulator mothership tunnel-provider contract header"_ctv);
    }
    return false;
  }

  return true;
}

static inline bool prodigyOpenBlobPayloadAfterContractHeaderText(
    const String& blobPath,
    const String& expectedHeader,
    const char *contractDescription,
    int& fd,
    String *failureReport = nullptr)
{
  fd = -1;

  String blobPathText = {};
  blobPathText.assign(blobPath);
  int openedFD = open(blobPathText.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (openedFD < 0)
  {
    if (failureReport)
    {
      int err = errno;
      failureReport->snprintf<"failed to open container blob {} errno={itoa}({})"_ctv>(blobPath, uint64_t(err), prodigyContainerErrnoString(err));
    }
    return false;
  }

  String actualHeader = {};
  actualHeader.need(expectedHeader.size());
  uint64_t readBytes = 0;
  while (readBytes < expectedHeader.size())
  {
    char buffer[128];
    uint64_t remaining = expectedHeader.size() - readBytes;
    uint64_t chunk = remaining < sizeof(buffer) ? remaining : sizeof(buffer);
    ssize_t result = read(openedFD, buffer, size_t(chunk));
    if (result > 0)
    {
      actualHeader.append(buffer, uint64_t(result));
      readBytes += uint64_t(result);
      continue;
    }

    if (result == 0)
    {
      if (failureReport)
      {
        failureReport->snprintf<"container blob is missing the supported Discombobulator {} contract header: ended before header completed"_ctv>(String(contractDescription));
      }
      close(openedFD);
      return false;
    }

    if (errno == EINTR)
    {
      continue;
    }

    if (failureReport)
    {
      int err = errno;
      failureReport->snprintf<"failed to read container blob contract header errno={itoa}({})"_ctv>(uint64_t(err), prodigyContainerErrnoString(err));
    }
    close(openedFD);
    return false;
  }

  if (actualHeader.equal(expectedHeader) == false)
  {
    if (failureReport)
    {
      failureReport->snprintf<"container blob is missing the supported Discombobulator {} contract header"_ctv>(String(contractDescription));
    }
    close(openedFD);
    return false;
  }

  fd = openedFD;
  return true;
}

static inline bool prodigyOpenContainerBlobPayloadAfterContractHeader(
    const String& blobPath,
    int& fd,
    String *failureReport = nullptr)
{
  return prodigyOpenBlobPayloadAfterContractHeaderText(
      blobPath,
      prodigyDiscombobulatorBlobHeaderText(),
      "app-container",
      fd,
      failureReport);
}

static inline bool prodigyOpenMothershipTunnelProviderBlobPayloadAfterContractHeader(
    const String& blobPath,
    int& fd,
    String *failureReport = nullptr)
{
  return prodigyOpenBlobPayloadAfterContractHeaderText(
      blobPath,
      prodigyDiscombobulatorMothershipTunnelProviderBlobHeaderText(),
      "mothership tunnel-provider",
      fd,
      failureReport);
}

static inline bool prodigyValidateDiscombobulatorContainerBlobHeader(
    const String& blobPath,
    String *failureReport = nullptr)
{
  int fd = -1;
  if (prodigyOpenContainerBlobPayloadAfterContractHeader(blobPath, fd, failureReport) == false)
  {
    return false;
  }

  close(fd);
  return true;
}

static inline bool prodigyValidateMothershipTunnelProviderBlobHeader(
    const String& blobPath,
    String *failureReport = nullptr)
{
  int fd = -1;
  if (prodigyOpenMothershipTunnelProviderBlobPayloadAfterContractHeader(blobPath, fd, failureReport) == false)
  {
    return false;
  }

  close(fd);
  return true;
}
