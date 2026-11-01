#pragma once

#include <fcntl.h>
#include <net/if.h>
#include <sys/stat.h>
#include <unistd.h>

#include <networking/includes.h>

// The selection is a root-owned host policy, shared by the Neuron that
// attaches it and Mothership's narrowly scoped retirement tool.
static inline bool prodigyResolveOptionalInterfaceDevice(const char *path, String& device, String *failureReport = nullptr)
{
  device.clear();
  int fd = ::open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) {
    if (errno == ENOENT) return true;
    if (failureReport) failureReport->snprintf<"optional interface configuration open failed errno={itoa}"_ctv>(uint32_t(errno));
    return false;
  }
  struct stat metadata = {};
  char value[IF_NAMESIZE + 2] = {};
  ssize_t bytes = ::read(fd, value, sizeof(value));
  const int readErrno = errno;
  const bool safe = ::fstat(fd, &metadata) == 0 && S_ISREG(metadata.st_mode) && metadata.st_uid == 0 &&
                    (metadata.st_mode & 0022) == 0 && metadata.st_nlink == 1 && bytes > 0 && bytes < ssize_t(sizeof(value));
  ::close(fd);
  if (!safe) { if (failureReport) failureReport->snprintf<"optional interface configuration rejected errno={itoa}"_ctv>(uint32_t(readErrno)); return false; }
  if (value[bytes - 1] == '\n') { --bytes; value[bytes] = '\0'; }
  if (bytes == 0 || bytes >= IF_NAMESIZE || value[bytes] != '\0') { if (failureReport) failureReport->assign("optional interface name is invalid"_ctv); return false; }
  for (ssize_t index = 0; index < bytes; ++index) {
    const unsigned char c = static_cast<unsigned char>(value[index]);
    if (!(c == '_' || c == '-' || (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'))) {
      if (failureReport) failureReport->assign("optional interface name is invalid"_ctv); return false;
    }
  }
  device.assign(value, bytes);
  return true;
}

static inline bool prodigyResolveOptionalAdditionalIngressDevice(String& device, String *failureReport = nullptr)
{
  return prodigyResolveOptionalInterfaceDevice("/etc/prodigy/additional-ingress-interface", device, failureReport);
}

// A physical private-overlay link is separately selected from the decrypted
// tunnel veth above. Both selections are root-owned files: no control-plane
// input may choose a host attachment point.
static inline bool prodigyResolveOptionalPrivateOverlayDevice(String& device, String *failureReport = nullptr)
{
  return prodigyResolveOptionalInterfaceDevice("/etc/prodigy/private-overlay-interface", device, failureReport);
}
