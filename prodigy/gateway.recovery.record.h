#pragma once

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <linux/openat2.h>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>

#include <services/filesystem.h>
#include <prodigy/types.h>

inline constexpr uint64_t prodigySecureContainerResolveFlags =
    RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS;

static inline bool prodigyParseDecimal128(std::string_view text, uint128_t& value)
{
  value = 0;
  if (text.empty())
  {
    return false;
  }
  constexpr uint128_t maximum = ~uint128_t(0);
  for (const char digitCharacter : text)
  {
    if (digitCharacter < '0' || digitCharacter > '9')
    {
      return false;
    }
    uint8_t digit = uint8_t(digitCharacter - '0');
    if (value > (maximum - digit) / 10)
    {
      return false;
    }
    value = value * 10 + digit;
  }
  return true;
}

namespace ProdigyGatewayRecovery {

// This root-owned record is consumed by a replacement binary, so its bytes
// cannot depend on compiler padding or host integer layout. All integers are
// big-endian and the reserved bytes must remain zero.
struct GatewayRecoveryRecord {
  uint8_t version = 1;
  uint8_t reserved[7] = {};
  uint8_t containerUUID[16] = {}, pairUUID[16] = {};
  uint8_t localClusterUUID[16] = {}, localMachineUUID[16] = {};
  uint8_t keyEpoch[8] = {}, authorityGeneration[8] = {}, gatewayGeneration[8] = {};
  char token[32] = {};
};
static_assert(sizeof(GatewayRecoveryRecord) == 128);

template <typename Integer, size_t N>
static void encodeGatewayRecoveryInteger(Integer value, uint8_t (&encoded)[N])
{
  for (size_t i = N; i > 0; --i)
  {
    encoded[i - 1] = uint8_t(value & Integer(0xff));
    value >>= 8;
  }
}

static inline GatewayRecoveryRecord makeGatewayRecoveryRecord(const ContainerPlan& plan, const String& token)
{
  GatewayRecoveryRecord record = {};
  encodeGatewayRecoveryInteger(plan.uuid, record.containerUUID);
  encodeGatewayRecoveryInteger(plan.system.gatewayPairUUID, record.pairUUID);
  encodeGatewayRecoveryInteger(plan.system.gatewayLocalClusterUUID, record.localClusterUUID);
  encodeGatewayRecoveryInteger(plan.system.gatewayLocalMachineUUID, record.localMachineUUID);
  encodeGatewayRecoveryInteger(plan.system.gatewayKeyEpoch, record.keyEpoch);
  encodeGatewayRecoveryInteger(plan.system.gatewayAuthorityGeneration, record.authorityGeneration);
  encodeGatewayRecoveryInteger(plan.system.gatewayGeneration, record.gatewayGeneration);
  memcpy(record.token, token.data(), sizeof(record.token));
  return record;
}

static inline bool readGatewayRecoveryRecordFD(int fd, GatewayRecoveryRecord& record)
{
  uint8_t *bytes = reinterpret_cast<uint8_t *>(&record);
  size_t offset = 0;
  while (offset < sizeof(record))
  {
    const ssize_t result = pread(fd, bytes + offset, sizeof(record) - offset, off_t(offset));
    if (result > 0) { offset += size_t(result); continue; }
    if (result < 0 && errno == EINTR) continue;
    return false;
  }
  uint8_t trailing = 0;
  return pread(fd, &trailing, 1, off_t(sizeof(record))) == 0;
}

static inline bool gatewayRecoveryTokenValid(const String& token)
{
  if (token.size() != 32) return false;
  for (uint64_t i = 0; i < token.size(); ++i)
    if (!((token[i] >= '0' && token[i] <= '9') || (token[i] >= 'a' && token[i] <= 'f'))) return false;
  return true;
}

static inline bool gatewayRecoveryRecordMatches(const GatewayRecoveryRecord& record, const ContainerPlan& plan)
{
  String storedToken = {};
  storedToken.assign(record.token, sizeof(record.token));
  if (record.version != 1 || !gatewayRecoveryTokenValid(storedToken)) return false;
  for (uint8_t value : record.reserved) if (value != 0) return false;
  const GatewayRecoveryRecord expected = makeGatewayRecoveryRecord(plan, storedToken);
  return memcmp(&record, &expected, sizeof(record)) == 0;
}

static inline bool readGatewayRecoveryRecordAt(
    int rootFD, const ContainerPlan& plan, String& token)
{
  token.clear();
  String name = {};
  name.assignItoa(plan.uuid);
  const int directoryFD = Filesystem::openDirectoryAt(
      rootFD, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC, prodigySecureContainerResolveFlags);
  if (directoryFD < 0) return false;
  const int fd = openat(directoryFD, "masque-gateway-recovery.v1", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  close(directoryFD);
  if (fd < 0) return false;

  struct stat info = {};
  GatewayRecoveryRecord record = {};
  const bool matches = fstat(fd, &info) == 0 && S_ISREG(info.st_mode) && info.st_uid == 0 &&
      info.st_nlink == 1 && (info.st_mode & 07777) == 0600 && info.st_size == off_t(sizeof(record)) &&
      readGatewayRecoveryRecordFD(fd, record) && gatewayRecoveryRecordMatches(record, plan);
  close(fd);
  if (!matches) return false;
  token.assign(record.token, sizeof(record.token));
  return true;
}

// A missing application descriptor can only be explained by a gateway if the
// same UUID has no conflicting regular application in the retained inventory.
static inline bool matchesRetainedGatewayAt(
    int rootFD, const String& containerName, const SystemContainerRuntimePlan& gateway,
    const Vector<BrainReplicatedContainerRuntimeState>& runtimes)
{
  if (!prodigyCrossClusterMasqueGatewayRuntimePlanAuthorityConfigured(gateway)) return false;
  ContainerPlan plan = {};
  const std::string_view decimalName(reinterpret_cast<const char *>(containerName.data()), containerName.size());
  if (!prodigyParseDecimal128(decimalName, plan.uuid) || plan.uuid == 0) return false;
  String name = {};
  name.assignItoa(plan.uuid);
  if (name != containerName) return false;
  for (const auto& runtime : runtimes)
  {
    if (runtime.plan.uuid == plan.uuid &&
        (runtime.machineUUID != gateway.gatewayLocalMachineUUID ||
         runtime.plan.system.kind != SystemContainerKind::crossClusterMasqueGateway ||
         runtime.plan.config.applicationID != 0))
      return false;
  }
  plan.system = gateway;
  String token = {};
  return readGatewayRecoveryRecordAt(rootFD, plan, token);
}
} // namespace ProdigyGatewayRecovery
