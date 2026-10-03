#pragma once

// Shared artifact approval owner. Mothership calls this before planning;
// Brain calls it on its ArtifactIO worker before publishing an admitted bundle.
#include <prodigy/bundle.artifact.h>
#include <prodigy/mothership/mothership.upgrade.contract.h>

class ProdigyApprovedUpgradeBundle {
public:
  String bundleSHA256 = {};
  MothershipUpgradeEnvelope envelope = {};
  MothershipUpgradeContract contract = {};
  String retainedSnapshotPath = {};

  ProdigyApprovedUpgradeBundle(void) = default;
  ProdigyApprovedUpgradeBundle(const ProdigyApprovedUpgradeBundle&) = delete;
  ProdigyApprovedUpgradeBundle& operator=(const ProdigyApprovedUpgradeBundle&) = delete;
  ~ProdigyApprovedUpgradeBundle(void) { reset(); }

  void reset(void)
  {
    if (!retainedSnapshotPath.empty()) (void)::unlink(retainedSnapshotPath.c_str());
    retainedSnapshotPath.clear(); bundleSHA256.clear(); envelope = {}; contract = {};
  }

  bool verifyRetainedSnapshot(String *failure = nullptr) const
  {
    String digest = {};
    if (retainedSnapshotPath.empty() || !prodigyComputeFileSHA256Hex(retainedSnapshotPath, digest, failure) ||
        digest != bundleSHA256)
    {
      if (failure && failure->empty()) failure->assign("approved bundle snapshot changed or is unavailable"_ctv);
      return false;
    }
    return true;
  }
};

static inline bool prodigyExtractFlatBundleEntry(const String& bundlePath, const String& entry,
                                                 String& temporaryPath, uint64_t maximumBytes, String *failure = nullptr)
{
  temporaryPath.assign("/tmp/prodigy-bundle-entry.XXXXXX"_ctv);
  temporaryPath.addNullTerminator();
  int fd = ::mkstemp(reinterpret_cast<char *>(temporaryPath.data()));
  if (fd < 0) { temporaryPath.clear(); if (failure) failure->assign("bundle entry extraction temporary file creation failed"_ctv); return false; }
  (void)::close(fd);
  temporaryPath = temporaryPath.substr(0, std::strlen(temporaryPath.c_str()), Copy::yes);
  String command;
  // bash's file-size limit uses KiB. Bound the writer itself; checking stat
  // only after extraction would let a compressed member exhaust local disk.
  command.snprintf<"ulimit -f {itoa}; exec tar --zstd -xOf "_ctv>((maximumBytes + 1023) / 1024);
  prodigyAppendShellSingleQuoted(command, bundlePath);
  command.append(" "_ctv); prodigyAppendShellSingleQuoted(command, entry);
  command.append(" > "_ctv); prodigyAppendShellSingleQuoted(command, temporaryPath);
  if (!prodigyRunLocalShellCommand(command, failure)) { (void)::unlink(temporaryPath.c_str()); temporaryPath.clear(); return false; }
  struct stat metadata = {};
  if (::stat(temporaryPath.c_str(), &metadata) != 0 || !S_ISREG(metadata.st_mode) || metadata.st_size <= 0 || uint64_t(metadata.st_size) > maximumBytes) { (void)::unlink(temporaryPath.c_str()); temporaryPath.clear(); if (failure) failure->assign("bundle entry extraction exceeded its size bound or was not a nonempty regular file"_ctv); return false; }
  return true;
}

static inline bool prodigyExtractFlatBundleEntryEitherPrefix(const String& bundlePath, const String& entry,
                                                             String& path, uint64_t maximumBytes, String *failure = nullptr)
{
  if (prodigyExtractFlatBundleEntry(bundlePath, entry, path, maximumBytes, failure)) return true;
  String prefixed;
  prefixed.append("./"_ctv); prefixed.append(entry);
  return prodigyExtractFlatBundleEntry(bundlePath, prefixed, path, maximumBytes, failure);
}

static inline bool prodigyApproveBundleUpgradeContract(const String& bundlePath,
                                                       ProdigyApprovedUpgradeBundle& approved,
                                                       String *failure = nullptr)
{
  approved.reset(); if (failure) failure->clear();
  if (!prodigyApproveBundleArtifact(bundlePath, approved.bundleSHA256, failure)) return false;
  String snapshotPath, contractPath, prodigyPath, mothershipPath, contractBytes;
  auto cleanup = [&] { if (!snapshotPath.empty()) (void)::unlink(snapshotPath.c_str()); if (!contractPath.empty()) (void)::unlink(contractPath.c_str()); if (!prodigyPath.empty()) (void)::unlink(prodigyPath.c_str()); if (!mothershipPath.empty()) (void)::unlink(mothershipPath.c_str()); };
  // Every entry must come from the same approved bytes. Reopening the caller's
  // pathname for each tar invocation would permit a changed bundle to mix an
  // approved digest with a different contract or component.
  snapshotPath.assign("/tmp/prodigy-approved-bundle.XXXXXX"_ctv);
  snapshotPath.addNullTerminator();
  int snapshotFD = ::mkstemp(reinterpret_cast<char *>(snapshotPath.data()));
  if (snapshotFD < 0)
  {
    snapshotPath.clear();
    if (failure) failure->assign("approved bundle snapshot creation failed"_ctv);
    return false;
  }
  (void)::close(snapshotFD);
  snapshotPath = snapshotPath.substr(0, std::strlen(snapshotPath.c_str()), Copy::yes);
  String copyCommand, snapshotDigest;
  copyCommand.assign("cp --reflink=auto -- "_ctv);
  prodigyAppendShellSingleQuoted(copyCommand, bundlePath);
  copyCommand.append(" "_ctv);
  prodigyAppendShellSingleQuoted(copyCommand, snapshotPath);
  if (!prodigyRunLocalShellCommand(copyCommand, failure) ||
      ::chmod(snapshotPath.c_str(), 0400) != 0 ||
      !prodigyComputeFileSHA256Hex(snapshotPath, snapshotDigest, failure) ||
      snapshotDigest != approved.bundleSHA256)
  {
    if (failure && failure->empty()) failure->assign("bundle changed after local approval"_ctv);
    cleanup();
    approved.reset();
    return false;
  }
  constexpr uint64_t maximumContractBytes = 256 * 1024;
  constexpr uint64_t maximumExecutableBytes = 1024ULL * 1024 * 1024;
  if (!prodigyExtractFlatBundleEntryEitherPrefix(snapshotPath, "containers/plans/upgrade-compatibility.json"_ctv, contractPath, maximumContractBytes, failure) ||
      !prodigyExtractFlatBundleEntryEitherPrefix(snapshotPath, "prodigy"_ctv, prodigyPath, maximumExecutableBytes, failure) ||
      !prodigyExtractFlatBundleEntryEitherPrefix(snapshotPath, "tools/mothership"_ctv, mothershipPath, maximumExecutableBytes, failure)) { cleanup(); approved.reset(); return false; }
  Filesystem::openReadAtClose(-1, contractPath, contractBytes, maximumContractBytes + 1);
  if (contractBytes.empty() || contractBytes.size() > maximumContractBytes || !prodigyComputeSHA256Hex(contractBytes, approved.envelope.contractSHA256, failure) || !prodigyComputeFileSHA256Hex(prodigyPath, approved.envelope.prodigySHA256, failure) || !prodigyComputeFileSHA256Hex(mothershipPath, approved.envelope.mothershipSHA256, failure)) { if (failure && failure->empty()) failure->assign("upgrade contract or bundle component extraction failed"_ctv); cleanup(); approved.reset(); return false; }
  approved.envelope.approvedByBundleOwner = true;
  approved.envelope.approvedBundleSHA256 = approved.bundleSHA256;
  const bool parsed = mothershipParseUpgradeContract(contractBytes, approved.envelope, approved.contract, failure);
  if (parsed)
  {
    approved.retainedSnapshotPath = snapshotPath;
    snapshotPath.clear();
  }
  cleanup(); if (!parsed) approved.reset(); return parsed;
}

// Artifact policy validation is shared by Mothership and Brain. It does not
// replace a fresh authority observation or the durable admission record.
static inline bool prodigyValidateSameClusterUpgradeTarget(
    const ProdigyApprovedUpgradeBundle& approved,
    const String& observedTargetArchitecture,
    uint128_t targetClusterUUID,
    String *failure = nullptr)
{
  if (failure) failure->clear();

  if (!mothershipUpgradeValidEnvelope(approved.envelope) ||
      approved.envelope.approvedBundleSHA256 != approved.bundleSHA256 ||
      approved.contract.contractSHA256 != approved.envelope.contractSHA256)
  {
    if (failure) failure->assign("approved bundle contract envelope is incomplete"_ctv);
    return false;
  }

  if (!mothershipUpgradeCanonicalArchitecture(observedTargetArchitecture) ||
      observedTargetArchitecture != approved.contract.architecture)
  {
    if (failure) failure->assign("observed target architecture does not match approved upgrade contract"_ctv);
    return false;
  }

  if (targetClusterUUID == 0)
  {
    if (failure) failure->assign("target cluster UUID is unavailable for update admission"_ctv);
    return false;
  }

  if (approved.contract.disposition == MothershipUpgradeDisposition::unsupported)
  {
    if (failure) failure->assign("approved target release declares upgrades unsupported"_ctv);
    return false;
  }

  if (approved.contract.disposition == MothershipUpgradeDisposition::newClusterRequired)
  {
    if (failure) failure->assign("approved target release requires independent-cluster migration"_ctv);
    return false;
  }

  if (!approved.contract.compatibility.allCompatible())
  {
    if (failure) failure->assign("approved target release lacks full same-cluster compatibility"_ctv);
    return false;
  }

  if (approved.contract.transportIdentityMode != "preserveClusterIdentity"_ctv)
  {
    if (failure) failure->assign("approved target release does not preserve cluster transport identity"_ctv);
    return false;
  }

  return true;
}

static inline bool prodigyValidateSameClusterUpgradeRelease(
    const ProdigyApprovedUpgradeBundle& approved,
    const String& observedTargetArchitecture,
    uint128_t targetClusterUUID,
    const MothershipUpgradeIdentity *observedSource,
    bool observedCurrentUpdaterSupportsSerialFollowers,
    String *failure = nullptr)
{
  if (!prodigyValidateSameClusterUpgradeTarget(approved, observedTargetArchitecture,
                                              targetClusterUUID, failure)) return false;

  if (observedSource == nullptr)
  {
    if (failure) failure->assign("observed source release identity is unavailable; typed Brain report is required"_ctv);
    return false;
  }

  if (!mothershipUpgradeDeclaredSource(approved.contract, *observedSource))
  {
    if (failure) failure->assign("observed source release identity is not declared by approved target contract"_ctv);
    return false;
  }

  if (!observedCurrentUpdaterSupportsSerialFollowers)
  {
    if (failure) failure->assign("current updater serial-follower capability is unqualified; typed Brain report is required"_ctv);
    return false;
  }

  return true;
}

static inline bool prodigyPreflightLegacySameClusterUpdate(
    const ProdigyApprovedUpgradeBundle& approved,
    const String& observedTargetArchitecture,
    uint128_t targetClusterUUID,
    const MothershipUpgradeIdentity *observedSource,
    bool observedCurrentUpdaterSupportsSerialFollowers,
    String *failure = nullptr)
{
  if (!prodigyValidateSameClusterUpgradeRelease(approved, observedTargetArchitecture,
      targetClusterUUID, observedSource, observedCurrentUpdaterSupportsSerialFollowers, failure)) return false;

  // This command has no durable operation ID or immutable admission receipt.
  // Never treat a locally computed preflight as rollout authorization.
  if (failure) failure->assign("legacy updateProdigy requires a persisted typed admission record before dispatch"_ctv);
  return false;
}
