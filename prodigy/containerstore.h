#pragma once

#include <prodigy/bundle.artifact.h>
#include <prodigy/container.contract.h>

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

class ContainerStore {
private:

  static inline bytell_hash_set<uint64_t> contents;

  static String errnoString(int err)
  {
    String text = {};
    text.assign(strerror(err));
    return text;
  }

  static String pathForContainerImageWithinRoot(const String& storeRoot, uint64_t deploymentID)
  {
    String path = {};
    path.assign(storeRoot);
    if (path.size() == 0 || path[path.size() - 1] != '/')
    {
      path.append('/');
    }

    String filename = {};
    filename.snprintf<"{itoa}.zst"_ctv>(deploymentID);
    path.append(filename);
    return path;
  }

  static bool writeAll(int fd, const String& payload, String *failureReport = nullptr)
  {
    uint64_t written = 0;
    while (written < payload.size())
    {
      ssize_t result = ::write(fd, payload.data() + written, size_t(payload.size() - written));
      if (result > 0)
      {
        written += uint64_t(result);
        continue;
      }

      if (result < 0 && errno == EINTR)
      {
        continue;
      }

      if (failureReport)
      {
        int err = errno;
        failureReport->snprintf<"blob write failed errno={itoa}({})"_ctv>(uint64_t(err), errnoString(err));
      }
      return false;
    }

    return true;
  }

  static bool fsyncParentDirectory(const String& finalPath, String *failureReport = nullptr)
  {
    String parentPath = {};
    prodigyDirname(finalPath, parentPath);
    if (parentPath.size() == 0)
    {
      if (failureReport)
      {
        failureReport->snprintf<"blob parent directory is missing for {}"_ctv>(finalPath);
      }
      return false;
    }

    int dirfd = Filesystem::openDirectoryAt(-1, parentPath, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dirfd < 0)
    {
      if (failureReport)
      {
        int err = errno;
        failureReport->snprintf<"failed to open blob parent directory {} errno={itoa}({})"_ctv>(parentPath, uint64_t(err), errnoString(err));
      }
      return false;
    }

    bool ok = (::fsync(dirfd) == 0);
    int syncErrno = errno;
    ::close(dirfd);
    if (ok == false && failureReport)
    {
      failureReport->snprintf<"failed to fsync blob parent directory {} errno={itoa}({})"_ctv>(parentPath, uint64_t(syncErrno), errnoString(syncErrno));
    }

    return ok;
  }

  static bool atomicWriteFile(const String& finalPath, const String& payload, String *failureReport = nullptr)
  {
    String parentPath = {};
    prodigyDirname(finalPath, parentPath);
    if (parentPath.size() == 0)
    {
      if (failureReport)
      {
        failureReport->snprintf<"blob parent directory is missing for {}"_ctv>(finalPath);
      }
      return false;
    }

    (void)Filesystem::createDirectoryAt(-1, parentPath, 0755);

    String tempPath = {};
    tempPath.assign(parentPath);
    if (tempPath[tempPath.size() - 1] != '/')
    {
      tempPath.append('/');
    }
    tempPath.append(".containerstore.tmp.XXXXXX"_ctv);
    tempPath.addNullTerminator();

    int fd = ::mkstemp(reinterpret_cast<char *>(tempPath.data()));
    if (fd < 0)
    {
      if (failureReport)
      {
        int err = errno;
        failureReport->snprintf<"failed to create temporary blob path for {} errno={itoa}({})"_ctv>(finalPath, uint64_t(err), errnoString(err));
      }
      return false;
    }

    bool ok = true;
    String createdTempPath = {};
    createdTempPath.assign(reinterpret_cast<const char *>(tempPath.data()));

    if (::fchmod(fd, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) != 0)
    {
      ok = false;
      if (failureReport)
      {
        int err = errno;
        failureReport->snprintf<"failed to chmod temporary blob {} errno={itoa}({})"_ctv>(createdTempPath, uint64_t(err), errnoString(err));
      }
    }

    if (ok && writeAll(fd, payload, failureReport) == false)
    {
      ok = false;
    }

    if (ok && ::fsync(fd) != 0)
    {
      ok = false;
      if (failureReport)
      {
        int err = errno;
        failureReport->snprintf<"failed to fsync temporary blob {} errno={itoa}({})"_ctv>(createdTempPath, uint64_t(err), errnoString(err));
      }
    }

    if (::close(fd) != 0 && ok)
    {
      ok = false;
      if (failureReport)
      {
        int err = errno;
        failureReport->snprintf<"failed to close temporary blob {} errno={itoa}({})"_ctv>(createdTempPath, uint64_t(err), errnoString(err));
      }
    }

    String finalPathText = {};
    finalPathText.assign(finalPath);
    if (ok && ::rename(createdTempPath.c_str(), finalPathText.c_str()) != 0)
    {
      ok = false;
      if (failureReport)
      {
        int err = errno;
        failureReport->snprintf<"failed to rename temporary blob {} -> {} errno={itoa}({})"_ctv>(createdTempPath, finalPath, uint64_t(err), errnoString(err));
      }
    }

    if (ok && fsyncParentDirectory(finalPath, failureReport) == false)
    {
      ok = false;
    }

    if (ok == false)
    {
      (void)::unlink(createdTempPath.c_str());
    }

    return ok;
  }

  static bool verifyStoredBlobAtPath(
      const String& finalPath,
      const String& expectedDigest,
      uint64_t expectedBytes,
      String *actualDigest = nullptr,
      uint64_t *actualBytes = nullptr,
      String *failureReport = nullptr)
  {
    if (failureReport)
    {
      failureReport->clear();
    }
    if (actualDigest)
    {
      actualDigest->clear();
    }
    if (actualBytes)
    {
      *actualBytes = 0;
    }

    if (prodigyFileReadable(finalPath) == false)
    {
      if (failureReport)
      {
        failureReport->snprintf<"container blob is not readable: {}"_ctv>(finalPath);
      }
      return false;
    }

    String computedDigest = {};
    uint64_t computedBytes = 0;
    if (prodigyFileMatchesExpectedSHA256HexAndSize(finalPath, expectedDigest, expectedBytes, computedDigest, &computedBytes, failureReport) == false)
    {
      if (actualDigest)
      {
        *actualDigest = std::move(computedDigest);
      }
      if (actualBytes)
      {
        *actualBytes = computedBytes;
      }
      return false;
    }

    if (actualDigest)
    {
      *actualDigest = std::move(computedDigest);
    }
    if (actualBytes)
    {
      *actualBytes = computedBytes;
    }
    return true;
  }

  static bool storeBlobAtPath(
      const String& finalPath,
      const String& containerBlob,
      String *actualDigest = nullptr,
      uint64_t *actualBytes = nullptr,
      const String *expectedDigest = nullptr,
      const uint64_t *expectedBytes = nullptr,
      String *failureReport = nullptr)
  {
    if (failureReport)
    {
      failureReport->clear();
    }
    if (actualDigest)
    {
      actualDigest->clear();
    }
    if (actualBytes)
    {
      *actualBytes = 0;
    }

    String computedDigest = {};
    if (prodigyComputeSHA256Hex(containerBlob, computedDigest, failureReport) == false)
    {
      return false;
    }

    uint64_t payloadBytes = containerBlob.size();
    if (expectedDigest != nullptr)
    {
      if (prodigyIsSHA256HexDigest(*expectedDigest) == false)
      {
        if (failureReport)
        {
          failureReport->snprintf<"expected container blob sha256 is invalid: {}"_ctv>(*expectedDigest);
        }
        return false;
      }

      if (computedDigest != *expectedDigest)
      {
        if (failureReport)
        {
          failureReport->snprintf<"container blob sha256 mismatch expected={} actual={}"_ctv>(*expectedDigest, computedDigest);
        }
        return false;
      }
    }

    if (expectedBytes != nullptr && payloadBytes != *expectedBytes)
    {
      if (failureReport)
      {
        failureReport->snprintf<"container blob size mismatch expected={itoa} actual={itoa}"_ctv>(*expectedBytes, payloadBytes);
      }
      return false;
    }

    if (atomicWriteFile(finalPath, containerBlob, failureReport) == false)
    {
      return false;
    }

    String verifiedDigest = {};
    uint64_t verifiedBytes = 0;
    if (verifyStoredBlobAtPath(finalPath, computedDigest, payloadBytes, &verifiedDigest, &verifiedBytes, failureReport) == false)
    {
      (void)Filesystem::eraseFile(finalPath);
      (void)fsyncParentDirectory(finalPath);
      return false;
    }

    if (actualDigest != nullptr)
    {
      *actualDigest = std::move(verifiedDigest);
    }

    if (actualBytes != nullptr)
    {
      *actualBytes = verifiedBytes;
    }

    return true;
  }

  static bool storeSystemBlobWithKey(const String& sha256, uint64_t bytes, const String& blob, String *failureReport, const String *storeRoot)
  {
    String root = storeRoot ? *storeRoot : String("/containers/system-store"_ctv);
    String path = pathForSystemArtifactWithinRoot(root, sha256);
    String parent = {};
    prodigyDirname(path, parent);
    (void)Filesystem::createDirectoryAt(-1, root, 0755);
    (void)Filesystem::createDirectoryAt(-1, parent, 0755);
    return atomicWriteFile(path, blob, failureReport);
  }

  static bool validateAppContainerArtifactContract(const String& containerBlob, String *failureReport = nullptr)
  {
    String headerText = prodigyDiscombobulatorBlobHeaderText();
    String header = {};
    header.assign(containerBlob.substr(0, headerText.size(), Copy::yes));
    return prodigyValidateDiscombobulatorBlobHeaderText(header, failureReport);
  }

  static bool storeAppContainerBlobAtPath(
      const String& finalPath,
      const String& containerBlob,
      String *actualDigest = nullptr,
      uint64_t *actualBytes = nullptr,
      const String *expectedDigest = nullptr,
      const uint64_t *expectedBytes = nullptr,
      String *failureReport = nullptr)
  {
    if (failureReport)
    {
      failureReport->clear();
    }
    if (actualDigest)
    {
      actualDigest->clear();
    }
    if (actualBytes)
    {
      *actualBytes = 0;
    }
    if (validateAppContainerArtifactContract(containerBlob, failureReport) == false)
    {
      return false;
    }

    return storeBlobAtPath(finalPath, containerBlob, actualDigest, actualBytes, expectedDigest, expectedBytes, failureReport);
  }

  static bool containsAtPath(uint64_t deploymentID, const String& path)
  {
    if (contents.contains(deploymentID))
    {
      if (prodigyFileReadable(path))
      {
        return true;
      }

      contents.erase(deploymentID);
      return false;
    }

    if (prodigyFileReadable(path))
    {
      contents.insert(deploymentID);
      return true;
    }

    return false;
  }

  static String pathForSystemArtifactWithinRoot(const String& storeRoot, const String& sha256)
  {
    String path = {};
    path.assign(storeRoot);
    if (path.size() == 0 || path[path.size() - 1] != '/')
    {
      path.append('/');
    }
    path.append("mothership-tunnel-provider/"_ctv);
    path.append(sha256);
    path.append(".blob"_ctv);
    return path;
  }

  static bool validateSystemArtifactKey(const String& sha256, uint64_t bytes, String *failureReport = nullptr)
  {
    if (prodigyIsSHA256HexDigest(sha256) == false)
    {
      if (failureReport)
      {
        failureReport->snprintf<"system container sha256 is invalid: {}"_ctv>(sha256);
      }
      return false;
    }
    if (bytes == 0)
    {
      if (failureReport)
      {
        failureReport->assign("system container artifact bytes required"_ctv);
      }
      return false;
    }
    return true;
  }

  static bool validateSystemArtifactContract(const String& blob, String *failureReport = nullptr)
  {
    String headerText = prodigyDiscombobulatorMothershipTunnelProviderBlobHeaderText();
    String header = {};
    header.assign(blob.substr(0, headerText.size(), Copy::yes));
    if (prodigyValidateDiscombobulatorMothershipTunnelProviderBlobHeaderText(header, failureReport) == false)
    {
      return false;
    }
    if (blob.size() <= headerText.size())
    {
      if (failureReport)
      {
        failureReport->assign("system container artifact payload required"_ctv);
      }
      return false;
    }
    return true;
  }

public:

  struct PreparedAppArtifact {
    uint64_t deploymentID = 0;
    String stagePath = {};
    String finalPath = {};
    String sha256 = {};
    uint64_t bytes = 0;
    dev_t device = 0;
    ino_t inode = 0;
    dev_t publishedDevice = 0;
    ino_t publishedInode = 0;
    bool prepared = false;
    bool published = false;
    bool reusedExisting = false;
  };

  // Worker-thread only: validates, writes, fsyncs, and verifies an isolated
  // stage. It deliberately never updates `contents` or the live final path.
  static bool prepareAppArtifactAtPath(
      PreparedAppArtifact& prepared,
      uint64_t deploymentID,
      const String& stagePath,
      const String& containerBlob,
      const String& expectedDigest,
      uint64_t expectedBytes,
      String *failureReport = nullptr,
      const String *storeRoot = nullptr)
  {
    prepared = {};
    String mutableStagePath = {};
    mutableStagePath.assign(stagePath);
    String stageParent = {};
    String finalParent = {};
    String finalPath = storeRoot ? pathForContainerImageWithinRoot(*storeRoot, deploymentID) : pathForContainerImage(deploymentID);
    prodigyDirname(mutableStagePath, stageParent);
    prodigyDirname(finalPath, finalParent);
    if (mutableStagePath.size() == 0 || expectedDigest.size() == 0 || stageParent != finalParent ||
        storeAppContainerBlobAtPath(mutableStagePath, containerBlob, nullptr, nullptr, &expectedDigest, &expectedBytes, failureReport) == false)
    {
      if (stageParent != finalParent && failureReport) failureReport->assign("prepared container artifact must stage in final store directory"_ctv);
      return false;
    }
    struct stat metadata = {};
    if (::stat(mutableStagePath.c_str(), &metadata) != 0)
    {
      if (failureReport) failureReport->assign("prepared container artifact disappeared after verification"_ctv);
      return false;
    }
    prepared.deploymentID = deploymentID;
    prepared.stagePath = mutableStagePath;
    prepared.finalPath = finalPath;
    prepared.sha256 = expectedDigest;
    prepared.bytes = expectedBytes;
    prepared.device = metadata.st_dev;
    prepared.inode = metadata.st_ino;
    prepared.prepared = true;
    return true;
  }

  // Worker-thread only, after the Ring owner has granted publication. Never
  // replaces an existing final path; this prevents a late job overwriting a
  // replacement artifact. Parent fsync remains off the Ring.
  static bool publishPreparedAppArtifact(PreparedAppArtifact& prepared, String *failureReport = nullptr)
  {
    if (prepared.prepared == false || prepared.published ||
        verifyStoredBlobAtPath(prepared.stagePath, prepared.sha256, prepared.bytes, nullptr, nullptr, failureReport) == false)
    {
      return false;
    }
    struct stat stage = {};
    if (::stat(prepared.stagePath.c_str(), &stage) != 0 || stage.st_dev != prepared.device || stage.st_ino != prepared.inode)
    {
      if (failureReport) failureReport->assign("prepared container artifact identity changed before publish"_ctv);
      return false;
    }
    // link(2) is an atomic no-replace publish because stage and final share the
    // store directory. The unlink only removes our verified staging name.
    if (::link(prepared.stagePath.c_str(), prepared.finalPath.c_str()) != 0)
    {
      // Duplicate stores are idempotent only when the existing immutable
      // artifact independently verifies as the exact expected bytes. It is
      // never ours to delete during late completion cleanup.
      if (errno == EEXIST && verifyStoredBlobAtPath(prepared.finalPath, prepared.sha256, prepared.bytes, nullptr, nullptr, failureReport))
      {
        struct stat existing = {};
        if (::stat(prepared.finalPath.c_str(), &existing) == 0)
        {
          prepared.published = true;
          prepared.reusedExisting = true;
          prepared.publishedDevice = existing.st_dev;
          prepared.publishedInode = existing.st_ino;
          if (::unlink(prepared.stagePath.c_str()) == 0)
          {
            return fsyncParentDirectory(prepared.finalPath, failureReport);
          }
        }
      }
      if (failureReport && failureReport->size() == 0)
      {
        int err = errno;
        failureReport->snprintf<"container artifact publish refused errno={itoa}({})"_ctv>(uint64_t(err), errnoString(err));
      }
      return false;
    }
    // From this point finalPath is a store-owned immutable inode, even if
    // staging cleanup below reports an error. It is never rolled back by a
    // stale asynchronous request.
    prepared.published = true;
    prepared.publishedDevice = prepared.device;
    prepared.publishedInode = prepared.inode;
    if (::unlink(prepared.stagePath.c_str()) != 0 || fsyncParentDirectory(prepared.finalPath, failureReport) == false)
    {
      return false;
    }
    struct stat finalMetadata = {};
    if (::stat(prepared.finalPath.c_str(), &finalMetadata) != 0 || finalMetadata.st_dev != prepared.device || finalMetadata.st_ino != prepared.inode)
    {
      if (failureReport) failureReport->assign("published container artifact identity changed"_ctv);
      return false;
    }
    prepared.publishedDevice = finalMetadata.st_dev;
    prepared.publishedInode = finalMetadata.st_ino;
    return true;
  }

  // Ring-thread only, after a second caller authority/epoch check. This is the
  // sole point where an asynchronously published artifact enters the cache.
  static bool adoptPreparedAppArtifact(const PreparedAppArtifact& prepared)
  {
    if (prepared.prepared == false || prepared.published == false) return false;
    String finalPath = {};
    finalPath.assign(prepared.finalPath);
    struct stat metadata = {};
    if (::stat(finalPath.c_str(), &metadata) != 0 || metadata.st_dev != prepared.publishedDevice || metadata.st_ino != prepared.publishedInode) return false;
    contents.insert(prepared.deploymentID);
    return true;
  }

  // Worker-thread only. Before publication, removes only this operation's
  // staging inode. A published immutable final path can be shared by another
  // accepted request, so normal ContainerStore lifecycle owns its removal.
  // Parent fsync stays off the Ring.
  static void discardPreparedAppArtifact(PreparedAppArtifact& prepared)
  {
    String path = {};
    path.assign(prepared.stagePath);
    struct stat metadata = {};
    if (path.size() && ::stat(path.c_str(), &metadata) == 0 &&
        metadata.st_dev == prepared.device && metadata.st_ino == prepared.inode)
    {
      (void)::unlink(path.c_str());
      (void)fsyncParentDirectory(path);
    }
    prepared = {};
  }

  static inline bool autoDestroy; // false if brain, else true

  static bool atomicWriteRuntimeFile(const String& finalPath, const String& payload, String *failureReport = nullptr)
  {
    return atomicWriteFile(finalPath, payload, failureReport);
  }

  static String pathForContainerImage(uint64_t deploymentID, const String *storeRoot = nullptr)
  {
    return pathForContainerImageWithinRoot(storeRoot ? *storeRoot : String("/containers/store"_ctv), deploymentID);
  }

#if PRODIGY_DEBUG
  static String debugPathForContainerImageAtRoot(const String& storeRoot, uint64_t deploymentID)
  {
    return pathForContainerImageWithinRoot(storeRoot, deploymentID);
  }

  static bool debugStoreAtRoot(
      const String& storeRoot,
      uint64_t deploymentID,
      const String& containerBlob,
      String *actualDigest = nullptr,
      uint64_t *actualBytes = nullptr,
      const String *expectedDigest = nullptr,
      const uint64_t *expectedBytes = nullptr,
      String *failureReport = nullptr)
  {
    return storeAppContainerBlobAtPath(
        pathForContainerImageWithinRoot(storeRoot, deploymentID),
        containerBlob,
        actualDigest,
        actualBytes,
        expectedDigest,
        expectedBytes,
        failureReport);
  }

  static bool debugVerifyAtRoot(
      const String& storeRoot,
      uint64_t deploymentID,
      const String& expectedDigest,
      uint64_t expectedBytes,
      String *actualDigest = nullptr,
      uint64_t *actualBytes = nullptr,
      String *failureReport = nullptr)
  {
    return verifyStoredBlobAtPath(
        pathForContainerImageWithinRoot(storeRoot, deploymentID),
        expectedDigest,
        expectedBytes,
        actualDigest,
        actualBytes,
        failureReport);
  }

  static bool debugContainsAtRoot(const String& storeRoot, uint64_t deploymentID)
  {
    return containsAtPath(deploymentID, pathForContainerImageWithinRoot(storeRoot, deploymentID));
  }

  static bool debugCacheContains(uint64_t deploymentID)
  {
    return contents.contains(deploymentID);
  }
#endif

  static void get(uint64_t deploymentID, String& containerBlob)
  {
    Filesystem::openReadAtClose(-1, pathForContainerImage(deploymentID), containerBlob);
  }

  static bool store(
      uint64_t deploymentID,
      const String& containerBlob,
      String *actualDigest = nullptr,
      uint64_t *actualBytes = nullptr,
      const String *expectedDigest = nullptr,
      const uint64_t *expectedBytes = nullptr,
      String *failureReport = nullptr)
  {
    if (storeAppContainerBlobAtPath(
            pathForContainerImage(deploymentID),
            containerBlob,
            actualDigest,
            actualBytes,
            expectedDigest,
            expectedBytes,
            failureReport) == false)
    {
      return false;
    }

    contents.insert(deploymentID);
    return true;
  }

  static bool verify(
      uint64_t deploymentID,
      const String& expectedDigest,
      uint64_t expectedBytes,
      String *actualDigest = nullptr,
      uint64_t *actualBytes = nullptr,
      String *failureReport = nullptr)
  {
    return verifyStoredBlobAtPath(
        pathForContainerImage(deploymentID),
        expectedDigest,
        expectedBytes,
        actualDigest,
        actualBytes,
        failureReport);
  }

  static bool clone(uint64_t sourceDeploymentID, uint64_t targetDeploymentID)
  {
    if (sourceDeploymentID == targetDeploymentID)
    {
      if (contains(targetDeploymentID))
      {
        return true;
      }

      String existingBlob;
      get(sourceDeploymentID, existingBlob);

      if (existingBlob.size() == 0)
      {
        return false;
      }

      contents.insert(targetDeploymentID);
      return true;
    }

    String containerBlob;
    get(sourceDeploymentID, containerBlob);

    if (containerBlob.size() == 0)
    {
      return false;
    }

    return store(targetDeploymentID, containerBlob);
  }

  static bool contains(uint64_t deploymentID)
  {
    return containsAtPath(deploymentID, pathForContainerImage(deploymentID));
  }

  static String systemPathForArtifact(const String& sha256, const String *storeRoot = nullptr)
  {
    return pathForSystemArtifactWithinRoot(storeRoot ? *storeRoot : String("/containers/system-store"_ctv), sha256);
  }

  static bool systemStore(const String& sha256, uint64_t bytes, const String& blob, String *failureReport = nullptr, const String *storeRoot = nullptr)
  {
    if (validateSystemArtifactKey(sha256, bytes, failureReport) == false || validateSystemArtifactContract(blob, failureReport) == false)
    {
      return false;
    }
    String computedDigest = {};
    if (prodigyComputeSHA256Hex(blob, computedDigest, failureReport) == false)
    {
      return false;
    }
    if (computedDigest != sha256)
    {
      if (failureReport)
      {
        failureReport->snprintf<"container blob sha256 mismatch expected={} actual={}"_ctv>(sha256, computedDigest);
      }
      return false;
    }
    if (blob.size() != bytes)
    {
      if (failureReport)
      {
        failureReport->snprintf<"container blob size mismatch expected={itoa} actual={itoa}"_ctv>(bytes, blob.size());
      }
      return false;
    }

    return storeSystemBlobWithKey(sha256, bytes, blob, failureReport, storeRoot);
  }

  static bool systemStore(const String& blob, String& sha256, uint64_t& bytes, String *failureReport = nullptr, const String *storeRoot = nullptr)
  {
    sha256.clear();
    bytes = 0;
    if (validateSystemArtifactContract(blob, failureReport) == false || prodigyComputeSHA256Hex(blob, sha256, failureReport) == false)
    {
      return false;
    }

    bytes = blob.size();
    return storeSystemBlobWithKey(sha256, bytes, blob, failureReport, storeRoot);
  }

  static bool systemVerify(const String& sha256, uint64_t bytes, String *actualDigest = nullptr, uint64_t *actualBytes = nullptr, String *failureReport = nullptr, const String *storeRoot = nullptr)
  {
    String path = pathForSystemArtifactWithinRoot(storeRoot ? *storeRoot : String("/containers/system-store"_ctv), sha256);
    if (validateSystemArtifactKey(sha256, bytes, failureReport) == false ||
        verifyStoredBlobAtPath(path, sha256, bytes, actualDigest, actualBytes, failureReport) == false)
    {
      return false;
    }

    String headerText = prodigyDiscombobulatorMothershipTunnelProviderBlobHeaderText();
    if (bytes <= headerText.size())
    {
      if (failureReport)
      {
        failureReport->assign("system container artifact payload required"_ctv);
      }
      return false;
    }
    String header = {};
    Filesystem::openReadAtClose(-1, path, header, headerText.size());
    return prodigyValidateDiscombobulatorMothershipTunnelProviderBlobHeaderText(header, failureReport);
  }

  static bool systemLoadVerified(const String& sha256, uint64_t bytes, String& blob, String *failureReport = nullptr, const String *storeRoot = nullptr)
  {
    String root = storeRoot ? *storeRoot : String("/containers/system-store"_ctv);
    blob.clear();
    if (systemVerify(sha256, bytes, nullptr, nullptr, failureReport, &root) == false)
    {
      return false;
    }
    Filesystem::openReadAtClose(-1, pathForSystemArtifactWithinRoot(root, sha256), blob);
    if (blob.size() != bytes)
    {
      if (failureReport)
      {
        failureReport->assign("system container artifact unreadable after verification"_ctv);
      }
      return false;
    }
    return true;
  }

  static void destroy(uint64_t deploymentID)
  {
    contents.erase(deploymentID);
    Filesystem::eraseFile(pathForContainerImage(deploymentID));
  }
};
