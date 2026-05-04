#pragma once

#include <prodigy/bundle.artifact.h>

#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

class ContainerStore {
private:

   static inline bytell_hash_set<uint64_t> contents;

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
            String errnoText = {};
            errnoText.assign(strerror(errno));
            failureReport->snprintf<"blob write failed errno={}({})"_ctv>(errno, errnoText);
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
         if (failureReport) failureReport->snprintf<"blob parent directory is missing for {}"_ctv>(finalPath);
         return false;
      }

      int dirfd = Filesystem::openDirectoryAt(-1, parentPath, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
      if (dirfd < 0)
      {
         if (failureReport)
         {
            String errnoText = {};
            errnoText.assign(strerror(errno));
            failureReport->snprintf<"failed to open blob parent directory {} errno={}({})"_ctv>(parentPath, errno, errnoText);
         }
         return false;
      }

      bool ok = (::fsync(dirfd) == 0);
      int syncErrno = errno;
      ::close(dirfd);
      if (ok == false && failureReport)
      {
         String errnoText = {};
         errnoText.assign(strerror(syncErrno));
         failureReport->snprintf<"failed to fsync blob parent directory {} errno={}({})"_ctv>(parentPath, syncErrno, errnoText);
      }

      return ok;
   }

   static bool atomicWriteFile(const String& finalPath, const String& payload, String *failureReport = nullptr)
   {
      String parentPath = {};
      prodigyDirname(finalPath, parentPath);
      if (parentPath.size() == 0)
      {
         if (failureReport) failureReport->snprintf<"blob parent directory is missing for {}"_ctv>(finalPath);
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
         if (failureReport) failureReport->snprintf<"failed to create temporary blob path for {} errno={}({})"_ctv>(finalPath, errno, String(strerror(errno)));
         return false;
      }

      bool ok = true;
      String createdTempPath = {};
      createdTempPath.assign(reinterpret_cast<const char *>(tempPath.data()));

      if (::fchmod(fd, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) != 0)
      {
         ok = false;
         if (failureReport) failureReport->snprintf<"failed to chmod temporary blob {} errno={}({})"_ctv>(createdTempPath, errno, String(strerror(errno)));
      }

      if (ok && writeAll(fd, payload, failureReport) == false)
      {
         ok = false;
      }

      if (ok && ::fsync(fd) != 0)
      {
         ok = false;
         if (failureReport) failureReport->snprintf<"failed to fsync temporary blob {} errno={}({})"_ctv>(createdTempPath, errno, String(strerror(errno)));
      }

      if (::close(fd) != 0 && ok)
      {
         ok = false;
         if (failureReport) failureReport->snprintf<"failed to close temporary blob {} errno={}({})"_ctv>(createdTempPath, errno, String(strerror(errno)));
      }

      String finalPathText = {};
      finalPathText.assign(finalPath);
      if (ok && ::rename(createdTempPath.c_str(), finalPathText.c_str()) != 0)
      {
         ok = false;
         if (failureReport) failureReport->snprintf<"failed to rename temporary blob {} -> {} errno={}({})"_ctv>(createdTempPath, finalPath, errno, String(strerror(errno)));
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
      if (failureReport) failureReport->clear();
      if (actualDigest) actualDigest->clear();
      if (actualBytes) *actualBytes = 0;

      if (prodigyFileReadable(finalPath) == false)
      {
         if (failureReport) failureReport->snprintf<"container blob is not readable: {}"_ctv>(finalPath);
         return false;
      }

      String computedDigest = {};
      uint64_t computedBytes = 0;
      if (prodigyFileMatchesExpectedSHA256HexAndSize(finalPath, expectedDigest, expectedBytes, computedDigest, &computedBytes, failureReport) == false)
      {
         if (actualDigest) *actualDigest = std::move(computedDigest);
         if (actualBytes) *actualBytes = computedBytes;
         return false;
      }

      if (actualDigest) *actualDigest = std::move(computedDigest);
      if (actualBytes) *actualBytes = computedBytes;
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
      if (failureReport) failureReport->clear();
      if (actualDigest) actualDigest->clear();
      if (actualBytes) *actualBytes = 0;

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
            if (failureReport) failureReport->snprintf<"expected container blob sha256 is invalid: {}"_ctv>(*expectedDigest);
            return false;
         }

         if (computedDigest != *expectedDigest)
         {
            if (failureReport) failureReport->snprintf<"container blob sha256 mismatch expected={} actual={}"_ctv>(*expectedDigest, computedDigest);
            return false;
         }
      }

      if (expectedBytes != nullptr && payloadBytes != *expectedBytes)
      {
         if (failureReport) failureReport->snprintf<"container blob size mismatch expected={} actual={}"_ctv>(*expectedBytes, payloadBytes);
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

public:

   static inline bool autoDestroy; // false if brain, else true

   static String pathForContainerImage(uint64_t deploymentID)
   {
      return pathForContainerImageWithinRoot("/containers/store"_ctv, deploymentID);
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
      return storeBlobAtPath(
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
      if (storeBlobAtPath(
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
      if (contents.contains(deploymentID))
      {
         return true;
      }

      if (Filesystem::fileExists(pathForContainerImage(deploymentID)))
      {
         contents.insert(deploymentID);
         return true;
      }

      return false;
   }

   static void destroy(uint64_t deploymentID)
   {
      contents.erase(deploymentID);
      Filesystem::eraseFile(pathForContainerImage(deploymentID));
   }
};
