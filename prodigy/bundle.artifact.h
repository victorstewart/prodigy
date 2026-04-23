#pragma once

#include <macros/bytes.h>
#include <networking/includes.h>
#include <services/filesystem.h>

#include <prodigy/build.identity.h>

#include <openssl/evp.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static inline bool prodigyResolveCurrentExecutablePath(String& executablePath)
{
   char path[PATH_MAX] = {};
   ssize_t result = readlink("/proc/self/exe", path, sizeof(path) - 1);
   if (result <= 0)
   {
      return false;
   }

   path[result] = '\0';
   executablePath.assign(path);
   return true;
}

static inline void prodigyAppendShellSingleQuoted(String& command, const String& value)
{
   command.append('\'');

   for (uint64_t index = 0; index < value.size(); ++index)
   {
      if (value[index] == '\'')
      {
         command.append("'\"'\"'"_ctv);
      }
      else
      {
         command.append(value[index]);
      }
   }

   command.append('\'');
}

static inline void prodigyDirname(const String& path, String& parent)
{
   parent.clear();

   if (path.size() == 0)
   {
      return;
   }

   int64_t slash = -1;
   for (int64_t index = int64_t(path.size()) - 1; index >= 0; --index)
   {
      if (path[uint64_t(index)] == '/')
      {
         slash = index;
         break;
      }
   }

   if (slash < 0)
   {
      parent.assign("."_ctv);
      return;
   }

   if (slash == 0)
   {
      parent.assign("/"_ctv);
      return;
   }

   parent.assign(path.substr(0, slash, Copy::yes));
}

static inline bool prodigyRunLocalShellCommand(const String& command, String *failure = nullptr)
{
   String commandText = {};
   commandText.assign(command);
   int rc = std::system(commandText.c_str());
   if (rc != 0)
   {
      if (failure) failure->snprintf<"local command failed: {}"_ctv>(command);
      return false;
   }

   if (failure) failure->clear();
   return true;
}

static inline bool prodigyFileReadable(const String& path)
{
   if (path.size() == 0)
   {
      return false;
   }

   String pathText = {};
   pathText.assign(path);
   return ::access(pathText.c_str(), R_OK) == 0;
}

static inline void prodigyAppendHexByte(String& digest, uint8_t value)
{
   static constexpr char hex[] = "0123456789abcdef";
   digest.append(hex[value >> 4]);
   digest.append(hex[value & 0x0F]);
}

static inline bool prodigyIsSHA256HexDigest(const String& digest)
{
   if (digest.size() != 64)
   {
      return false;
   }

   for (uint64_t index = 0; index < digest.size(); ++index)
   {
      unsigned char ch = static_cast<unsigned char>(digest[index]);
      bool isDigit = (ch >= '0' && ch <= '9');
      bool isLowerHex = (ch >= 'a' && ch <= 'f');
      if (isDigit == false && isLowerHex == false)
      {
         return false;
      }
   }

   return true;
}

static inline bool prodigyComputeSHA256Hex(const uint8_t *data, uint64_t size, String& digest, String *failure = nullptr)
{
   digest.clear();
   if (failure) failure->clear();

   if (data == nullptr && size > 0)
   {
      if (failure) failure->assign("sha256 source buffer is null"_ctv);
      return false;
   }

   EVP_MD_CTX *ctx = EVP_MD_CTX_new();
   if (ctx == nullptr)
   {
      if (failure) failure->assign("EVP_MD_CTX_new failed"_ctv);
      return false;
   }

   bool ok = true;
   if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1)
   {
      ok = false;
      if (failure) failure->assign("EVP_DigestInit_ex failed"_ctv);
   }

   if (ok && size > 0 && EVP_DigestUpdate(ctx, data, size_t(size)) != 1)
   {
      ok = false;
      if (failure) failure->assign("EVP_DigestUpdate failed"_ctv);
   }

   uint8_t rawDigest[EVP_MAX_MD_SIZE];
   unsigned int rawDigestSize = 0;
   if (ok && EVP_DigestFinal_ex(ctx, rawDigest, &rawDigestSize) != 1)
   {
      ok = false;
      if (failure) failure->assign("EVP_DigestFinal_ex failed"_ctv);
   }

   EVP_MD_CTX_free(ctx);

   if (ok == false)
   {
      digest.clear();
      return false;
   }

   if (rawDigestSize != 32)
   {
      if (failure) failure->snprintf<"unexpected sha256 size: {}"_ctv>(rawDigestSize);
      digest.clear();
      return false;
   }

   digest.reserve(64);
   for (unsigned int index = 0; index < rawDigestSize; ++index)
   {
      prodigyAppendHexByte(digest, rawDigest[index]);
   }

   return true;
}

static inline bool prodigyComputeSHA256Hex(const String& payload, String& digest, String *failure = nullptr)
{
   return prodigyComputeSHA256Hex(reinterpret_cast<const uint8_t *>(payload.data()), payload.size(), digest, failure);
}

static inline void prodigyTrimTrailingASCIIWhitespace(String& text)
{
   while (text.size() > 0)
   {
      char ch = text[text.size() - 1];
      if (ch != '\n' && ch != '\r' && ch != '\t' && ch != ' ')
      {
         break;
      }

      text.resize(text.size() - 1);
   }
}

static inline void prodigyResolveBundleSHA256Path(const String& bundlePath, String& sha256Path)
{
   sha256Path.assign(bundlePath);
   sha256Path.append(".sha256"_ctv);
}

static inline bool prodigyLoadBundleExpectedSHA256Hex(const String& bundlePath, String& expectedDigest, String *failure = nullptr)
{
   expectedDigest.clear();
   if (failure) failure->clear();

   String sha256Path = {};
   prodigyResolveBundleSHA256Path(bundlePath, sha256Path);
   if (prodigyFileReadable(sha256Path) == false)
   {
      if (failure) failure->snprintf<"bundle sha256 sidecar is not readable: {}"_ctv>(sha256Path);
      return false;
   }

   String pathText = {};
   pathText.assign(sha256Path);
   Filesystem::openReadAtClose(-1, pathText, expectedDigest);
   prodigyTrimTrailingASCIIWhitespace(expectedDigest);
   if (prodigyIsSHA256HexDigest(expectedDigest) == false)
   {
      if (failure) failure->snprintf<"bundle sha256 sidecar is invalid: {}"_ctv>(sha256Path);
      expectedDigest.clear();
      return false;
   }

   return true;
}

static inline bool prodigyComputeFileSHA256Hex(const String& path, String& digest, uint64_t *actualBytes, String *failure = nullptr)
{
   digest.clear();
   if (failure) failure->clear();
   if (actualBytes) *actualBytes = 0;

   if (prodigyFileReadable(path) == false)
   {
      if (failure) failure->snprintf<"sha256 source is not readable: {}"_ctv>(path);
      return false;
   }

   String pathText = {};
   pathText.assign(path);

   int fd = ::open(pathText.c_str(), O_RDONLY | O_CLOEXEC);
   if (fd < 0)
   {
      if (failure) failure->snprintf<"open failed for sha256 source: {} errno={}"_ctv>(path, errno);
      return false;
   }

   EVP_MD_CTX *ctx = EVP_MD_CTX_new();
   if (ctx == nullptr)
   {
      ::close(fd);
      if (failure) failure->assign("EVP_MD_CTX_new failed"_ctv);
      return false;
   }

   bool ok = true;
   uint64_t totalBytesRead = 0;
   if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1)
   {
      ok = false;
      if (failure) failure->assign("EVP_DigestInit_ex failed"_ctv);
   }

   uint8_t buffer[64_KB];
   while (ok)
   {
      ssize_t bytesRead = ::read(fd, buffer, sizeof(buffer));
      if (bytesRead == 0)
      {
         break;
      }

      if (bytesRead < 0)
      {
         if (errno == EINTR)
         {
            continue;
         }

         ok = false;
         if (failure) failure->snprintf<"read failed for sha256 source: {} errno={}"_ctv>(path, errno);
         break;
      }

      if (EVP_DigestUpdate(ctx, buffer, size_t(bytesRead)) != 1)
      {
         ok = false;
         if (failure) failure->assign("EVP_DigestUpdate failed"_ctv);
         break;
      }

      totalBytesRead += uint64_t(bytesRead);
   }

   uint8_t rawDigest[EVP_MAX_MD_SIZE];
   unsigned int rawDigestSize = 0;
   if (ok && EVP_DigestFinal_ex(ctx, rawDigest, &rawDigestSize) != 1)
   {
      ok = false;
      if (failure) failure->assign("EVP_DigestFinal_ex failed"_ctv);
   }

   EVP_MD_CTX_free(ctx);
   ::close(fd);

   if (ok == false)
   {
      digest.clear();
      return false;
   }

   if (rawDigestSize != 32)
   {
      if (failure) failure->snprintf<"unexpected sha256 size: {}"_ctv>(rawDigestSize);
      digest.clear();
      return false;
   }

   digest.reserve(64);
   for (unsigned int index = 0; index < rawDigestSize; ++index)
   {
      prodigyAppendHexByte(digest, rawDigest[index]);
   }

   if (actualBytes)
   {
      *actualBytes = totalBytesRead;
   }

   return true;
}

static inline bool prodigyFileMatchesExpectedSHA256Hex(const String& path, const String& expectedDigest, String& actualDigest, String *failure = nullptr)
{
   actualDigest.clear();
   if (failure) failure->clear();

   if (prodigyIsSHA256HexDigest(expectedDigest) == false)
   {
      if (failure) failure->snprintf<"expected sha256 is invalid: {}"_ctv>(expectedDigest);
      return false;
   }

   if (prodigyComputeFileSHA256Hex(path, actualDigest, nullptr, failure) == false)
   {
      return false;
   }

   if (actualDigest != expectedDigest)
   {
      if (failure) failure->snprintf<"sha256 mismatch expected={} actual={} path={}"_ctv>(expectedDigest, actualDigest, path);
      return false;
   }

   return true;
}

static inline bool prodigyComputeFileSHA256Hex(const String& path, String& digest, String *failure = nullptr)
{
   return prodigyComputeFileSHA256Hex(path, digest, nullptr, failure);
}

static inline bool prodigyFileMatchesExpectedSHA256HexAndSize(
   const String& path,
   const String& expectedDigest,
   uint64_t expectedBytes,
   String& actualDigest,
   uint64_t *actualBytes = nullptr,
   String *failure = nullptr)
{
   actualDigest.clear();
   if (failure) failure->clear();
   if (actualBytes) *actualBytes = 0;

   if (prodigyIsSHA256HexDigest(expectedDigest) == false)
   {
      if (failure) failure->snprintf<"expected sha256 is invalid: {}"_ctv>(expectedDigest);
      return false;
   }

   uint64_t measuredBytes = 0;
   if (prodigyComputeFileSHA256Hex(path, actualDigest, &measuredBytes, failure) == false)
   {
      return false;
   }

   if (actualBytes)
   {
      *actualBytes = measuredBytes;
   }

   if (measuredBytes != expectedBytes)
   {
      if (failure) failure->snprintf<"blob size mismatch expected={} actual={} path={}"_ctv>(expectedBytes, measuredBytes, path);
      return false;
   }

   if (actualDigest != expectedDigest)
   {
      if (failure) failure->snprintf<"sha256 mismatch expected={} actual={} path={}"_ctv>(expectedDigest, actualDigest, path);
      return false;
   }

   return true;
}

static inline bool prodigyBundleMatchesExpectedSHA256Hex(const String& bundlePath, const String& expectedDigest, String& actualDigest, String *failure = nullptr)
{
   bool matched = prodigyFileMatchesExpectedSHA256Hex(bundlePath, expectedDigest, actualDigest, failure);
   if (matched || failure == nullptr || failure->size() == 0)
   {
      return matched;
   }

   String prefixed = {};
   prefixed.snprintf<"bundle {}"_ctv>(*failure);
   *failure = std::move(prefixed);
   return false;
}

static inline bool prodigyIsZstdFile(const String& path)
{
   if (path.size() == 0)
   {
      return false;
   }

   String pathText = {};
   pathText.assign(path);
   String header;
   header.reserve(4);
   Filesystem::openReadAtClose(-1, pathText, header, 4);

   return header.size() >= 4
      && uint8_t(header[0]) == 0x28
      && uint8_t(header[1]) == 0xB5
      && uint8_t(header[2]) == 0x2F
      && uint8_t(header[3]) == 0xFD;
}

static inline String prodigyBundleFilename(MachineCpuArchitecture architecture)
{
   switch (architecture)
   {
      case MachineCpuArchitecture::x86_64:
      {
         return "prodigy.x86_64.bundle.tar.zst"_ctv;
      }
      case MachineCpuArchitecture::aarch64:
      {
         return "prodigy.aarch64.bundle.tar.zst"_ctv;
      }
      case MachineCpuArchitecture::riscv64:
      {
         return "prodigy.riscv64.bundle.tar.zst"_ctv;
      }
      default:
      {
         return "prodigy.bundle.tar.zst"_ctv;
      }
   }
}

static inline String prodigyBundleFilename(void)
{
   return prodigyBundleFilename(nametagCurrentBuildMachineArchitecture());
}

static inline bool prodigyResolveBundleHomeDirectory(String& bundleHome, String *failure = nullptr)
{
   bundleHome.clear();
   if (failure) failure->clear();

   const char *xdgDataHome = std::getenv("XDG_DATA_HOME");
   if (xdgDataHome != nullptr && xdgDataHome[0] != '\0')
   {
      bundleHome.assign(xdgDataHome);
      if (bundleHome[bundleHome.size() - 1] != '/')
      {
         bundleHome.append('/');
      }
      bundleHome.append("prodigy"_ctv);
      return true;
   }

   const char *home = std::getenv("HOME");
   if (home != nullptr && home[0] != '\0')
   {
      bundleHome.assign(home);
      if (bundleHome.size() > 0 && bundleHome[bundleHome.size() - 1] != '/')
      {
         bundleHome.append('/');
      }
      bundleHome.append(".local/share/prodigy"_ctv);
      return true;
   }

   if (failure) failure->assign("unable to resolve user prodigy bundle directory from XDG_DATA_HOME or HOME"_ctv);
   return false;
}

static inline String prodigyStagedBundlePath(void)
{
   return "/root/prodigy.bundle.new.tar.zst"_ctv;
}

class ProdigyInstallRootPaths
{
public:

   String installRoot;
   String installRootTemp;
   String installRootPrevious;
   String binaryPath;
   String libraryDirectory;
   String toolsDirectory;
   String bundlePath;
   String bundleSHA256Path;
   String bundleTempPath;
   String bundleSHA256TempPath;
};

static inline void prodigyBuildInstallRootPaths(const String& installRoot, ProdigyInstallRootPaths& paths)
{
   paths = {};
   paths.installRoot.assign(installRoot);
   paths.installRootTemp.assign(installRoot);
   paths.installRootTemp.append(".new"_ctv);
   paths.installRootPrevious.assign(installRoot);
   paths.installRootPrevious.append(".prev"_ctv);
   paths.binaryPath.assign(installRoot);
   if (paths.binaryPath.size() > 0 && paths.binaryPath[paths.binaryPath.size() - 1] != '/')
   {
      paths.binaryPath.append('/');
   }
   paths.binaryPath.append("prodigy"_ctv);
   paths.libraryDirectory.assign(installRoot);
   if (paths.libraryDirectory.size() > 0 && paths.libraryDirectory[paths.libraryDirectory.size() - 1] != '/')
   {
      paths.libraryDirectory.append('/');
   }
   paths.libraryDirectory.append("lib"_ctv);
   paths.toolsDirectory.assign(installRoot);
   if (paths.toolsDirectory.size() > 0 && paths.toolsDirectory[paths.toolsDirectory.size() - 1] != '/')
   {
      paths.toolsDirectory.append('/');
   }
   paths.toolsDirectory.append("tools"_ctv);
   paths.bundlePath.assign(installRoot);
   if (paths.bundlePath.size() > 0 && paths.bundlePath[paths.bundlePath.size() - 1] != '/')
   {
      paths.bundlePath.append('/');
   }
   paths.bundlePath.append("prodigy.bundle.tar.zst"_ctv);
   prodigyResolveBundleSHA256Path(paths.bundlePath, paths.bundleSHA256Path);
   paths.bundleTempPath.assign(prodigyStagedBundlePath());
   prodigyResolveBundleSHA256Path(paths.bundleTempPath, paths.bundleSHA256TempPath);
}

static inline void prodigyResolveInstalledBundlePathForRoot(const String& installRoot, String& bundlePath)
{
   bundlePath.assign(installRoot);
   if (bundlePath.size() > 0 && bundlePath[bundlePath.size() - 1] != '/')
   {
      bundlePath.append('/');
   }
   bundlePath.append("prodigy.bundle.tar.zst"_ctv);
}

static inline void prodigyResolveBundlePathForExecutable(const String& localExecutablePath, MachineCpuArchitecture architecture, String& bundlePath)
{
   String executableDirectory = {};
   prodigyDirname(localExecutablePath, executableDirectory);
   bundlePath.assign(executableDirectory);
   if (bundlePath.size() > 0 && bundlePath[bundlePath.size() - 1] != '/')
   {
      bundlePath.append('/');
   }
   bundlePath.append(prodigyBundleFilename(architecture));
}

static inline void prodigyResolveBundlePathForDirectory(const String& directory, MachineCpuArchitecture architecture, String& bundlePath)
{
   bundlePath.assign(directory);
   if (bundlePath.size() > 0 && bundlePath[bundlePath.size() - 1] != '/')
   {
      bundlePath.append('/');
   }
   bundlePath.append(prodigyBundleFilename(architecture));
}

static inline void prodigyResolveBundlePathForExecutable(const String& localExecutablePath, String& bundlePath)
{
   prodigyResolveBundlePathForExecutable(localExecutablePath, nametagCurrentBuildMachineArchitecture(), bundlePath);
}

static inline void prodigyResolveInstalledToolPathForRoot(const String& installRoot, const String& toolName, String& toolPath)
{
   toolPath.assign(installRoot);
   if (toolPath.size() > 0 && toolPath[toolPath.size() - 1] != '/')
   {
      toolPath.append('/');
   }
   toolPath.append("tools/"_ctv);
   toolPath.append(toolName);
}

static inline bool prodigyResolveBundledToolPathForExecutable(const String& localExecutablePath, const String& toolName, String& toolPath)
{
   String executableDirectory = {};
   prodigyDirname(localExecutablePath, executableDirectory);
   prodigyResolveInstalledToolPathForRoot(executableDirectory, toolName, toolPath);
   return prodigyFileReadable(toolPath);
}

static inline bool prodigyResolveBuiltBundleArtifact(const String& localExecutablePath, MachineCpuArchitecture architecture, String& bundlePath, String *failure = nullptr)
{
   if (failure) failure->clear();

   prodigyResolveBundlePathForExecutable(localExecutablePath, architecture, bundlePath);
   if (prodigyFileReadable(bundlePath))
   {
      return true;
   }

   if (failure) failure->snprintf<"built prodigy bundle artifact is not readable: {}"_ctv>(bundlePath);
   return false;
}

static inline bool prodigyResolveInstalledBundleArtifact(MachineCpuArchitecture architecture, String& bundlePath, String *failure = nullptr)
{
   if (failure) failure->clear();

   String bundleHome = {};
   if (prodigyResolveBundleHomeDirectory(bundleHome, failure) == false)
   {
      bundlePath.clear();
      return false;
   }

   prodigyResolveBundlePathForDirectory(bundleHome, architecture, bundlePath);
   if (prodigyFileReadable(bundlePath))
   {
      return true;
   }

   if (failure) failure->snprintf<"installed prodigy bundle artifact is not readable for architecture={} path={}"_ctv>(
      String(machineCpuArchitectureName(architecture)),
      bundlePath);
   return false;
}

static inline bool prodigyApproveBundleArtifact(const String& bundlePath, String& approvedDigest, String *failure = nullptr)
{
   approvedDigest.clear();
   if (failure) failure->clear();

   String expectedDigest = {};
   if (prodigyLoadBundleExpectedSHA256Hex(bundlePath, expectedDigest, failure) == false)
   {
      return false;
   }

   return prodigyBundleMatchesExpectedSHA256Hex(bundlePath, expectedDigest, approvedDigest, failure);
}

static inline bool prodigyResolveInstalledApprovedBundleArtifact(MachineCpuArchitecture architecture, String& bundlePath, String& approvedDigest, String *failure = nullptr)
{
   approvedDigest.clear();
   if (failure) failure->clear();

   if (prodigyResolveInstalledBundleArtifact(architecture, bundlePath, failure) == false)
   {
      bundlePath.clear();
      return false;
   }

   return prodigyApproveBundleArtifact(bundlePath, approvedDigest, failure);
}

static inline bool prodigyResolvePreferredBootstrapBundleArtifact(const String& localExecutablePath, MachineCpuArchitecture architecture, const String& installRoot, String& bundlePath, String *failure = nullptr)
{
   bundlePath.clear();
   if (failure) failure->clear();

   String builtFailure = {};
   if (localExecutablePath.size() > 0
      && prodigyResolveBuiltBundleArtifact(localExecutablePath, architecture, bundlePath, &builtFailure))
   {
      return true;
   }

   String installedFailure = {};
   if (prodigyResolveInstalledBundleArtifact(architecture, bundlePath, &installedFailure))
   {
      return true;
   }

   String fallbackBundlePath = {};
   prodigyResolveInstalledBundlePathForRoot(installRoot, fallbackBundlePath);
   if (prodigyFileReadable(fallbackBundlePath))
   {
      bundlePath = fallbackBundlePath;
      return true;
   }

   if (failure != nullptr)
   {
      if (builtFailure.size() > 0 && installedFailure.size() > 0)
      {
         failure->snprintf<"{}; {}; fallback installed bundle '{}' not readable"_ctv>(builtFailure, installedFailure, fallbackBundlePath);
      }
      else if (builtFailure.size() > 0)
      {
         failure->snprintf<"{}; fallback installed bundle '{}' not readable"_ctv>(builtFailure, fallbackBundlePath);
      }
      else if (installedFailure.size() > 0)
      {
         failure->snprintf<"{}; fallback installed bundle '{}' not readable"_ctv>(installedFailure, fallbackBundlePath);
      }
      else
      {
         failure->snprintf<"fallback installed bundle '{}' not readable"_ctv>(fallbackBundlePath);
      }
   }

   bundlePath.clear();
   return false;
}

static inline bool prodigyResolveBuiltBundleArtifact(const String& localExecutablePath, String& bundlePath, String *failure = nullptr)
{
   return prodigyResolveBuiltBundleArtifact(localExecutablePath, nametagCurrentBuildMachineArchitecture(), bundlePath, failure);
}

static inline bool prodigyResolveBundleArtifactInput(const String& inputPath, MachineCpuArchitecture architecture, String& bundlePath, String *failure = nullptr)
{
   bundlePath.clear();
   if (failure) failure->clear();

   if (inputPath.size() == 0)
   {
      if (failure) failure->assign("bundle or executable path required"_ctv);
      return false;
   }

   if (prodigyFileReadable(inputPath) == false)
   {
      if (failure) failure->snprintf<"bundle or executable path is not readable: {}"_ctv>(inputPath);
      return false;
   }

   if (prodigyIsZstdFile(inputPath))
   {
      bundlePath = inputPath;
      return true;
   }

   String builtFailure = {};
   if (prodigyResolveBuiltBundleArtifact(inputPath, architecture, bundlePath, &builtFailure))
   {
      return true;
   }

   return prodigyResolveInstalledBundleArtifact(architecture, bundlePath, failure);
}

static inline bool prodigyResolveBundleArtifactInput(const String& inputPath, String& bundlePath, String *failure = nullptr)
{
   return prodigyResolveBundleArtifactInput(inputPath, nametagCurrentBuildMachineArchitecture(), bundlePath, failure);
}

static inline bool prodigyInstallBundleToRoot(const String& bundlePath, const String& installRoot, String *failure = nullptr)
{
   if (failure) failure->clear();

   ProdigyInstallRootPaths paths = {};
   prodigyBuildInstallRootPaths(installRoot, paths);
   String tempBundlePath = {};
   prodigyResolveInstalledBundlePathForRoot(paths.installRootTemp, tempBundlePath);

   String command = {};
   command.assign("set -eu; rm -rf "_ctv);
   prodigyAppendShellSingleQuoted(command, paths.installRootTemp);
   command.append(" "_ctv);
   prodigyAppendShellSingleQuoted(command, paths.installRootPrevious);
   command.append("; mkdir -p "_ctv);
   prodigyAppendShellSingleQuoted(command, paths.installRootTemp);
   command.append("; tar --zstd -xf "_ctv);
   prodigyAppendShellSingleQuoted(command, bundlePath);
   command.append(" -C "_ctv);
   prodigyAppendShellSingleQuoted(command, paths.installRootTemp);
   command.append("; install -m 0644 "_ctv);
   prodigyAppendShellSingleQuoted(command, bundlePath);
   command.append(" "_ctv);
   prodigyAppendShellSingleQuoted(command, tempBundlePath);
   command.append("; if [ -e "_ctv);
   prodigyAppendShellSingleQuoted(command, paths.installRoot);
   command.append(" ]; then mv "_ctv);
   prodigyAppendShellSingleQuoted(command, paths.installRoot);
   command.append(" "_ctv);
   prodigyAppendShellSingleQuoted(command, paths.installRootPrevious);
   command.append("; fi; mv "_ctv);
   prodigyAppendShellSingleQuoted(command, paths.installRootTemp);
   command.append(" "_ctv);
   prodigyAppendShellSingleQuoted(command, paths.installRoot);
   command.append("; rm -rf "_ctv);
   prodigyAppendShellSingleQuoted(command, paths.installRootPrevious);

   return prodigyRunLocalShellCommand(command, failure);
}
