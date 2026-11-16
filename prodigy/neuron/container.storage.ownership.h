#pragma once

#include <prodigy/bundle.artifact.h>
#include <services/bitsery.h>
#include <linux/btrfs.h>
#include <linux/openat2.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <sys/syscall.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <algorithm>
#include <array>
#include <cstring>
#include <string>
#include <vector>

// Neuron owns the private loop filesystem before the application starts. A
// replacement changes its execution UID; the entire data subvolume must move
// to that UID, not just its root. Keep the original subvolume until logical
// readback has qualified the replacement. No application path is an input.
namespace ProdigyStorageOwnership {
struct Receipt {
  uint32_t version = 1;
  uint128_t container = 0;
  uint64_t deployment = 0;
  String artifact;
  uint64_t artifactBytes = 0;
  uint128_t filesystem = 0;
  uint64_t source = 0;
  uint64_t copy = 0;
  uint32_t sourceUID = 0;
  uint32_t targetUID = 0;
  uint8_t phase = 0; // 0: source sealed, 1: snapshot, 2: verified, 3: exchanged
  String manifest;
};
template <typename S> static void serialize(S&& s, Receipt& r) {
  s.value4b(r.version); s.value16b(r.container); s.value8b(r.deployment);
  s.text1b(r.artifact, 64); s.value8b(r.artifactBytes);
  s.value16b(r.filesystem); s.value8b(r.source); s.value8b(r.copy);
  s.value4b(r.sourceUID); s.value4b(r.targetUID); s.value1b(r.phase);
  s.text1b(r.manifest, 64);
}
#if defined(PRODIGY_STORAGE_OWNERSHIP_TESTING)
static uint8_t interruptAfterPhase = 255;
static inline bool checkpoint(uint8_t phase) {
  if (interruptAfterPhase != phase) return true;
  interruptAfterPhase = 255;
  return false;
}
#else
static inline bool checkpoint(uint8_t) { return true; }
#endif
struct Entry { std::string path; struct stat metadata {}; };
struct Tree { std::vector<Entry> entries; uint32_t priorUID = 0; String manifest; };
static inline bool fail(String *error, const char *message) {
  if (error) error->assign(message);
  return false;
}
static inline int openEntry(int root, const std::string& path, bool directory) {
  if (path.empty()) return dup(root);
  open_how how {};
  how.flags = O_RDONLY | O_CLOEXEC | O_NOFOLLOW | (directory ? O_DIRECTORY : 0);
  how.resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV;
  return int(syscall(SYS_openat2, root, path.c_str(), &how, sizeof(how)));
}
static inline bool collect(int root, int directory, const std::string& prefix,
                           dev_t device, uint32_t target, Tree& tree, String *error, bool ownershipOnly) {
  if (std::count(prefix.begin(), prefix.end(), '/') > 32 || tree.entries.size() >= 100'000)
    return fail(error, "storage ownership tree exceeds bounds");
  struct stat metadata {};
  if (fstat(directory, &metadata) || metadata.st_dev != device)
    return fail(error, "storage ownership tree crosses its private filesystem");
  if (!ownershipOnly && ((!S_ISDIR(metadata.st_mode) && !S_ISREG(metadata.st_mode)) ||
      (metadata.st_mode & 07022) || metadata.st_uid != metadata.st_gid || !metadata.st_uid ||
      (S_ISREG(metadata.st_mode) && metadata.st_nlink != 1)))
    return fail(error, "storage ownership tree has an unsafe entry");
  if (!ownershipOnly) {
    // UID conversion would otherwise silently change named ACL/capability
    // semantics. Ordinary application-owned trees require no conversion.
    for (const char *attribute : {"security.capability", "system.posix_acl_access", "system.posix_acl_default"}) {
      ssize_t bytes = fgetxattr(directory, attribute, nullptr, 0);
      if (bytes > 0 || (bytes < 0 && errno != ENODATA && errno != ENOTSUP))
        return fail(error, "storage ownership conversion has unsupported access metadata");
    }
  }
  if (ownershipOnly) {
    if (metadata.st_uid < target || metadata.st_uid - target >= 65'535 ||
        metadata.st_gid < target || metadata.st_gid - target >= 65'535) tree.priorUID = 1;
  } else if (metadata.st_uid != target) {
    if (metadata.st_uid % 65'535 || (tree.priorUID && tree.priorUID != metadata.st_uid))
      return fail(error, "storage ownership tree has multiple predecessor identities");
    tree.priorUID = metadata.st_uid;
  }
  tree.entries.push_back({prefix, metadata});
  if (S_ISREG(metadata.st_mode)) return true;
  DIR *stream = fdopendir(openat(directory, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC));
  if (!stream) return fail(error, "storage ownership directory cannot be enumerated");
  std::vector<std::string> names;
  errno = 0;
  while (dirent *entry = readdir(stream)) {
    if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
    names.emplace_back(entry->d_name);
  }
  const int readError = errno;
  closedir(stream);
  if (readError) return fail(error, "storage ownership directory enumeration failed");
  std::sort(names.begin(), names.end());
  for (const auto& name : names) {
    std::string path = prefix.empty() ? name : prefix + "/" + name;
    if (ownershipOnly) {
      struct stat childMetadata {};
      if (fstatat(directory, name.c_str(), &childMetadata, AT_SYMLINK_NOFOLLOW))
        return fail(error, "storage ownership entry metadata is unavailable");
      if (childMetadata.st_dev != device || (!S_ISDIR(childMetadata.st_mode) && !S_ISREG(childMetadata.st_mode))) {
        if (childMetadata.st_uid < target || childMetadata.st_uid - target >= 65'535 ||
            childMetadata.st_gid < target || childMetadata.st_gid - target >= 65'535) tree.priorUID = 1;
        tree.entries.push_back({path, childMetadata});
        continue;
      }
    }
    int child = openEntry(root, path, false);
    if (child < 0) return fail(error, "storage ownership entry cannot be opened without traversal");
    bool ready = collect(root, child, path, device, target, tree, error, ownershipOnly);
    close(child);
    if (!ready) return false;
  }
  return true;
}
static inline bool inspect(int root, uint32_t target, Tree& tree, bool hash, String *error, bool ownershipOnly = false) {
  tree = {};
  struct stat metadata {};
  if (fstat(root, &metadata) || !S_ISDIR(metadata.st_mode))
    return fail(error, "storage ownership payload is not a directory");
  if (!collect(root, root, "", metadata.st_dev, target, tree, error, ownershipOnly)) return false;
  if (!hash) return true;
  EVP_MD_CTX *digest = EVP_MD_CTX_new();
  if (!digest) return fail(error, "storage ownership digest allocation failed");
  bool ready = EVP_DigestInit_ex(digest, EVP_sha256(), nullptr) == 1;
  uint64_t logicalBytes = 0;
  std::array<uint8_t, 65536> bytes {};
  for (const auto& entry : tree.entries) {
    const bool directory = S_ISDIR(entry.metadata.st_mode);
    std::string identity = std::to_string(entry.path.size()) + ":" + entry.path + ":" +
        std::to_string(entry.metadata.st_mode & 0777) + ":" +
        std::to_string(directory ? 0 : entry.metadata.st_size) + (directory ? ":d\n" : ":f\n");
    ready = ready && EVP_DigestUpdate(digest, identity.data(), identity.size()) == 1;
    if (directory) continue;
    if (entry.metadata.st_size < 0) { ready = false; break; }
    int file = openEntry(root, entry.path, false);
    if (file < 0) { ready = false; break; }
    // HSE reserves very large sparse files. Hash the size and the kernel's
    // data extents, including their offsets; do not materialize or read holes.
    off_t offset = 0;
    uint32_t extents = 0;
    while (ready && offset < entry.metadata.st_size) {
      errno = 0;
      off_t start = lseek(file, offset, SEEK_DATA);
      if (start < 0 && errno == ENXIO) break;
      off_t end = start < 0 ? -1 : lseek(file, start, SEEK_HOLE);
      if (start < offset || end <= start || end > entry.metadata.st_size || ++extents > 100'000 ||
          uint64_t(end - start) > (8ULL << 30) - logicalBytes) { ready = false; break; }
      logicalBytes += uint64_t(end - start);
      std::string extent = std::to_string(start) + ":" + std::to_string(end - start) + "\n";
      ready = EVP_DigestUpdate(digest, extent.data(), extent.size()) == 1;
      off_t position = start;
      while (ready && position < end) {
        ssize_t count = pread(file, bytes.data(), size_t(std::min<off_t>(bytes.size(), end - position)), position);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { ready = false; break; }
        position += count;
        ready = EVP_DigestUpdate(digest, bytes.data(), size_t(count)) == 1;
      }
      offset = end;
    }
    close(file);
    if (!ready) break;
  }
  std::array<uint8_t, 32> hashBytes {};
  unsigned size = 0;
  ready = ready && EVP_DigestFinal_ex(digest, hashBytes.data(), &size) == 1 && size == hashBytes.size();
  EVP_MD_CTX_free(digest);
  if (!ready) return fail(error, "storage ownership logical readback failed");
  constexpr char hex[] = "0123456789abcdef";
  for (uint8_t byte : hashBytes) { tree.manifest.append(hex[byte >> 4]); tree.manifest.append(hex[byte & 15]); }
  return true;
}
static inline bool normalize(int root, uint32_t source, uint32_t target, String *error) {
  Tree tree;
  if (!inspect(root, target, tree, false, error) || (tree.priorUID && tree.priorUID != source))
    return fail(error, "storage ownership copy identity differs");
  for (auto it = tree.entries.rbegin(); it != tree.entries.rend(); ++it) {
    int file = openEntry(root, it->path, S_ISDIR(it->metadata.st_mode));
    struct stat now {};
    bool ready = file >= 0 && !fstat(file, &now) && now.st_ino == it->metadata.st_ino &&
        now.st_dev == it->metadata.st_dev && (now.st_uid == source || now.st_uid == target) &&
        !fchown(file, target, target) && !fchmod(file, it->metadata.st_mode & 0777) && !fsync(file);
    if (file >= 0) close(file);
    if (!ready) return fail(error, "storage ownership copy normalization failed");
  }
  return true;
}
static inline bool filesystemID(int root, uint128_t& identity) {
  btrfs_ioctl_fs_info_args info {};
  if (ioctl(root, BTRFS_IOC_FS_INFO, &info)) return false;
  memcpy(&identity, info.fsid, sizeof(identity));
  return identity != 0;
}
static inline uint64_t subvolumeID(int root) {
  btrfs_ioctl_get_subvol_info_args info {};
  return ioctl(root, BTRFS_IOC_GET_SUBVOL_INFO, &info) ? 0 : info.treeid;
}
static inline bool writeReceipt(int root, const std::string& name, Receipt& receipt, String *error) {
  String encoded;
  if (!BitseryEngine::serialize(encoded, receipt)) return fail(error, "storage ownership receipt encoding failed");
  const std::string temporary = name + ".pending";
  int file = openat(root, temporary.c_str(), O_WRONLY | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
  struct stat metadata {};
  bool ready = file >= 0 && !fstat(file, &metadata) && S_ISREG(metadata.st_mode) &&
      metadata.st_uid == geteuid() && metadata.st_nlink == 1 && !(metadata.st_mode & 0077) && !ftruncate(file, 0);
  size_t written = 0;
  while (ready && written < encoded.size()) {
    ssize_t count = write(file, encoded.data() + written, encoded.size() - written);
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0) { ready = false; break; }
    written += size_t(count);
  }
  ready = ready && !fsync(file);
  if (file >= 0) close(file);
  if (!ready || renameat(root, temporary.c_str(), root, name.c_str()) || fsync(root))
    return fail(error, "storage ownership receipt publication failed");
  return true;
}
static inline bool readReceipt(int root, const std::string& name, Receipt& receipt, bool& exists, String *error) {
  int file = openat(root, name.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  exists = file >= 0;
  if (file < 0) return errno == ENOENT || fail(error, "storage ownership receipt cannot be opened");
  struct stat metadata {};
  bool ready = !fstat(file, &metadata) && S_ISREG(metadata.st_mode) && metadata.st_uid == geteuid() &&
      metadata.st_nlink == 1 && !(metadata.st_mode & 0077) && metadata.st_size > 0 && metadata.st_size <= 1024;
  String encoded;
  std::array<uint8_t, 1024> bytes {};
  ssize_t count = ready ? read(file, bytes.data(), bytes.size()) : -1;
  close(file);
  if (!ready || count != metadata.st_size) return fail(error, "storage ownership receipt metadata differs");
  encoded.assign(bytes.data(), size_t(count));
  return BitseryEngine::deserializeSafe(encoded, receipt) || fail(error, "storage ownership receipt is malformed");
}

// snapshot(source, target) is the existing ContainerManager Btrfs snapshot owner.
// The caller has already verified the canonical backend and an empty cgroup.
template <typename Snapshot>
static bool transfer(int root, const String& rootPath, uint128_t container, uint64_t deployment,
                     uint32_t target, const String& artifact, uint64_t artifactBytes, Snapshot&& snapshot, String *error) {
  if (!container || !deployment || !target || target % 65'535 ||
      !prodigyIsSHA256HexDigest(artifact) || !artifactBytes) return fail(error, "storage ownership authority is invalid");
  uint128_t filesystem = 0;
  if (!filesystemID(root, filesystem)) return fail(error, "storage ownership backend is not Btrfs");
  String suffix; suffix.assignItoa(container);
  std::string receiptName = ".ownership-" + std::string(suffix.c_str()) + ".v1";
  std::string copyName = ".ownership-" + std::string(suffix.c_str()) + ".source";
  int data = openat(root, "data", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (data < 0) return fail(error, "storage ownership data subvolume is unavailable");
  const uint64_t dataID = subvolumeID(data);
  Receipt receipt;
  bool exists = false;
  bool ready = readReceipt(root, receiptName, receipt, exists, error);
  if (!ready) { close(data); return false; }
  if (!exists) {
    Tree tree;
    ready = inspect(data, target, tree, false, error, true);
    if (!ready || !tree.priorUID) { close(data); return ready; }
    ready = inspect(data, target, tree, true, error);
    receipt.container = container; receipt.deployment = deployment; receipt.filesystem = filesystem;
    receipt.artifact = artifact; receipt.artifactBytes = artifactBytes;
    receipt.source = dataID; receipt.sourceUID = tree.priorUID; receipt.targetUID = target; receipt.manifest = tree.manifest;
    ready = ready && dataID && writeReceipt(root, receiptName, receipt, error) && checkpoint(0);
  }
  close(data);
  if (!ready) return false;
  if (receipt.version != 1 || receipt.container != container || receipt.deployment != deployment ||
      receipt.filesystem != filesystem || receipt.artifact != artifact || receipt.artifactBytes != artifactBytes ||
      receipt.targetUID != target || !receipt.sourceUID ||
      receipt.sourceUID == target || !receipt.source || receipt.phase > 3 || !prodigyIsSHA256HexDigest(receipt.manifest))
    return fail(error, "storage ownership receipt authority differs");
  int copy = openat(root, copyName.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (receipt.phase == 0) {
    if (dataID != receipt.source) { if (copy >= 0) close(copy); return fail(error, "storage ownership source identity differs"); }
    if (copy < 0) {
      if (errno != ENOENT) return fail(error, "storage ownership snapshot path is unsafe");
      String sourcePath(rootPath); sourcePath.append("/data"_ctv);
      String copyPath(rootPath); copyPath.append("/"_ctv); copyPath.append(copyName.c_str());
      if (!snapshot(sourcePath, copyPath, error)) return false;
      copy = openat(root, copyName.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    }
    Tree tree;
    ready = copy >= 0 && inspect(copy, target, tree, true, error) && tree.manifest == receipt.manifest &&
        tree.priorUID == receipt.sourceUID && (receipt.copy = subvolumeID(copy)) != 0 && receipt.copy != receipt.source;
    receipt.phase = 1;
    ready = ready && !fsync(root) && writeReceipt(root, receiptName, receipt, error) && checkpoint(1);
    if (!ready) { if (copy >= 0) close(copy); return fail(error, "storage ownership snapshot verification failed"); }
  }
  data = openat(root, "data", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (copy < 0 || data < 0) { if (copy >= 0) close(copy); if (data >= 0) close(data); return fail(error, "storage ownership publication identities are unavailable"); }
  uint128_t dataFilesystem = 0, copyFilesystem = 0;
  if (!filesystemID(data, dataFilesystem) || !filesystemID(copy, copyFilesystem) ||
      dataFilesystem != filesystem || copyFilesystem != filesystem) {
    close(data); close(copy);
    return fail(error, "storage ownership subvolume belongs to another filesystem");
  }
  uint64_t currentData = subvolumeID(data), currentCopy = subvolumeID(copy);
  if (currentData == receipt.copy && currentCopy == receipt.source && receipt.phase >= 2) {
    // An exchange can be durable before its final receipt. Once committed,
    // ordinary application writes may change the manifest, never the owner.
    Tree tree;
    ready = inspect(data, target, tree, receipt.phase != 3, error, receipt.phase == 3) && !tree.priorUID &&
        (receipt.phase == 3 || tree.manifest == receipt.manifest);
    receipt.phase = 3;
    ready = ready && writeReceipt(root, receiptName, receipt, error);
  } else if (currentData == receipt.source && currentCopy == receipt.copy && receipt.phase < 3) {
    Tree sourceTree, copyTree;
    ready = inspect(data, target, sourceTree, true, error) && sourceTree.manifest == receipt.manifest &&
        sourceTree.priorUID == receipt.sourceUID && normalize(copy, receipt.sourceUID, target, error) &&
        inspect(copy, target, copyTree, true, error) && !copyTree.priorUID && copyTree.manifest == receipt.manifest;
    receipt.phase = 2;
    ready = ready && writeReceipt(root, receiptName, receipt, error) && checkpoint(2);
    if (ready) ready = !renameat2(root, "data", root, copyName.c_str(), RENAME_EXCHANGE) && !fsync(root) && checkpoint(3);
    if (ready) { receipt.phase = 3; ready = writeReceipt(root, receiptName, receipt, error); }
  } else ready = false;
  close(data); close(copy);
  return ready || fail(error, "storage ownership atomic publication failed");
}
} // namespace ProdigyStorageOwnership
