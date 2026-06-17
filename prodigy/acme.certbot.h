#pragma once

#include <cerrno>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fcntl.h>
#include <spawn.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

#include <prodigy/types.h>

class ProdigyCertbotPaths {
public:

  String certbotPath;
  String configDir;
  String workDir;
  String logsDir;
  String authHookPath;
  String cleanupHookPath;
  String deployHookPath;
};

class ProdigyCertbotCommand {
public:

  Vector<String> argv;
  Vector<String> env;
};

static inline void prodigyCertbotDefaultClusterPath(uint128_t clusterUUID, const char *leaf, String& path)
{
  String clusterText;
  clusterText.assignItoh(clusterUUID);
  path.assign("/var/lib/prodigy/certbot/"_ctv);
  path.append(clusterText);
  path.append("/"_ctv);
  path.append(leaf);
}

static inline void prodigyCertbotDefaultLogPath(uint128_t clusterUUID, String& path)
{
  String clusterText;
  clusterText.assignItoh(clusterUUID);
  path.assign("/var/log/prodigy/certbot/"_ctv);
  path.append(clusterText);
}

static inline void prodigyCertbotEffectiveDirs(const BrainConfig& config, const ProdigyCertbotPaths& paths, String& configDir, String& workDir, String& logsDir)
{
  configDir = paths.configDir;
  workDir = paths.workDir;
  logsDir = paths.logsDir;
  if (configDir.size() == 0)
  {
    prodigyCertbotDefaultClusterPath(config.clusterUUID, "config", configDir);
  }
  if (workDir.size() == 0)
  {
    prodigyCertbotDefaultClusterPath(config.clusterUUID, "work", workDir);
  }
  if (logsDir.size() == 0)
  {
    prodigyCertbotDefaultLogPath(config.clusterUUID, logsDir);
  }
}

static inline void prodigyCertbotLineagePath(const BrainConfig& config, const PublicTlsCertificateState& certificate, const ProdigyCertbotPaths& paths, String& lineagePath)
{
  String configDir = {};
  String ignoredWorkDir = {};
  String ignoredLogsDir = {};
  prodigyCertbotEffectiveDirs(config, paths, configDir, ignoredWorkDir, ignoredLogsDir);
  const String& certName = certificate.certbotCertName.size() ? certificate.certbotCertName : certificate.spec.identityName;
  lineagePath.snprintf<"{}/live/{}"_ctv>(configDir, certName);
}

static inline void prodigyCertbotLockPath(const BrainConfig& config, const PublicTlsCertificateState& certificate, const ProdigyCertbotPaths& paths, String& lockPath)
{
  String ignoredConfigDir = {};
  String workDir = {};
  String ignoredLogsDir = {};
  prodigyCertbotEffectiveDirs(config, paths, ignoredConfigDir, workDir, ignoredLogsDir);
  const String& certName = certificate.certbotCertName.size() ? certificate.certbotCertName : certificate.spec.identityName;
  lockPath.snprintf<"{}/locks/{}.lock"_ctv>(workDir, certName);
}

static inline void prodigyReleaseCertbotLockFD(int& fd)
{
  if (fd >= 0)
  {
    (void)flock(fd, LOCK_UN);
    close(fd);
    fd = -1;
  }
}

static inline bool prodigyAcquireCertbotCertificateLock(const BrainConfig& config, const PublicTlsCertificateState& certificate, const ProdigyCertbotPaths& paths, int& fd, bool *busy = nullptr, String *failure = nullptr)
{
  fd = -1;
  if (busy)
  {
    *busy = false;
  }
  if (failure)
  {
    failure->clear();
  }

  String lockPath = {};
  prodigyCertbotLockPath(config, certificate, paths, lockPath);
  uint64_t slash = lockPath.size();
  while (slash > 0 && lockPath[slash - 1] != '/')
  {
    slash -= 1;
  }
  std::error_code error;
  String lockDir = lockPath.substr(0, slash, Copy::yes);
  std::filesystem::create_directories(std::filesystem::path(reinterpret_cast<const char *>(lockDir.c_str())), error);
  if (error)
  {
    if (failure)
    {
      failure->snprintf<"failed to create Certbot lock directory: {}"_ctv>(String(error.message().c_str()));
    }
    return false;
  }

  fd = open(reinterpret_cast<const char *>(lockPath.c_str()), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
  if (fd < 0)
  {
    if (failure)
    {
      failure->snprintf<"failed to open Certbot lock: {}"_ctv>(String(strerror(errno)));
    }
    return false;
  }
  if (flock(fd, LOCK_EX | LOCK_NB) == 0)
  {
    return true;
  }

  int savedErrno = errno;
  close(fd);
  fd = -1;
  if (savedErrno == EWOULDBLOCK || savedErrno == EAGAIN)
  {
    if (busy)
    {
      *busy = true;
    }
    if (failure)
    {
      failure->assign("public TLS Certbot lock is held"_ctv);
    }
    return false;
  }
  if (failure)
  {
    failure->snprintf<"failed to lock Certbot certificate: {}"_ctv>(String(strerror(savedErrno)));
  }
  return false;
}

static inline void prodigyCertbotAppendArg(Vector<String>& argv, const char *arg)
{
  String owned;
  owned.assign(arg);
  argv.push_back(std::move(owned));
}

static inline void prodigyCertbotAppendArg(Vector<String>& argv, const String& arg)
{
  argv.push_back(arg);
}

static inline void prodigyCertbotAppendKV(Vector<String>& env, const char *key, const String& value)
{
  String entry;
  entry.assign(key);
  entry.append("="_ctv);
  entry.append(value);
  env.push_back(std::move(entry));
}

static inline bool prodigyBuildCertbotCertonlyCommand(
    const BrainConfig& config,
    const PublicTlsCertificateState& certificate,
    const ProdigyCertbotPaths& paths,
    ProdigyCertbotCommand& command,
    String *failure = nullptr)
{
  command = {};
  if (failure)
  {
    failure->clear();
  }

  const PublicTlsCertificateSpec& spec = certificate.spec;
  const String& certName = certificate.certbotCertName.size() ? certificate.certbotCertName : spec.identityName;
  if (config.acme.accountEmail.size() == 0 || config.acme.termsAgreed == false)
  {
    if (failure)
    {
      failure->assign("ACME accountEmail and termsAgreed are required"_ctv);
    }
    return false;
  }
  if (config.clusterUUID == 0)
  {
    if (failure)
    {
      failure->assign("public TLS Certbot requires cluster UUID"_ctv);
    }
    return false;
  }
  if (certName.size() == 0 || spec.domains.empty())
  {
    if (failure)
    {
      failure->assign("public TLS certificate requires cert name and domains"_ctv);
    }
    return false;
  }
  if (config.controlSocketPath.size() == 0)
  {
    if (failure)
    {
      failure->assign("public TLS Certbot requires cluster control socket"_ctv);
    }
    return false;
  }
  if (prodigySafePathSegment(certName) == false)
  {
    if (failure)
    {
      failure->assign("public TLS cert name must be a safe path segment"_ctv);
    }
    return false;
  }
  if (spec.keyType.equal("ecdsa"_ctv) == false && spec.keyType.equal("rsa"_ctv) == false)
  {
    if (failure)
    {
      failure->assign("public TLS keyType must be ecdsa or rsa"_ctv);
    }
    return false;
  }

  String certbotPath;
  if (paths.certbotPath.size())
  {
    certbotPath = paths.certbotPath;
  }
  else if (config.acme.certbotPath.size())
  {
    certbotPath = config.acme.certbotPath;
  }
  else
  {
    certbotPath.assign(prodigyCertbotManagedPath);
  }
  if (paths.certbotPath.size() && config.acme.certbotPath.size() && paths.certbotPath.equals(config.acme.certbotPath) == false)
  {
    if (failure)
    {
      failure->assign("ACME Certbot path override does not match managed cluster path"_ctv);
    }
    return false;
  }
  if (config.acme.certbotInstall.size() && config.acme.certbotInstall.equals("bundle"_ctv) == false)
  {
    if (failure)
    {
      failure->assign("ACME Certbot install must be bundle"_ctv);
    }
    return false;
  }
  if (config.acme.certbotVersion.size() && config.acme.certbotVersion.equals("5.6.0"_ctv) == false)
  {
    if (failure)
    {
      failure->assign("ACME Certbot version is not bundled"_ctv);
    }
    return false;
  }
  if (certbotPath.size() == 0 || certbotPath[0] != '/')
  {
    if (failure)
    {
      failure->assign("ACME Certbot path must be absolute and Prodigy-managed"_ctv);
    }
    return false;
  }
  String configDir = {};
  String workDir = {};
  String logsDir = {};
  prodigyCertbotEffectiveDirs(config, paths, configDir, workDir, logsDir);

  String authHookPath;
  String cleanupHookPath;
  String deployHookPath;
  if (paths.authHookPath.size())
  {
    authHookPath = paths.authHookPath;
  }
  else
  {
    authHookPath.assign("/usr/lib/prodigy/acme-present-dns-01"_ctv);
  }
  if (paths.cleanupHookPath.size())
  {
    cleanupHookPath = paths.cleanupHookPath;
  }
  else
  {
    cleanupHookPath.assign("/usr/lib/prodigy/acme-cleanup-dns-01"_ctv);
  }
  if (paths.deployHookPath.size())
  {
    deployHookPath = paths.deployHookPath;
  }
  else
  {
    deployHookPath.assign("/usr/lib/prodigy/acme-import-lineage"_ctv);
  }

  prodigyCertbotAppendArg(command.argv, certbotPath);
  prodigyCertbotAppendArg(command.argv, "certonly");
  prodigyCertbotAppendArg(command.argv, "--force-renewal");
  prodigyCertbotAppendArg(command.argv, "--manual");
  prodigyCertbotAppendArg(command.argv, "--preferred-challenges");
  prodigyCertbotAppendArg(command.argv, "dns");
  prodigyCertbotAppendArg(command.argv, "--manual-auth-hook");
  prodigyCertbotAppendArg(command.argv, authHookPath);
  prodigyCertbotAppendArg(command.argv, "--manual-cleanup-hook");
  prodigyCertbotAppendArg(command.argv, cleanupHookPath);
  prodigyCertbotAppendArg(command.argv, "--deploy-hook");
  prodigyCertbotAppendArg(command.argv, deployHookPath);
  prodigyCertbotAppendArg(command.argv, "--no-directory-hooks");
  prodigyCertbotAppendArg(command.argv, "--cert-name");
  prodigyCertbotAppendArg(command.argv, certName);
  prodigyCertbotAppendArg(command.argv, "--key-type");
  prodigyCertbotAppendArg(command.argv, spec.keyType);
  prodigyCertbotAppendArg(command.argv, "--email");
  prodigyCertbotAppendArg(command.argv, config.acme.accountEmail);
  prodigyCertbotAppendArg(command.argv, "--non-interactive");
  prodigyCertbotAppendArg(command.argv, "--agree-tos");
  if (spec.staging)
  {
    prodigyCertbotAppendArg(command.argv, "--test-cert");
  }
  prodigyCertbotAppendArg(command.argv, "--config-dir");
  prodigyCertbotAppendArg(command.argv, configDir);
  prodigyCertbotAppendArg(command.argv, "--work-dir");
  prodigyCertbotAppendArg(command.argv, workDir);
  prodigyCertbotAppendArg(command.argv, "--logs-dir");
  prodigyCertbotAppendArg(command.argv, logsDir);
  for (const String& domain : spec.domains)
  {
    prodigyCertbotAppendArg(command.argv, "-d");
    prodigyCertbotAppendArg(command.argv, domain);
  }

  String clusterText;
  clusterText.assignItoh(config.clusterUUID);
  prodigyCertbotAppendKV(command.env, "PRODIGY_CONTROL_SOCKET", config.controlSocketPath);
  prodigyCertbotAppendKV(command.env, "PRODIGY_CLUSTER_UUID", clusterText);
  prodigyCertbotAppendKV(command.env, "PRODIGY_ACME_CERT_NAME", certName);

  String appText;
  appText.snprintf<"{itoa}"_ctv>(uint64_t(spec.applicationID));
  prodigyCertbotAppendKV(command.env, "PRODIGY_ACME_APPLICATION_ID", appText);

  String deploymentText;
  deploymentText.snprintf<"{itoa}"_ctv>(spec.deploymentID);
  prodigyCertbotAppendKV(command.env, "PRODIGY_ACME_DEPLOYMENT_ID", deploymentText);
  prodigyCertbotAppendKV(command.env, "PRODIGY_ACME_WORMHOLE_NAME", spec.wormholeName);
  prodigyCertbotAppendKV(command.env, "PRODIGY_MOTHERSHIP_SOCKET", config.controlSocketPath);
  if (config.remoteProdigyPath.size())
  {
    String mothershipPath = {};
    mothershipPath.snprintf<"{}/tools/mothership"_ctv>(config.remoteProdigyPath);
    prodigyCertbotAppendKV(command.env, "PRODIGY_MOTHERSHIP", mothershipPath);
  }
  return true;
}

static inline bool prodigyRequiredEnv(const char *name, String& value, String *failure = nullptr)
{
  const char *raw = std::getenv(name);
  if (raw == nullptr || raw[0] == '\0')
  {
    if (failure)
    {
      failure->assign("missing environment variable "_ctv);
      failure->append(name);
    }
    return false;
  }
  value.assign(raw);
  return true;
}

static inline bool prodigyRequiredEnvUInt64(const char *name, uint64_t& value, uint64_t minValue, uint64_t maxValue, String *failure = nullptr)
{
  String raw;
  if (prodigyRequiredEnv(name, raw, failure) == false)
  {
    return false;
  }

  char *end = nullptr;
  errno = 0;
  unsigned long long parsed = std::strtoull(raw.c_str(), &end, 10);
  if (end == raw.c_str() || *end != '\0' || errno != 0 || parsed < minValue || parsed > maxValue)
  {
    if (failure)
    {
      failure->assign("invalid environment variable "_ctv);
      failure->append(name);
    }
    return false;
  }

  value = uint64_t(parsed);
  return true;
}

static inline bool prodigyRequiredClusterUUIDEnv(uint128_t& clusterUUID, String *failure = nullptr)
{
  String raw = {};
  if (prodigyRequiredEnv("PRODIGY_CLUSTER_UUID", raw, failure) == false)
  {
    return false;
  }
  clusterUUID = String::numberFromHexString<uint128_t>(raw);
  if (clusterUUID == 0)
  {
    if (failure)
    {
      failure->assign("invalid environment variable PRODIGY_CLUSTER_UUID"_ctv);
    }
    return false;
  }
  return true;
}

static inline bool prodigyBuildACMEDNS01ChallengeRequestFromEnv(AcmeDNS01ChallengeRequest& request, String *failure = nullptr)
{
  request = {};
  uint64_t app = 0;
  if (prodigyRequiredClusterUUIDEnv(request.clusterUUID, failure) == false ||
      prodigyRequiredEnvUInt64("PRODIGY_ACME_APPLICATION_ID", app, 1, UINT16_MAX, failure) == false ||
      prodigyRequiredEnvUInt64("PRODIGY_ACME_DEPLOYMENT_ID", request.deploymentID, 1, UINT64_MAX, failure) == false ||
      prodigyRequiredEnv("PRODIGY_ACME_WORMHOLE_NAME", request.wormholeName, failure) == false ||
      prodigyRequiredEnv("PRODIGY_ACME_CERT_NAME", request.certName, failure) == false ||
      prodigyRequiredEnv("CERTBOT_IDENTIFIER", request.identifier, failure) == false ||
      prodigyRequiredEnv("CERTBOT_VALIDATION", request.validation, failure) == false)
  {
    return false;
  }
  request.applicationID = uint16_t(app);
  return true;
}

static inline void prodigySplitCertbotDomainList(const String& text, Vector<String>& domains)
{
  domains.clear();
  uint64_t start = 0;
  while (start < text.size())
  {
    while (start < text.size() && std::isspace(static_cast<unsigned char>(text[start])))
    {
      start += 1;
    }
    uint64_t end = start;
    while (end < text.size() && std::isspace(static_cast<unsigned char>(text[end])) == false)
    {
      end += 1;
    }
    if (end > start)
    {
      domains.push_back(text.substr(start, end - start, Copy::yes));
    }
    start = end;
  }
}

static inline bool prodigyBuildACMELineageImportRequestFromEnv(AcmeLineageImportRequest& request, String *failure = nullptr)
{
  request = {};
  uint64_t app = 0;
  String renewedDomains;
  if (prodigyRequiredClusterUUIDEnv(request.clusterUUID, failure) == false ||
      prodigyRequiredEnvUInt64("PRODIGY_ACME_APPLICATION_ID", app, 1, UINT16_MAX, failure) == false ||
      prodigyRequiredEnvUInt64("PRODIGY_ACME_DEPLOYMENT_ID", request.deploymentID, 1, UINT64_MAX, failure) == false ||
      prodigyRequiredEnv("PRODIGY_ACME_WORMHOLE_NAME", request.wormholeName, failure) == false ||
      prodigyRequiredEnv("PRODIGY_ACME_CERT_NAME", request.certName, failure) == false ||
      prodigyRequiredEnv("RENEWED_LINEAGE", request.lineagePath, failure) == false ||
      prodigyRequiredEnv("RENEWED_DOMAINS", renewedDomains, failure) == false)
  {
    return false;
  }
  request.applicationID = uint16_t(app);
  prodigySplitCertbotDomainList(renewedDomains, request.renewedDomains);
  return true;
}

static inline bool prodigyEnvironmentEntryMatchesKey(const char *entry, const String& override)
{
  const uint8_t *equals = static_cast<const uint8_t *>(std::memchr(override.data(), '=', override.size()));
  if (entry == nullptr || equals == nullptr || equals == override.data())
  {
    return false;
  }
  const uint64_t keySize = uint64_t(equals - override.data());
  return std::strncmp(entry, reinterpret_cast<const char *>(override.data()), keySize) == 0 && entry[keySize] == '=';
}

static inline void prodigyBuildEnvironmentWithOverrides(const Vector<String>& overrides, Vector<String>& environment)
{
  environment.clear();
  static const char *base[] = {
      "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
      "LANG=C.UTF-8",
      nullptr,
  };
  for (const char **entry = base; *entry != nullptr; ++entry)
  {
    bool overridden = false;
    for (const String& override : overrides)
    {
      if (prodigyEnvironmentEntryMatchesKey(*entry, override))
      {
        overridden = true;
        break;
      }
    }
    if (overridden == false)
    {
      String copy;
      copy.assign(*entry);
      environment.push_back(std::move(copy));
    }
  }
  for (const String& override : overrides)
  {
    environment.push_back(override);
  }
}

static inline bool prodigySpawnArgv(const Vector<String>& argv, const Vector<String>& extraEnv, pid_t& pid, String *failure = nullptr)
{
  pid = -1;
  if (failure)
  {
    failure->clear();
  }
  if (argv.empty())
  {
    if (failure)
    {
      failure->assign("process argv is empty"_ctv);
    }
    return false;
  }

  Vector<String> env;
  prodigyBuildEnvironmentWithOverrides(extraEnv, env);

  std::vector<char *> rawArgv;
  rawArgv.reserve(argv.size() + 1);
  for (const String& arg : argv)
  {
    rawArgv.push_back(const_cast<char *>(const_cast<String&>(arg).c_str()));
  }
  rawArgv.push_back(nullptr);

  std::vector<char *> rawEnv;
  rawEnv.reserve(env.size() + 1);
  for (const String& entry : env)
  {
    rawEnv.push_back(const_cast<char *>(const_cast<String&>(entry).c_str()));
  }
  rawEnv.push_back(nullptr);

  int spawnRC = posix_spawnp(&pid, rawArgv[0], nullptr, nullptr, rawArgv.data(), rawEnv.data());
  if (spawnRC != 0)
  {
    pid = -1;
    if (failure)
    {
      failure->snprintf<"failed to launch process: {}"_ctv>(String(strerror(spawnRC)));
    }
    return false;
  }
  return true;
}

static inline bool prodigyRunBlockingArgv(const Vector<String>& argv, const Vector<String>& extraEnv, int *exitStatus = nullptr, String *failure = nullptr)
{
  if (exitStatus)
  {
    *exitStatus = -1;
  }
  if (failure)
  {
    failure->clear();
  }
  pid_t pid = -1;
  if (prodigySpawnArgv(argv, extraEnv, pid, failure) == false)
  {
    return false;
  }

  int status = -1;
  for (;;)
  {
    if (waitpid(pid, &status, 0) == pid)
    {
      break;
    }
    if (errno == EINTR)
    {
      continue;
    }
    if (failure)
    {
      failure->snprintf<"failed to wait for process: {}"_ctv>(String(strerror(errno)));
    }
    return false;
  }

  if (WIFEXITED(status))
  {
    int code = WEXITSTATUS(status);
    if (exitStatus)
    {
      *exitStatus = code;
    }
    if (code == 0)
    {
      return true;
    }
    if (failure)
    {
      failure->snprintf<"process exited with status {itoa}"_ctv>(uint64_t(code));
    }
    return false;
  }

  if (WIFSIGNALED(status))
  {
    int signalNumber = WTERMSIG(status);
    if (exitStatus)
    {
      *exitStatus = 128 + signalNumber;
    }
    if (failure)
    {
      failure->snprintf<"process terminated by signal {itoa}"_ctv>(uint64_t(signalNumber));
    }
    return false;
  }

  if (failure)
  {
    failure->assign("process ended with unexpected wait status"_ctv);
  }
  return false;
}
