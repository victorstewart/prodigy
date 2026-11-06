#include <prodigy/mothership/mothership.file.limits.h>

#include <array>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

static void require(bool condition, const char *message)
{
  if (condition == false)
  {
    throw std::runtime_error(message);
  }
}

static void setLimit(rlim_t soft, rlim_t hard)
{
  const rlimit limit = {soft, hard};
  require(setrlimit(RLIMIT_NOFILE, &limit) == 0, "set test descriptor limit");
}

struct ProcessResult {
  int exitCode = -1;
  std::string output;
};

static ProcessResult runMothershipWithLimit(const char *binary, const char *registryRoot, rlim_t soft, rlim_t hard)
{
  int pipeFDs[2] = {-1, -1};
  require(pipe(pipeFDs) == 0, "create mothership output pipe");

  const pid_t child = fork();
  require(child >= 0, "fork mothership child");
  if (child == 0)
  {
    const rlimit limit = {soft, hard};
    if (setrlimit(RLIMIT_NOFILE, &limit) != 0)
    {
      _exit(126);
    }
    (void)dup2(pipeFDs[1], STDOUT_FILENO);
    (void)dup2(pipeFDs[1], STDERR_FILENO);
    (void)close(pipeFDs[0]);
    (void)close(pipeFDs[1]);
    if (setenv("PRODIGY_MOTHERSHIP_TIDESDB_PATH", registryRoot, 1) != 0)
    {
      _exit(125);
    }
    char *const arguments[] = {const_cast<char *>(binary), const_cast<char *>("printClusters"), nullptr};
    execv(binary, arguments);
    _exit(127);
  }

  (void)close(pipeFDs[1]);
  ProcessResult result = {};
  char buffer[1024] = {};
  while (true)
  {
    const ssize_t readBytes = read(pipeFDs[0], buffer, sizeof(buffer));
    if (readBytes == 0)
    {
      break;
    }
    require(readBytes > 0 || errno == EINTR, "read mothership output");
    if (readBytes > 0)
    {
      result.output.append(buffer, size_t(readBytes));
    }
  }
  (void)close(pipeFDs[0]);

  int status = 0;
  pid_t waited;
  do
  {
    waited = waitpid(child, &status, 0);
  } while (waited < 0 && errno == EINTR);
  require(waited == child && WIFEXITED(status), "mothership child exited");
  result.exitCode = WEXITSTATUS(status);
  return result;
}

template <typename Test>
static void inChild(Test test)
{
  const pid_t child = fork();
  require(child >= 0, "fork test child");
  if (child == 0)
  {
    try
    {
      test();
      _exit(0);
    } catch (const std::exception& error)
    {
      std::fprintf(stderr, "FAIL: %s\n", error.what());
      _exit(1);
    }
  }
  int status = 0;
  pid_t waited;
  do
  {
    waited = waitpid(child, &status, 0);
  } while (waited < 0 && errno == EINTR);
  require(waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "child test passed");
}

static tidesdb_t *openDescriptorFixture(const char *path)
{
  tidesdb_config_t config = tidesdb_default_config();
  config.db_path = const_cast<char *>(path);
  config.log_level = TDB_LOG_NONE;
  config.num_flush_threads = 1;
  config.num_compaction_threads = 1;
  config.value_separation_threshold = 1;
  config.vlog_segment_size = 4096;
  tidesdb_t *db = nullptr;
  require(tidesdb_open(&config, &db) == TDB_SUCCESS, "open descriptor fixture");
  return db;
}

static void createNonemptySegmentFixture(const char *path)
{
  tidesdb_t *db = openDescriptorFixture(path);
  tidesdb_column_family_config_t config = tidesdb_default_column_family_config();
  require(tidesdb_create_column_family(db, "clusters", &config) == TDB_SUCCESS,
          "create descriptor fixture column family");
  tidesdb_column_family_t *columnFamily = tidesdb_get_column_family(db, "clusters");
  require(columnFamily != nullptr, "get descriptor fixture column family");

  std::array<uint8_t, 8192> value = {};
  value.fill('v');
  for (uint32_t index = 0; index < 1061; ++index)
  {
    char key[32] = {};
    const int keySize = std::snprintf(key, sizeof(key), "cluster-%04u", index);
    require(keySize > 0 && size_t(keySize) < sizeof(key), "render descriptor fixture key");
    tidesdb_txn_t *transaction = nullptr;
    require(tidesdb_txn_begin(db, &transaction) == TDB_SUCCESS, "begin descriptor fixture write");
    require(tidesdb_txn_put(transaction, columnFamily, reinterpret_cast<const uint8_t *>(key),
                            size_t(keySize), value.data(), value.size(), 0) == TDB_SUCCESS,
            "write descriptor fixture value");
    require(tidesdb_txn_commit(transaction) == TDB_SUCCESS, "commit descriptor fixture write");
    tidesdb_txn_free(transaction);
  }
  require(tidesdb_flush_memtable(db) == TDB_SUCCESS, "flush descriptor fixture");
  require(tidesdb_close(db) == TDB_SUCCESS, "close descriptor fixture");
}

static void verifyNonemptySegmentRecovery(const char *path, rlim_t hardLimit)
{
  inChild([&] {
    setLimit(1024, hardLimit);
    require(mothershipPrepareFileLimit(), "raise descriptor recovery limit");
    tidesdb_t *db = openDescriptorFixture(path);
    tidesdb_db_stats_t stats = {};
    require(tidesdb_get_db_stats(db, &stats) == TDB_SUCCESS, "read descriptor recovery stats");
    require(stats.vlog_segment_count > 1024, "recover more than 1024 nonempty value-log segments");
    auto *cf = tidesdb_get_column_family(db, "clusters");
    require(cf != nullptr, "recover fixture column family");
    tidesdb_txn_t *read = nullptr;
    require(tidesdb_txn_begin(db, &read) == TDB_SUCCESS, "begin fixture read");
    std::array<uint8_t, 8192> expected = {};
    expected.fill('v');
    for (const char *key : {"cluster-0000", "cluster-1060"})
    {
      uint8_t *value = nullptr;
      size_t size = 0;
      require(tidesdb_txn_get(read, cf, reinterpret_cast<const uint8_t *>(key), std::strlen(key), &value, &size) == TDB_SUCCESS,
              "read recovered separated value");
      const bool matches = size == expected.size() && std::memcmp(value, expected.data(), size) == 0;
      tidesdb_free(value);
      require(matches, "verify recovered separated value");
    }
    tidesdb_txn_free(read);
    std::fprintf(stderr, "Recovered %llu segments and verified both boundary records\n",
                 static_cast<unsigned long long>(stats.vlog_segment_count));
    require(tidesdb_close(db) == TDB_SUCCESS, "close recovered descriptor fixture");
  });
}

int main(int argc, char *argv[])
{
  const bool policyOnly = argc == 2 && std::strcmp(argv[1], "--policy-only") == 0;
  try
  {
    require(argc == 1 || policyOnly, "usage: prodigy_mothership_file_limits_unit [--policy-only]");
    rlimit inherited = {};
    require(getrlimit(RLIMIT_NOFILE, &inherited) == 0, "read inherited limit");
    require(inherited.rlim_max >= mothershipRequiredOpenFiles, "test needs hard limit >= 16384");
    inChild([&] {
      setLimit(1024, inherited.rlim_max);
      require(mothershipPrepareFileLimit(), "raise inherited 1024 soft limit");
      rlimit raised = {};
      require(getrlimit(RLIMIT_NOFILE, &raised) == 0, "read raised limit");
      require(raised.rlim_cur >= mothershipRequiredOpenFiles && raised.rlim_max == inherited.rlim_max,
              "raise soft limit without changing hard limit");
    });
    inChild([&] {
      const rlim_t higher = inherited.rlim_max;
      setLimit(higher, higher);
      require(mothershipPrepareFileLimit(), "accept sufficient inherited limit");
      rlimit after = {};
      require(getrlimit(RLIMIT_NOFILE, &after) == 0 && after.rlim_cur == higher,
              "never lower an inherited limit");
    });
    inChild([] {
      setLimit(1024, 1024);
      FILE *errors = tmpfile();
      require(errors != nullptr, "capture hard-limit diagnostic");
      require(mothershipPrepareFileLimit(errors) == false, "reject inadequate hard limit");
      rewind(errors);
      char message[512] = {};
      require(std::fread(message, 1, sizeof(message) - 1, errors) > 0, "read diagnostic");
      fclose(errors);
      require(std::strstr(message, "16384") && std::strstr(message, "1024") &&
                  std::strstr(message, "LimitNOFILE"),
              "actionable limit diagnostic");
    });

    char descriptorFixture[] = "/tmp/prodigy-mothership-file-limits-vlog-XXXXXX";
    require(mkdtemp(descriptorFixture) != nullptr, "create descriptor fixture directory");
    try
    {
      inChild([&] {
        require(mothershipPrepareFileLimit(), "prepare descriptor fixture limit");
        createNonemptySegmentFixture(descriptorFixture);
      });
      verifyNonemptySegmentRecovery(descriptorFixture, inherited.rlim_max);
      std::filesystem::remove_all(descriptorFixture);
    } catch (...)
    {
      std::filesystem::remove_all(descriptorFixture);
      throw;
    }

    if (policyOnly == false)
    {
      char registryRoot[] = "/tmp/prodigy-mothership-file-limits-registry-XXXXXX";
      require(mkdtemp(registryRoot) != nullptr, "create isolated mothership registry root");
      try
      {
        const ProcessResult mothership = runMothershipWithLimit(
            PRODIGY_TEST_BINARY_DIR "/mothership", registryRoot, 1024, 1024);
        require(mothership.exitCode == EXIT_FAILURE, "mothership rejects inadequate hard limit");
        require(mothership.output.find("mothership requires at least 16384 open files") != std::string::npos &&
                    mothership.output.find("effective limit is 1024") != std::string::npos,
                "mothership main reports actionable limit diagnostic");
        std::filesystem::remove_all(registryRoot);
      } catch (...)
      {
        std::filesystem::remove_all(registryRoot);
        throw;
      }
    }

    std::puts(policyOnly ? "PASS: Mothership file-limit policy" : "PASS: Mothership file-limit policy and CLI preflight");
    return 0;
  } catch (const std::exception& error)
  {
    std::fprintf(stderr, "FAIL: %s\n", error.what());
    return 1;
  }
}
