#pragma once

#include <filesystem>
#include <functional>
#include <networking/multiplexer.h>
#include <networking/ring.h>
#include <prodigy/persistent.state.h>

class TestSuite {
public:
  int failed = 0;

  void expect(bool value, const char *name)
  {
    if (!value)
    {
      dprintf(STDERR_FILENO, "FAIL: %s\n", name);
      ++failed;
    }
  }
};

class ScopedPersistentRoot {
public:
  String path = {};

  ScopedPersistentRoot()
  {
    std::filesystem::create_directories(".run");
    char pattern[] = ".run/nametag-prodigy-async-persistence-XXXXXX";
    if (char *created = ::mkdtemp(pattern)) path.assign(created);
  }

  ~ScopedPersistentRoot()
  {
    if (!path.size()) return;
    String secrets = {};
    resolveProdigyPersistentSecretsDBPath(path, secrets);
    std::error_code ignored = {};
    std::filesystem::remove_all(path.c_str(), ignored);
    std::filesystem::remove_all(secrets.c_str(), ignored);
  }
};

class PersistenceRing final : public TimeoutDispatcher {
public:
  RingDispatcher dispatcher;
  TimeoutPacket tick = {};
  TimeoutPacket deadline = {};
  TimeoutPacket drain = {};
  std::function<void()> tickAction = {};
  bool timedOut = false;
  bool shutdown = false;

  PersistenceRing()
  {
    Ring::interfacer = &dispatcher;
    Ring::lifecycler = &dispatcher;
    Ring::exit = false;
    Ring::shuttingDown = false;
    Ring::createRing(64, 128, 8, 2, -1, -1, 8);
    tick.dispatcher = this;
    deadline.dispatcher = this;
    drain.dispatcher = this;
  }

  ~PersistenceRing()
  {
    if (!shutdown) Ring::shutdownForExec();
    Ring::interfacer = nullptr;
    Ring::lifecycler = nullptr;
    Ring::exit = false;
    Ring::shuttingDown = false;
    RingDispatcher::dispatcher = nullptr;
  }

  void armTick(uint64_t ms)
  {
    tick.clear();
    tick.setTimeoutMs(ms);
    Ring::queueTimeout(&tick);
  }

  void armDeadline(uint64_t ms)
  {
    deadline.clear();
    deadline.setTimeoutMs(ms);
    Ring::queueTimeout(&deadline);
  }

  void drainStoppedIO()
  {
    // stop() requests raw-poll cancellation. Let its terminal CQE retire
    // before Ring shutdown, matching the ArtifactIO owner's regression fixture.
    tickAction = {};
    drain.setTimeoutMs(25);
    Ring::queueTimeout(&drain);
    Ring::exit = false;
    Ring::start();
  }

  void dispatchTimeout(TimeoutPacket *packet) override
  {
    if (packet == &tick && tickAction) tickAction();
    if (packet == &drain) Ring::exit = true;
    if (packet == &deadline)
    {
      timedOut = true;
      Ring::exit = true;
    }
  }
};

