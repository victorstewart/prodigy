#pragma once

// The TidesDB 9 -> 10 transition is deliberately an explicit, stopped-world
// Mothership operation.  In particular, this owner must never be called from
// a normal registry/state-store constructor: a v10 reader cannot safely probe
// a v9 directory to decide whether migration is needed.

#include <cstdint>

#include <networking/includes.h>
#include <types/types.containers.h>

enum class MothershipTidesDBMigrationPhase : uint8_t {
  accepted,
  preflighted,
  writersQuiesced,
  copied,
  validated,
  swapped,
  activationStarted,
  completed,
  rollbackRequired,
  rolledBack,
};

class MothershipTidesDBMigrationDatabase {
public:
  uint128_t machineUUID = 0; // zero only for the local Mothership databases
  String label;
  String livePath;
  String retainedV9Path;
  String copiedV9Path;
  String streamPath;
  String preparedV10Path;
  String validationReceiptPath;
  bool swapped = false;
};

class MothershipTidesDBMigrationReceipt {
public:
  uint8_t version = 1;
  uint128_t clusterUUID = 0;
  uint128_t operationID = 0;
  MothershipTidesDBMigrationPhase phase = MothershipTidesDBMigrationPhase::accepted;
  String oldRuntimeSHA256;
  String newRuntimeSHA256;
  String approvedBundleSHA256;
  Vector<MothershipTidesDBMigrationDatabase> databases;
  // Set immediately before starting the replacement runtime.  A failure after
  // this point is not an automatic rollback: a new writer may have committed.
  bool activationBoundaryCrossed = false;
};

template <typename S>
static void serialize(S&& serializer, MothershipTidesDBMigrationDatabase& database)
{
  serializer.value16b(database.machineUUID);
  serializer.text1b(database.label, UINT32_MAX);
  serializer.text1b(database.livePath, UINT32_MAX);
  serializer.text1b(database.retainedV9Path, UINT32_MAX);
  serializer.text1b(database.copiedV9Path, UINT32_MAX);
  serializer.text1b(database.streamPath, UINT32_MAX);
  serializer.text1b(database.preparedV10Path, UINT32_MAX);
  serializer.text1b(database.validationReceiptPath, UINT32_MAX);
  serializer.value1b(database.swapped);
}

template <typename S>
static void serialize(S&& serializer, MothershipTidesDBMigrationReceipt& receipt)
{
  serializer.value1b(receipt.version);
  serializer.value16b(receipt.clusterUUID);
  serializer.value16b(receipt.operationID);
  serializer.value1b(receipt.phase);
  serializer.text1b(receipt.oldRuntimeSHA256, UINT32_MAX);
  serializer.text1b(receipt.newRuntimeSHA256, UINT32_MAX);
  serializer.text1b(receipt.approvedBundleSHA256, UINT32_MAX);
  serializer.object(receipt.databases);
  serializer.value1b(receipt.activationBoundaryCrossed);
}

static inline bool mothershipTidesDBMigrationMayRollback(const MothershipTidesDBMigrationReceipt& receipt)
{
  return receipt.activationBoundaryCrossed == false && receipt.phase != MothershipTidesDBMigrationPhase::completed;
}

static inline bool mothershipTidesDBMigrationAllDatabasesSwapped(const MothershipTidesDBMigrationReceipt& receipt)
{
  if (receipt.databases.size() != 8) return false;
  for (const MothershipTidesDBMigrationDatabase& database : receipt.databases)
    if (database.swapped == false) return false;
  return true;
}

// This is intentionally distinct from mothershipBuildProdigyStopAndDrainCommand:
// that remove-cluster owner kills /containers.slice leaves.  A database-only
// runtime migration must leave those guests and their disks intact.
static inline void mothershipBuildTidesDBMigrationServiceQuiesceCommand(String& command)
{
  command.assign("set -eu; "_ctv);
  command.append(R"SH(
load=$(systemctl show --property=LoadState --value prodigy) || exit 1
[ "$load" != not-found ] || { echo 'prodigy unit is absent' >&2; exit 1; }
kill_mode=$(systemctl show --property=KillMode --value prodigy) || exit 1
[ "$kill_mode" = control-group ] || { echo 'prodigy KillMode is not control-group' >&2; exit 1; }
unit_cgroup=$(systemctl show --property=ControlGroup --value prodigy) || exit 1
case "$unit_cgroup" in /containers.slice*|'') echo 'prodigy unit cgroup is unsafe' >&2; exit 1;; esac
systemctl stop prodigy || { echo 'failed to stop prodigy' >&2; exit 1; }
active=$(systemctl show --property=ActiveState --value prodigy) || exit 1
pid=$(systemctl show --property=MainPID --value prodigy) || exit 1
[ "$pid" = 0 ] || { echo 'prodigy remained active' >&2; exit 1; }
case "$active" in inactive|failed) ;; *) echo 'prodigy service is still transitioning' >&2; exit 1;; esac
# Runtime container leaves are deliberately only observed here.  Do not stop,
# kill, remount, reset, or alter them as part of persistence migration.
for leaf in /sys/fs/cgroup/containers.slice/*.slice/leaf; do
  [ -e "$leaf/cgroup.procs" ] || continue
  cat "$leaf/cgroup.procs" >/dev/null || { echo 'container cgroup is unreadable' >&2; exit 1; }
done
)SH"_ctv);
}

// The production caller supplies local/remote transport and a durable receipt
// writer.  Keeping filesystem/process authority behind this narrow seam lets
// the ordering be tested without opening an old database through TidesDB10.
class MothershipTidesDBMigrationHooks {
public:
  virtual ~MothershipTidesDBMigrationHooks() = default;
  virtual bool exists(const MothershipTidesDBMigrationDatabase& database, const String& path) = 0;
  virtual bool copySource(const MothershipTidesDBMigrationDatabase& database, String *failure) = 0;
  virtual bool runExport(const String& exporter, const MothershipTidesDBMigrationDatabase& database, String *failure) = 0;
  virtual bool runImport(const String& importer, const MothershipTidesDBMigrationDatabase& database, String *failure) = 0;
  virtual bool validate(const MothershipTidesDBMigrationDatabase& database, const String& path, String *failure) = 0;
  virtual bool rename(const MothershipTidesDBMigrationDatabase& database, const String& from, const String& to, String *failure) = 0;
  virtual bool persist(const MothershipTidesDBMigrationReceipt& receipt, String *failure) = 0;
};

static inline bool mothershipTidesDBMigrationCheckpoint(MothershipTidesDBMigrationHooks& hooks, MothershipTidesDBMigrationReceipt& receipt, MothershipTidesDBMigrationPhase phase, String *failure)
{
  receipt.phase = phase;
  return hooks.persist(receipt, failure);
}

static inline bool mothershipMigrateTidesDB9To10Offline(MothershipTidesDBMigrationReceipt& receipt,
                                                          const String& exporter, const String& importer,
                                                          MothershipTidesDBMigrationHooks& hooks, String *failure = nullptr)
{
  if (failure) failure->clear();
  if (receipt.version != 1 || receipt.phase < MothershipTidesDBMigrationPhase::writersQuiesced || receipt.phase > MothershipTidesDBMigrationPhase::swapped || receipt.databases.size() != 8 || exporter.size() == 0 || importer.size() == 0 || receipt.activationBoundaryCrossed)
  { if (failure) failure->assign("invalid or activated TidesDB migration receipt"_ctv); return false; }
  for (MothershipTidesDBMigrationDatabase& db : receipt.databases) {
    if (db.livePath.size() == 0 || db.retainedV9Path.size() == 0 || db.copiedV9Path.size() == 0 || db.streamPath.size() == 0 || db.preparedV10Path.size() == 0)
    { if (failure) failure->assign("incomplete TidesDB migration database paths"_ctv); return false; }
    const bool live = hooks.exists(db, db.livePath), retained = hooks.exists(db, db.retainedV9Path), prepared = hooks.exists(db, db.preparedV10Path);
    if (db.swapped) {
      if (!live || !retained || prepared || !hooks.validate(db, db.livePath, failure)) return false;
      continue;
    }
    // A persisted per-database checkpoint can be lost after the second rename.
    // The verified live v10 directory plus retained v9 directory is then the
    // durable physical completion record; never recreate a prepared directory.
    if (live && retained && !prepared) {
      if (!hooks.validate(db, db.livePath, failure)) return false;
      continue;
    }
    // The only other resumable pre-checkpoint states are the initial live v9
    // directory (with or without a prepared v10 directory), or the state just
    // after live was retained and before prepared became live.
    if ((!live && retained && !prepared) || (!live && !retained) || (live && retained && prepared))
    { if (failure) failure->assign("invalid partial TidesDB migration paths"_ctv); return false; }
    if (!prepared) {
      if (!hooks.exists(db, db.copiedV9Path) && !hooks.copySource(db, failure)) return false;
      if (!hooks.exists(db, db.streamPath) && !hooks.runExport(exporter, db, failure)) return false;
      if (!hooks.runImport(importer, db, failure)) return false;
    }
    if (!hooks.validate(db, db.preparedV10Path, failure)) return false;
  }
  if (!mothershipTidesDBMigrationCheckpoint(hooks, receipt, MothershipTidesDBMigrationPhase::validated, failure)) return false;
  for (MothershipTidesDBMigrationDatabase& db : receipt.databases) {
    // Resume either side of the two renames. A retained old directory proves
    // the first rename completed; no source is ever removed.
    if (!db.swapped) {
      const bool live = hooks.exists(db, db.livePath), old = hooks.exists(db, db.retainedV9Path), prepared = hooks.exists(db, db.preparedV10Path);
      if (live && old && prepared) { if (failure) failure->assign("ambiguous TidesDB rename state"_ctv); return false; }
      if (live && !old && prepared && !hooks.rename(db, db.livePath, db.retainedV9Path, failure)) return false;
      if (!hooks.exists(db, db.livePath) && hooks.exists(db, db.preparedV10Path) && !hooks.rename(db, db.preparedV10Path, db.livePath, failure)) return false;
      if (!hooks.exists(db, db.livePath) || !hooks.exists(db, db.retainedV9Path) || hooks.exists(db, db.preparedV10Path) || !hooks.validate(db, db.livePath, failure)) { if (failure) failure->assign("incomplete or unverified TidesDB rename state"_ctv); return false; }
      db.swapped = true;
      if (!hooks.persist(receipt, failure)) return false;
    }
  }
  return mothershipTidesDBMigrationCheckpoint(hooks, receipt, MothershipTidesDBMigrationPhase::swapped, failure);
}
