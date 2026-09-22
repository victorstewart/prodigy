#include <cassert>
#include <prodigy/mothership/mothership.tidesdb.migration.h>

class Hooks final : public MothershipTidesDBMigrationHooks {
public:
  Vector<String> paths, absent, corrupt;
  uint32_t copies = 0, exports = 0, imports = 0, checkpoints = 0, renames = 0, validatesBeforeFirstRename = 0;
  uint32_t failRenameAt = 0, failPersistAt = 0;

  void observe(const MothershipTidesDBMigrationDatabase& database) const { assert(database.label.size() != 0 && database.livePath.size() != 0); }
  bool listed(const Vector<String>& values, const String& path) const { for (const String& value : values) if (value == path) return true; return false; }
  bool exists(const MothershipTidesDBMigrationDatabase& database, const String& path) override { observe(database); return !listed(absent, path) && listed(paths, path); }
  void add(const String& path) { if (!listed(paths, path)) paths.push_back(path); }
  bool copySource(const MothershipTidesDBMigrationDatabase& d, String *) override { observe(d); ++copies; add(d.copiedV9Path); return true; }
  bool runExport(const String&, const MothershipTidesDBMigrationDatabase& d, String *) override { observe(d); ++exports; add(d.streamPath); return true; }
  bool runImport(const String&, const MothershipTidesDBMigrationDatabase& d, String *) override { observe(d); ++imports; add(d.preparedV10Path); return true; }
  bool validate(const MothershipTidesDBMigrationDatabase& d, const String& path, String *) override { observe(d); if (renames == 0) ++validatesBeforeFirstRename; return exists(d, path) && !listed(corrupt, path); }
  bool rename(const MothershipTidesDBMigrationDatabase& d, const String& from, const String& to, String *) override {
    observe(d); assert((from == d.livePath && to == d.retainedV9Path) || (from == d.preparedV10Path && to == d.livePath));
    ++renames;
    if (failRenameAt == renames) return false;
    for (String& path : paths) if (path == from) { path = to; return true; }
    return false;
  }
  bool persist(const MothershipTidesDBMigrationReceipt&, String *) override { ++checkpoints; return checkpoints != failPersistAt; }
};

static MothershipTidesDBMigrationReceipt receipt(Hooks& hooks)
{
  MothershipTidesDBMigrationReceipt value = {};
  value.clusterUUID = 1;
  value.phase = MothershipTidesDBMigrationPhase::writersQuiesced;
  for (uint32_t index = 0; index < 8; ++index) {
    MothershipTidesDBMigrationDatabase db = {};
    db.machineUUID = index + 1;
    db.label.assignItoa(index);
    db.livePath.snprintf<"/live/{itoa}"_ctv>(index);
    db.retainedV9Path.snprintf<"/old/{itoa}"_ctv>(index);
    db.copiedV9Path.snprintf<"/copy/{itoa}"_ctv>(index);
    db.streamPath.snprintf<"/stream/{itoa}"_ctv>(index);
    db.preparedV10Path.snprintf<"/new/{itoa}"_ctv>(index);
    hooks.add(db.livePath);
    value.databases.push_back(std::move(db));
  }
  return value;
}

static bool migrate(MothershipTidesDBMigrationReceipt& value, Hooks& hooks, String& failure)
{
  failure.clear();
  return mothershipMigrateTidesDB9To10Offline(value, "/export"_ctv, "/import"_ctv, hooks, &failure);
}

static void assertCompleted(MothershipTidesDBMigrationReceipt& value, Hooks& hooks, String& failure)
{
  assert(migrate(value, hooks, failure));
  assert(value.phase == MothershipTidesDBMigrationPhase::swapped);
  assert(mothershipTidesDBMigrationAllDatabasesSwapped(value));
  assert(hooks.copies == 8 && hooks.exports == 8 && hooks.imports == 8);
}

static void assertResumeAroundRename(uint32_t failRenameAt)
{
  Hooks hooks;
  MothershipTidesDBMigrationReceipt value = receipt(hooks);
  String failure = {};
  hooks.failRenameAt = failRenameAt;
  assert(!migrate(value, hooks, failure));
  assert(hooks.copies == 8 && hooks.exports == 8 && hooks.imports == 8);
  assert(hooks.validatesBeforeFirstRename == 8);
  hooks.failRenameAt = 0;
  assertCompleted(value, hooks, failure);
  assert(migrate(value, hooks, failure));
  assert(hooks.imports == 8);
}

static void assertResumeAfterCheckpoint(uint32_t failPersistAt)
{
  Hooks hooks;
  MothershipTidesDBMigrationReceipt value = receipt(hooks);
  String failure = {};
  hooks.failPersistAt = failPersistAt;
  assert(!migrate(value, hooks, failure));
  assert(hooks.copies == 8 && hooks.exports == 8 && hooks.imports == 8);
  if (failPersistAt > 1) {
    const uint32_t database = failPersistAt - 2;
    // The failed checkpoint was never durable: reproduce the receipt read by a
    // restart while retaining the completed physical two-rename state.
    value.databases[database].swapped = false;
  }
  hooks.failPersistAt = 0;
  assertCompleted(value, hooks, failure);
  assert(migrate(value, hooks, failure));
  assert(hooks.imports == 8);
}

int main()
{
  {
    Hooks hooks;
    MothershipTidesDBMigrationReceipt value = receipt(hooks);
    String failure = {};
    assertCompleted(value, hooks, failure);
    assert(hooks.validatesBeforeFirstRename == 8); // All imports validate before any rename.
    assert(migrate(value, hooks, failure));
    assert(hooks.imports == 8);
  }

  // Fail before the first rename and after the first rename. Both resumes reuse imports.
  assertResumeAroundRename(1);
  assertResumeAroundRename(2);

  // Interrupt the validation checkpoint and every per-database checkpoint.
  // Checkpoint 2 is exactly after database zero's second rename.
  for (uint32_t checkpoint = 1; checkpoint <= 9; ++checkpoint) assertResumeAfterCheckpoint(checkpoint);

  {
    Hooks hooks;
    MothershipTidesDBMigrationReceipt value = receipt(hooks);
    String failure = {};
    hooks.add(value.databases[0].retainedV9Path);
    hooks.add(value.databases[0].preparedV10Path);
    assert(!migrate(value, hooks, failure)); // live + retained + prepared is ambiguous.
    assert(hooks.imports == 0 && hooks.renames == 0);
  }
  {
    Hooks hooks;
    MothershipTidesDBMigrationReceipt value = receipt(hooks);
    String failure = {};
    hooks.absent.push_back(value.databases[0].livePath);
    hooks.add(value.databases[0].retainedV9Path);
    assert(!migrate(value, hooks, failure)); // Retained-only is not a resumable prepared state.
    assert(hooks.imports == 0 && hooks.renames == 0);
  }
  {
    Hooks hooks;
    MothershipTidesDBMigrationReceipt value = receipt(hooks);
    String failure = {};
    assertCompleted(value, hooks, failure);
    hooks.corrupt.push_back(value.databases[0].livePath);
    assert(!migrate(value, hooks, failure)); // A physically swapped corrupt live directory is rejected.
  }
  {
    Hooks hooks;
    MothershipTidesDBMigrationReceipt value = receipt(hooks);
    String failure = {};
    assertCompleted(value, hooks, failure);
    hooks.absent.push_back(value.databases[0].retainedV9Path);
    assert(!migrate(value, hooks, failure)); // Swapped state requires verified live and retained v9.
  }
  {
    Hooks hooks;
    MothershipTidesDBMigrationReceipt value = receipt(hooks);
    String failure = {};
    value.phase = MothershipTidesDBMigrationPhase::preflighted;
    assert(!migrate(value, hooks, failure));
    value.phase = static_cast<MothershipTidesDBMigrationPhase>(255);
    assert(!migrate(value, hooks, failure));
    value.phase = MothershipTidesDBMigrationPhase::writersQuiesced;
    value.version = 2;
    assert(!migrate(value, hooks, failure));
    assert(hooks.copies == 0 && hooks.renames == 0);
  }
}
