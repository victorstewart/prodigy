#include <cassert>
#include <prodigy/mothership/mothership.tidesdb.migration.command.h>

int main(int argc, char **argv)
{
  using namespace MothershipTidesMigration;
  assert(argc == 4);
  const auto root=fs::current_path()/".run"/("migration-command-"+std::to_string(::getpid()));
  assert(!fs::exists(root)); fs::create_directories(root/"tools"); ::chmod(root.c_str(),0700);
  fs::create_symlink(fs::absolute(argv[2]),root/"tools/prodigy_tidesdb9_export");
  fs::create_symlink(fs::absolute(argv[3]),root/"tools/prodigy_tidesdb10_import");
  Plan plan; plan.operationRoot=root.string(); plan.planSHA=std::string(64,'a');
  Execution execution(plan); execution.localRuntime=root.string();
  execution.receipt.clusterUUID=1; execution.receipt.operationID=2;
  execution.receipt.phase=MothershipTidesDBMigrationPhase::writersQuiesced;
  for(unsigned i=0;i<8;++i) {
    const auto label="database-"+std::to_string(i), path=(root/label).string();
    execution.run(0,quote(fs::absolute(argv[1]).string())+" "+quote(path));
    execution.addDB(0,label,path,root.string());
  }
  String failure;
  assert(mothershipMigrateTidesDB9To10Offline(execution.receipt,"export"_ctv,"import"_ctv,execution,&failure));
  assert(execution.receipt.phase==MothershipTidesDBMigrationPhase::swapped);
  assert(mothershipMigrateTidesDB9To10Offline(execution.receipt,"export"_ctv,"import"_ctv,execution,&failure));
  MothershipTidesDBMigrationReceipt persisted;
  String bytes=text(read(root/"receipt")); assert(BitseryEngine::deserializeSafe(bytes,persisted));
  assert(persisted.databases.size()==8 && mothershipTidesDBMigrationAllDatabasesSwapped(persisted));
  for(auto& db:persisted.databases) {
    assert(fs::is_directory(str(db.livePath)) && fs::is_directory(str(db.retainedV9Path)) && !fs::exists(str(db.preparedV10Path)));
    assert(execution.validate(db,db.livePath,&failure));
  }
  // A resumed operation must retain each remote database's host authority.
  for(size_t i=0;i<persisted.databases.size();++i) persisted.databases[i].machineUUID=i+100;
  BitseryEngine::serialize(bytes,persisted);
  MothershipTidesDBMigrationReceipt roundtrip;
  assert(BitseryEngine::deserializeSafe(bytes,roundtrip));
  for(size_t i=0;i<roundtrip.databases.size();++i) assert(roundtrip.databases[i].machineUUID==i+100);
  String stop; mothershipBuildTidesDBMigrationServiceQuiesceCommand(stop);
  assert(str(stop).find("systemctl stop prodigy")!=std::string::npos);
  assert(str(stop).find("cgroup.kill")==std::string::npos && str(stop).find("pkill")==std::string::npos);
  assert(uuid("0x850fa69cddf33ccdb965f709303710c6")!=0);
  bool rejected=false; try { pathCheck("/var/lib/../prod"); } catch(const std::exception&) { rejected=true; } assert(rejected);
  fs::remove_all(root);
}
