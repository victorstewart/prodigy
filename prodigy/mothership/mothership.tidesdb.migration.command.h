#pragma once

#include <filesystem>
#include <fstream>
#include <map>
#include <stdexcept>
#include <string>
#include <sys/file.h>
#include <prodigy/mothership/mothership.tidesdb.migration.h>
#include <prodigy/mothership/mothership.cluster.registry.h>
#include <prodigy/mothership/mothership.virtual.datacenter.recovery.h>
#include <prodigy/remote.bootstrap.h>

// Explicit operator-requested format migration. Normal readers never call this
// owner, and the old database format is opened only by the bundled v9 exporter
// against a private copy. Mothership retains launch and filesystem authority.
namespace MothershipTidesMigration {
namespace fs = std::filesystem;
inline String text(const std::string& value) { String result; result.assign(value.data(), value.size()); return result; }
inline std::string str(const String& value) { return std::string(reinterpret_cast<const char *>(value.data()), value.size()); }
inline std::string quote(const std::string& value) { String result; prodigyAppendShellSingleQuoted(result, text(value)); return str(result); }
inline void require(bool value, const char *message) { if (!value) throw std::runtime_error(message); }
// `grep -q` intentionally stops after its first match.  Under pipefail that
// can leave printf with SIGPIPE when /proc contains many descriptors, turning
// a valid retained preflight into a false rejection.  Redirect ordinary grep
// output instead, so it consumes the complete descriptor listing while its
// exact-match exit status remains the check result.
inline std::string descriptorLockCheckCommand(const std::string& lockPath) {
  return "printf '%s\\n' \"$fds\" | grep -Fx "+quote(lockPath)+" > /dev/null; ";
}
inline std::string read(const fs::path& path) {
  std::ifstream input(path, std::ios::binary); require(bool(input), "migration input unreadable");
  return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}
inline void durable(const fs::path& path, const String& bytes) {
  String directory = text(path.parent_path().string()), failure;
  require(mothershipVDCDurableWrite(directory, path.filename().c_str(), bytes, &failure), "migration checkpoint write failed");
}
inline std::string digest(const fs::path& path) {
  String value, failure; require(prodigyComputeFileSHA256Hex(text(path.string()), value, &failure), "migration file digest failed"); return str(value);
}
inline uint128_t uuid(const std::string& value) {
  require(value.size() >= 3 && value.size() <= 34 && value.substr(0, 2) == "0x", "migration UUID must be hexadecimal");
  require(value.substr(2).find_first_not_of("0123456789abcdef")==std::string::npos,"invalid migration UUID");
  uint128_t result=String::numberFromHexString<uint128_t>(text(value));
  require(result != 0, "zero migration UUID"); return result;
}
inline std::string field(simdjson::dom::element object, const char *key) {
  std::string_view value; require(object[key].get_string().get(value) == simdjson::SUCCESS && !value.empty(), "missing migration plan string");
  require(value.find('\0') == std::string_view::npos, "NUL in migration plan"); return std::string(value);
}
inline void pathCheck(const std::string& value) {
  fs::path p(value); require(p.is_absolute() && p.lexically_normal() == p && value.size() > 5 && value.back() != '/', "unsafe migration path");
  for (const auto& item : p) require(item != "..", "parent traversal in migration path");
}
struct Machine {
  uint128_t uuid = 0; std::string linuxID, address; MothershipProdigyClusterMachine registered;
};
struct Plan {
  std::string identity, operationRoot, registryRoot, bundle, runtimeRoot, statePath, secretsPath, oldRuntimeSHA, oldBundleSHA, planSHA;
  bool retainedRecovery = false;
  uint128_t operationID = 0, clusterUUID = 0;
  std::vector<Machine> machines;
};
inline Plan parse(const char *file) {
  struct stat st {}; require(::lstat(file, &st) == 0 && S_ISREG(st.st_mode) && (st.st_mode & 0077) == 0 && st.st_nlink == 1 && st.st_uid == ::geteuid(), "migration plan must be a private owned regular file");
  require(st.st_size > 0 && st.st_size <= 65536, "migration plan size invalid");
  simdjson::dom::parser parser; simdjson::dom::element doc;
  const auto contents = read(file); require(parser.parse(contents).get(doc) == simdjson::SUCCESS, "migration plan JSON invalid");
  uint64_t version = 0; require(doc["schemaVersion"].get_uint64().get(version) == simdjson::SUCCESS && version == 1, "unsupported migration plan");
  Plan p; p.identity = field(doc, "clusterUUID"); p.clusterUUID = uuid(p.identity); p.operationID = uuid(field(doc,"operationID"));
  p.operationRoot=field(doc,"operationRoot"); p.registryRoot=field(doc,"registryRoot"); p.bundle=field(doc,"bundlePath");
  p.runtimeRoot=field(doc,"runtimeRoot"); p.statePath=field(doc,"statePath"); p.secretsPath=field(doc,"secretsPath");
  p.oldRuntimeSHA=field(doc,"expectedOldRuntimeSHA256"); p.oldBundleSHA=field(doc,"expectedOldBundleSHA256"); p.planSHA=digest(file);
  for (const auto& v : {p.operationRoot,p.registryRoot,p.bundle,p.runtimeRoot,p.statePath,p.secretsPath}) pathCheck(v);
  require(prodigyIsSHA256HexDigest(text(p.oldRuntimeSHA)) && prodigyIsSHA256HexDigest(text(p.oldBundleSHA)), "invalid old runtime identities");
  require(p.operationRoot.find_first_not_of("/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")==std::string::npos,"operation root cannot contain systemd specifiers or whitespace");
  require(p.statePath != p.secretsPath && p.runtimeRoot != p.operationRoot, "overlapping migration paths");
  simdjson::dom::array machines; require(doc["machines"].get_array().get(machines) == simdjson::SUCCESS, "migration machines missing");
  for (auto value : machines) { Machine m; m.uuid=uuid(field(value,"machineUUID")); m.linuxID=field(value,"linuxMachineID"); m.address=field(value,"sshAddress");
    require(m.linuxID.size()==32 && m.linuxID.find_first_not_of("0123456789abcdef")==std::string::npos, "invalid Linux machine identity");
    for (const auto& old : p.machines) require(old.uuid!=m.uuid && old.linuxID!=m.linuxID && old.address!=m.address, "duplicate migration machine");
    p.machines.push_back(std::move(m)); }
  require(p.machines.size()==3, "migration requires the explicitly selected three-Brain cluster");
  return p;
}

// Adoption intent can predate runtime UUID assignment. The persisted topology
// supplies that UUID; registered adoption data remains the SSH authority.
inline void resolveRegisteredMachine(const MothershipProdigyCluster& cluster, Machine& machine) {
  const MothershipProdigyClusterMachine *registered=nullptr;
  for(const auto& candidate:cluster.machines) if(str(candidate.ssh.address)==machine.address) {
    require(registered==nullptr,"ambiguous registered migration SSH address"); registered=&candidate;
  }
  require(registered && registered->isBrain && (registered->uuid==0 || registered->uuid==machine.uuid),"migration adoption identity mismatch");
  ClusterMachine adopted; mothershipFillAdoptedClusterMachine(*registered,adopted);
  const ClusterMachine *runtime=nullptr;
  for(const auto& candidate:cluster.topology.machines) if(candidate.uuid==machine.uuid) {
    require(runtime==nullptr,"ambiguous migration runtime UUID"); runtime=&candidate;
  }
  require(runtime && runtime->isBrain && runtime->sameIdentityAs(adopted) && str(runtime->ssh.address)==machine.address,"migration runtime identity differs from registered topology");
  require(registered->ssh.port && str(registered->ssh.user)=="root" && !registered->ssh.hostPublicKeyOpenSSH.empty(),"registered migration SSH authority incomplete");
  machine.registered=*registered;
}

inline std::string quiesceServiceCommand(bool retainedRecoveryVerified = false) {
  String stop; mothershipBuildTidesDBMigrationServiceQuiesceCommand(stop, retainedRecoveryVerified);
  return "if test \"$(systemctl show -p MainPID --value prodigy)\" != 0; then\n"+str(stop)+"\nfi; test \"$(systemctl show -p MainPID --value prodigy)\" = 0; ";
}

class Execution final : public MothershipTidesDBMigrationHooks {
public:
  Plan plan; MothershipProdigyCluster cluster; MothershipTidesDBMigrationReceipt receipt;
  std::map<uint128_t, Machine*> machines; std::string localRuntime, remoteRoot, remoteRuntime; int lockFD=-1; std::vector<int> databaseLocks; std::vector<std::pair<std::string,std::string>> artifactLinks;
  explicit Execution(Plan p): plan(std::move(p)) {
    localRuntime=plan.operationRoot+"/runtime"; remoteRoot=plan.operationRoot+"/guest"; remoteRuntime=remoteRoot+"/runtime";
  }
  ~Execution() { for (int fd : databaseLocks) ::close(fd); if(lockFD>=0) ::close(lockFD); }
  std::string tool(uint128_t machine, const char *name) const { return (machine ? remoteRuntime : localRuntime)+"/tools/"+name; }
  std::string environment(uint128_t machine) const { return "LD_LIBRARY_PATH="+quote((machine ? remoteRuntime : localRuntime)+"/lib")+" "; }
  bool command(uint128_t machine, const std::string& command, String *failure=nullptr, String *output=nullptr) {
    if (!machine) return prodigyRunLocalShellCommand(text("set -euo pipefail; "+command), failure);
    auto found=machines.find(machine); if(found==machines.end()) { if(failure) failure->assign("migration machine is not registered"_ctv); return false; }
    const auto& ssh=found->second->registered.ssh; LIBSSH2_SESSION *session=nullptr; int fd=-1;
    const Vault::SSHKeyPackage *package=ssh.privateKeyPath.empty() ? &cluster.bootstrapSshKeyPackage : nullptr;
    if(!prodigyConnectBlockingSSHSession(ssh.address,ssh.port,ssh.hostPublicKeyOpenSSH,ssh.user,ssh.privateKeyPath,package,session,fd,failure)) return false;
    const std::string guarded="set -euo pipefail; test \"$(cat /etc/machine-id)\" = "+quote(found->second->linuxID)+"; "+command;
    bool okay=prodigyRunBlockingSSHCommand(session,fd,text(guarded),output,failure,600000); prodigyCloseBlockingSSHSession(session,fd); return okay;
  }
  void run(uint128_t machine,const std::string& cmd) { String failure; if(!command(machine,cmd,&failure)) throw std::runtime_error("Mothership migration command failed: "+str(failure)); }
  void upload(Machine& machine,const std::string& from,const std::string& to) {
    const auto& ssh=machine.registered.ssh; LIBSSH2_SESSION *session=nullptr; int fd=-1; String failure;
    const Vault::SSHKeyPackage *package=ssh.privateKeyPath.empty() ? &cluster.bootstrapSshKeyPackage : nullptr;
    require(prodigyConnectBlockingSSHSession(ssh.address,ssh.port,ssh.hostPublicKeyOpenSSH,ssh.user,ssh.privateKeyPath,package,session,fd,&failure), "migration SSH upload connection failed");
    bool okay=prodigyUploadLocalFileToSSHSession(session,fd,text(from),text(to),0600,&failure,600000); prodigyCloseBlockingSSHSession(session,fd); require(okay,"migration bundle upload failed");
  }
  bool exists(const MothershipTidesDBMigrationDatabase& db,const String& p) override { return command(db.machineUUID,"test -e "+quote(str(p))); }
  bool copySource(const MothershipTidesDBMigrationDatabase& db,String *failure) override {
    // Do not publish a partial copy as a resumable source. Reflinks share no
    // mutable inode; neither exporter nor importer receives the original path.
    auto to=str(db.copiedV9Path), from=str(db.livePath);
    return command(db.machineUUID,"set -eu; umask 077; test -d "+quote(from)+"; test ! -L "+quote(from)+"; test ! -e "+quote(to)+"; test ! -e "+quote(to+".partial")+"; cp -a --reflink=auto -- "+quote(from)+" "+quote(to+".partial")+"; sync -f "+quote(to+".partial")+"; mv -T -- "+quote(to+".partial")+" "+quote(to)+"; sync -f "+quote(fs::path(to).parent_path().string()),failure);
  }
  bool runExport(const String&,const MothershipTidesDBMigrationDatabase& db,String *failure) override {
    return command(db.machineUUID,environment(db.machineUUID)+quote(tool(db.machineUUID,"prodigy_tidesdb9_export"))+" "+quote(str(db.copiedV9Path))+" "+quote(str(db.streamPath)),failure);
  }
  bool runImport(const String&,const MothershipTidesDBMigrationDatabase& db,String *failure) override {
    return command(db.machineUUID,environment(db.machineUUID)+quote(tool(db.machineUUID,"prodigy_tidesdb10_import"))+" "+quote(str(db.streamPath))+" "+quote(str(db.preparedV10Path)),failure);
  }
  std::string readPath(uint128_t machine,const std::string& path) {
    if(!machine) return read(path);
    String output,failure; require(command(machine,"test \"$(stat -c %s "+quote(path)+")\" -le 65536; cat "+quote(path),&failure,&output),"migration receipt readback failed");
    return str(output);
  }
  bool verifyDB(const MothershipTidesDBMigrationDatabase& db,const String& path,String *failure,bool evidence) {
    const auto captured=str(db.validationReceiptPath)+".capture";
    if(!command(db.machineUUID,"umask 077; "+environment(db.machineUUID)+quote(tool(db.machineUUID,"prodigy_tidesdb10_import"))+" --verify "+quote(str(db.streamPath))+" "+quote(str(path))+" > "+quote(captured),failure)) return false;
    const auto output=readPath(db.machineUUID,captured);
    simdjson::dom::parser parser; simdjson::dom::element value; uint64_t records=0,families=0;
    require(parser.parse(output).get(value)==simdjson::SUCCESS && value["records"].get_uint64().get(records)==simdjson::SUCCESS && value["columnFamilies"].get_uint64().get(families)==simdjson::SUCCESS,"migration validation JSON malformed");
    const auto streamSHA=field(value,"streamSHA256"); require(prodigyIsSHA256HexDigest(text(streamSHA)) && families<=128,"migration validation metadata invalid");
    if(evidence) {
      String machineText; machineText.snprintf<"{itoh}"_ctv>(db.machineUUID);
      String binding; binding.assign("{\"planSHA256\":"_ctv); prodigyAppendEscapedJSONStringLiteral(binding,text(plan.planSHA));
      binding.append(",\"machineUUID\":"_ctv); prodigyAppendEscapedJSONStringLiteral(binding,machineText);
      binding.append(",\"database\":"_ctv); prodigyAppendEscapedJSONStringLiteral(binding,db.label);
      binding.append(",\"databasePath\":"_ctv); prodigyAppendEscapedJSONStringLiteral(binding,path);
      binding.append(",\"validation\":"_ctv); binding.append(text(output)); binding.append("}\n"_ctv);
      const auto destination=str(db.validationReceiptPath);
      return command(db.machineUUID,"umask 077; printf %s "+quote(str(binding))+" > "+quote(destination+".new")+"; sync -f "+quote(destination+".new")+"; mv -T "+quote(destination+".new")+" "+quote(destination)+"; sync -f "+quote(fs::path(destination).parent_path().string()),failure);
    }
    return true;
  }
  bool validate(const MothershipTidesDBMigrationDatabase& db,const String& path,String *failure) override {
    return verifyDB(db,path,failure,true);
  }
  bool rename(const MothershipTidesDBMigrationDatabase& db,const String& from,const String& to,String *failure) override {
    return command(db.machineUUID,"set -eu; test ! -e "+quote(str(to))+"; test \"$(stat -c %d "+quote(str(from))+")\" = \"$(stat -c %d "+quote(fs::path(str(to)).parent_path().string())+")\"; mv -T -- "+quote(str(from))+" "+quote(str(to))+"; sync -f "+quote(fs::path(str(to)).parent_path().string()),failure);
  }
  bool persist(const MothershipTidesDBMigrationReceipt& state,String *) override {
    auto copy=state; String bytes; BitseryEngine::serialize(bytes,copy); durable(fs::path(plan.operationRoot)/"receipt",bytes); return true;
  }
  void addDB(uint128_t machine,const std::string& label,const std::string& live,const std::string& root) {
    MothershipTidesDBMigrationDatabase db; db.machineUUID=machine; db.label=text(label); db.livePath=text(live);
    db.retainedV9Path=text(live+(plan.retainedRecovery ? ".retained10-" : ".tidesdb9-")+plan.planSHA.substr(0,16)); db.copiedV9Path=text(root+"/"+label+(plan.retainedRecovery ? ".copy10" : ".copy9"));
    db.streamPath=text(root+"/"+label+".kv"); db.preparedV10Path=text(root+"/"+label+".new10"); db.validationReceiptPath=text(root+"/"+label+".validation"); if(plan.retainedRecovery && label=="secrets") { db.copiedV9Path=text(root+"/state.copy10.secrets"); db.preparedV10Path=text(root+"/state.new10.secrets"); }
    receipt.databases.push_back(std::move(db));
  }
  void populateDatabases() {
    receipt.databases.clear();
    if (!plan.retainedRecovery) { addDB(0,"clusters",plan.registryRoot+"/clusters",plan.operationRoot); addDB(0,"provider_credentials",plan.registryRoot+"/provider_credentials",plan.operationRoot); }
    for(auto& m:plan.machines) { addDB(m.uuid,"state",plan.statePath,remoteRoot); addDB(m.uuid,"secrets",plan.secretsPath,remoteRoot); }
  }
  void prepareDB(MothershipTidesDBMigrationDatabase& db) {
    String failure;
    if(!exists(db,db.preparedV10Path)) {
      if(!exists(db,db.copiedV9Path)) require(copySource(db,&failure),"migration source copy failed");
      if(!exists(db,db.streamPath)) require(runExport({},db,&failure),"migration v9 export failed");
      require(runImport({},db,&failure),"migration v10 import failed");
    }
    require(validate(db,db.preparedV10Path,&failure),"migration prepared data validation failed");
  }
  void lockRegistry() {
    for (const char *name : {"clusters", "provider_credentials"}) {
      const auto index=std::string(name)=="clusters" ? 0 : 1;
      const auto& db=receipt.databases[index];
      const auto path=(fs::exists(str(db.retainedV9Path)) ? str(db.retainedV9Path) : str(db.livePath))+"/LOCK";
      int fd=::open(path.c_str(),O_RDWR|O_CLOEXEC|O_NOFOLLOW); require(fd>=0,"old Mothership database lock unavailable");
      struct flock range {}; range.l_type=F_WRLCK; range.l_whence=SEEK_SET;
      if(::fcntl(fd,F_SETLK,&range)!=0) { ::close(fd); throw std::runtime_error("another Mothership process holds the old database"); }
      databaseLocks.push_back(fd);
    }
  }
  void initialize() {
    const char *registryEnvironment=::getenv("PRODIGY_MOTHERSHIP_TIDESDB_PATH");
    require(registryEnvironment && plan.registryRoot==registryEnvironment,"migration registry differs from selected Mothership owner");
    require(fs::weakly_canonical(plan.operationRoot)==fs::path(plan.operationRoot),"migration operation root contains a symlink");
    fs::create_directories(plan.operationRoot); require(::chmod(plan.operationRoot.c_str(),0700)==0,"cannot protect migration operation root");
    lockFD=::open((plan.operationRoot+"/lock").c_str(),O_CREAT|O_RDWR|O_CLOEXEC|O_NOFOLLOW,0600);
    require(lockFD>=0 && ::flock(lockFD,LOCK_EX|LOCK_NB)==0,"migration operation already running");
    auto planFile=fs::path(plan.operationRoot)/"plan.sha256";
    if(fs::exists(planFile)) require(read(planFile)==plan.planSHA,"migration plan differs from retained operation"); else durable(planFile,text(plan.planSHA));
    String bundleSHA,failure; require(prodigyApproveBundleArtifact(text(plan.bundle),bundleSHA,&failure),"migration bundle not approved");
    require(prodigyInstallBundleToRoot(text(plan.bundle),text(localRuntime),&failure),"migration bundle staging failed");
    require(digest(localRuntime+"/prodigy.bundle.tar.zst")==str(bundleSHA),"staged migration bundle differs");
    const auto newRuntimeSHA=digest(localRuntime+"/prodigy"); require(newRuntimeSHA!=plan.oldRuntimeSHA,"migration requires a successor runtime");
    if(fs::exists(plan.operationRoot+"/receipt")) {
      String bytes=text(read(plan.operationRoot+"/receipt")); require(BitseryEngine::deserializeSafe(bytes,receipt),"migration receipt invalid");
      require(receipt.operationID==plan.operationID && receipt.clusterUUID==plan.clusterUUID && str(receipt.approvedBundleSHA256)==str(bundleSHA) && str(receipt.newRuntimeSHA256)==newRuntimeSHA && str(receipt.oldRuntimeSHA256)==plan.oldRuntimeSHA && receipt.databases.size()==(plan.retainedRecovery ? 6 : 8),"migration receipt identity mismatch");
      auto stored=receipt; populateDatabases();
      for(size_t i=0;i<receipt.databases.size();++i) { const auto& a=stored.databases[i]; const auto& b=receipt.databases[i];
        require(a.machineUUID==b.machineUUID && a.label==b.label && a.livePath==b.livePath && a.retainedV9Path==b.retainedV9Path && a.copiedV9Path==b.copiedV9Path && a.streamPath==b.streamPath && a.preparedV10Path==b.preparedV10Path && a.validationReceiptPath==b.validationReceiptPath,"migration receipt paths differ from immutable plan"); }
      receipt=std::move(stored);
    } else {
      receipt.clusterUUID=plan.clusterUUID; receipt.operationID=plan.operationID; receipt.oldRuntimeSHA256=text(plan.oldRuntimeSHA); receipt.newRuntimeSHA256=text(newRuntimeSHA); receipt.approvedBundleSHA256=bundleSHA;
      populateDatabases();
      persist(receipt,nullptr);
    }
  }

  void resolveMachines() {
    // The shadow registry is read only after export/import has verified it. Its
    // credential-bearing original remains v9 and is never opened by this build.
    auto& registry=receipt.databases[0];
    const auto authority=plan.operationRoot+"/clusters.authority10";
    if(!fs::exists(authority)) {
      require(receipt.phase < MothershipTidesDBMigrationPhase::validated,"migration authority copy is missing after commit preparation");
      prepareDB(registry);
      run(0,"cp -a --reflink=auto "+quote(str(registry.preparedV10Path))+" "+quote(authority)+"; sync -f "+quote(authority));
    }
    String failure; require(verifyDB(registry,text(authority),&failure,false),"migration registry authority copy differs from export");
    {
      MothershipClusterRegistry shadow(text(authority));
      require(shadow.getClusterByIdentity(text(plan.identity),cluster,&failure),"migrated registry cannot resolve selected cluster");
    }
    require(cluster.clusterUUID==plan.clusterUUID && cluster.nBrains==3 && cluster.machines.size()==3 && cluster.deploymentMode!=MothershipClusterDeploymentMode::test,"migration target is not the registered three-machine production cluster");
    require(str(cluster.remoteProdigyPath)==plan.runtimeRoot,"migration runtime path differs from registered bootstrap owner");
    for(auto& m:plan.machines) {
      resolveRegisteredMachine(cluster,m);
      machines.emplace(m.uuid,&m);
    }
  }
  std::string observeContainers() const {
    return R"SH(snapshot_containers() {
      for leaf in /sys/fs/cgroup/containers.slice/*.slice/leaf; do
        [ -f "$leaf/cgroup.procs" ] || continue
        for pid in $(cat "$leaf/cgroup.procs"); do
          [ -r "/proc/$pid/stat" ] || return 1
          line=$(cat "/proc/$pid/stat") || return 1
          rest=${line##*) }
          start=$(printf '%s\n' "$rest" | awk '{print $20}')
          [ -n "$start" ] || return 1
          printf '%s %s %s\n' "${leaf#/sys/fs/cgroup}" "$pid" "$start"
        done
      done | sort
    }
)SH";
  }
  void buildArtifactManifest() {
    std::string manifest;
    for(const auto& entry:fs::recursive_directory_iterator(localRuntime)) {
      const auto relative=fs::relative(entry.path(),localRuntime).string();
      require(relative.find_first_of("\n\r\\")==std::string::npos,"unsupported bundle filename");
      if(entry.is_symlink()) {
        require(fs::weakly_canonical(entry.path()).string().starts_with(localRuntime+"/"),"bundle symlink escapes staging root");
        artifactLinks.emplace_back(entry.path().lexically_relative(localRuntime).string(),fs::read_symlink(entry.path()).string());
      } else if(entry.is_regular_file()) manifest+=digest(entry.path())+"  "+relative+"\n";
      else require(entry.is_directory(),"unexpected bundle file type");
    }
    durable(fs::path(plan.operationRoot)/"runtime.files.sha256",text(manifest));
  }
  void verifyRuntime(Machine& machine,const std::string& root) {
    std::string cmd="cd "+quote(root)+"; sha256sum --quiet -c "+quote(remoteRoot+"/runtime.files.sha256")+"; ";
    for(const auto& [name,target]:artifactLinks) cmd+="test -L "+quote(name)+"; test \"$(readlink "+quote(name)+")\" = "+quote(target)+"; ";
    for(const auto& name:{"prodigy","tools/prodigy_tidesdb9_export","tools/prodigy_tidesdb10_import"}) cmd+="test -f "+quote(name)+"; test ! -L "+quote(name)+"; test -x "+quote(name)+"; ";
    run(machine.uuid,cmd);
  }
  void stageAndPreflight() {
    for(auto& machine:plan.machines) {
      const auto id=machine.uuid;
      run(id,"test \"$(realpath -m "+quote(remoteRoot)+")\" = "+quote(remoteRoot)+"; umask 077; mkdir -p "+quote(remoteRoot)+"; chmod 700 "+quote(remoteRoot));
      MothershipTidesDBMigrationDatabase marker; marker.machineUUID=id;
      if(!exists(marker,text(remoteRuntime))) {
        const auto bundle=remoteRoot+"/successor.bundle.tar.zst";
        upload(machine,plan.bundle,bundle); upload(machine,plan.bundle+".sha256",bundle+".sha256");
        String install; prodigyBuildBundleInstallCommand(text(bundle),text(remoteRuntime),install);
        run(id,"test \"$(sha256sum "+quote(bundle)+" | cut -d' ' -f1)\" = "+quote(str(receipt.approvedBundleSHA256))+"; "+str(install));
      }
      upload(machine,plan.operationRoot+"/runtime.files.sha256",remoteRoot+"/runtime.files.sha256");
      verifyRuntime(machine,remoteRuntime);
      run(id,"test \"$(sha256sum "+quote(remoteRuntime+"/prodigy")+" | cut -d' ' -f1)\" = "+quote(str(receipt.newRuntimeSHA256)));
      if(receipt.phase < MothershipTidesDBMigrationPhase::preflighted) {
        const auto binary=plan.runtimeRoot+"/prodigy";
        std::string cmd="test \"$(sha256sum "+quote(binary)+" | cut -d' ' -f1)\" = "+quote(plan.oldRuntimeSHA)+"; test \"$(sha256sum "+quote(plan.runtimeRoot+"/prodigy.bundle.tar.zst")+" | cut -d' ' -f1)\" = "+quote(plan.oldBundleSHA)+"; ";
        cmd+="test \"$(systemctl show -p KillMode --value prodigy)\" = control-group; test \"$(systemctl show -p Restart --value prodigy)\" = always; ";
        cmd+="pid=$(systemctl show -p MainPID --value prodigy); test \"$pid\" -gt 1; test \"$(readlink -f /proc/$pid/exe)\" = "+quote(binary)+"; test \"$(cat /proc/$pid/cgroup)\" = '0::/system.slice/prodigy.service'; ";
        cmd+="fds=$(for f in /proc/$pid/fd/*; do readlink \"$f\" || true; done); ";
        for(const auto& dbPath:{plan.statePath,plan.secretsPath}) cmd+="test -d "+quote(dbPath)+"; test ! -L "+quote(dbPath)+"; test \"$(stat -c %d "+quote(dbPath)+")\" = \"$(stat -c %d "+quote(remoteRoot)+")\"; "+descriptorLockCheckCommand(dbPath+"/LOCK");
        cmd+=observeContainers()+"snapshot_containers > "+quote(remoteRoot+"/containers.check")+"; ";
        cmd+="if test -f "+quote(remoteRoot+"/containers.before")+"; then cmp "+quote(remoteRoot+"/containers.before")+" "+quote(remoteRoot+"/containers.check")+"; else mv "+quote(remoteRoot+"/containers.check")+" "+quote(remoteRoot+"/containers.before")+"; sync -f "+quote(remoteRoot)+"; fi";
        run(id,cmd);
      }
    }
  }
  // A retained-recovery successor may adopt an already stopped, fenced fleet.
  // Every successor fence is durable before any predecessor fence is removed.
  void stageInheritedQuiesced(const Execution& predecessor) {
    require(predecessor.plan.clusterUUID==plan.clusterUUID && predecessor.plan.runtimeRoot==plan.runtimeRoot && predecessor.plan.machines.size()==plan.machines.size(),"inherited fence target differs");
    const auto oldFence=predecessor.fencePath();
    const auto oldDropin="/etc/systemd/system/prodigy.service.d/99-tidesdb-migration-"+predecessor.plan.planSHA.substr(0,16)+".conf";
    const auto newDropin="/etc/systemd/system/prodigy.service.d/99-tidesdb-migration-"+plan.planSHA.substr(0,16)+".conf";
    const auto content="[Unit]\nConditionPathExists=!"+fencePath()+"\n";
    for(auto& machine:plan.machines) {
      const auto id=machine.uuid;
      run(id,"test \"$(realpath -m "+quote(remoteRoot)+")\" = "+quote(remoteRoot)+"; umask 077; mkdir -p "+quote(remoteRoot)+"; chmod 700 "+quote(remoteRoot));
      MothershipTidesDBMigrationDatabase marker; marker.machineUUID=id;
      if(!exists(marker,text(remoteRuntime))) {
        const auto bundle=remoteRoot+"/successor.bundle.tar.zst";
        upload(machine,plan.bundle,bundle); upload(machine,plan.bundle+".sha256",bundle+".sha256");
        String install; prodigyBuildBundleInstallCommand(text(bundle),text(remoteRuntime),install);
        run(id,"test \"$(sha256sum "+quote(bundle)+" | cut -d' ' -f1)\" = "+quote(str(receipt.approvedBundleSHA256))+"; "+str(install));
      }
      upload(machine,plan.operationRoot+"/runtime.files.sha256",remoteRoot+"/runtime.files.sha256"); verifyRuntime(machine,remoteRuntime);
      std::string cmd="test \"$(systemctl show -p MainPID --value prodigy)\" = 0; ";
      cmd+="if test -e "+quote(fencePath())+"; then test \"$(cat "+quote(fencePath())+")\" = "+quote(plan.planSHA)+"; else test \"$(cat "+quote(oldFence)+")\" = "+quote(predecessor.plan.planSHA)+"; printf %s "+quote(plan.planSHA)+" > "+quote(fencePath()+".new")+"; sync -f "+quote(fencePath()+".new")+"; mv -T "+quote(fencePath()+".new")+" "+quote(fencePath())+"; sync -f "+quote(remoteRoot)+"; fi; ";
      cmd+="mkdir -p /etc/systemd/system/prodigy.service.d; if test -e "+quote(newDropin)+"; then printf %s "+quote(content)+" | cmp -s - "+quote(newDropin)+"; else printf %s "+quote(content)+" > "+quote(newDropin+".new")+"; sync -f "+quote(newDropin+".new")+"; mv -T "+quote(newDropin+".new")+" "+quote(newDropin)+"; sync -f /etc/systemd/system/prodigy.service.d; systemctl daemon-reload; fi; systemctl daemon-reload";
      run(id,cmd);
    }
    for(auto& machine:plan.machines) {
      std::string cmd="test \"$(systemctl show -p MainPID --value prodigy)\" = 0; test \"$(cat "+quote(fencePath())+")\" = "+quote(plan.planSHA)+"; ";
      cmd+="if test -e "+quote(oldFence)+"; then test \"$(cat "+quote(oldFence)+")\" = "+quote(predecessor.plan.planSHA)+"; rm -- "+quote(oldFence)+"; sync -f "+quote(predecessor.remoteRoot)+"; fi; ";
      cmd+="if test -e "+quote(oldDropin)+"; then printf %s "+quote("[Unit]\nConditionPathExists=!"+oldFence+"\n")+" | cmp -s - "+quote(oldDropin)+"; rm -- "+quote(oldDropin)+"; sync -f /etc/systemd/system/prodigy.service.d; fi; systemctl daemon-reload; ";
      cmd+=observeContainers()+"snapshot_containers > "+quote(remoteRoot+"/containers.inherited")+"; if test -f "+quote(remoteRoot+"/containers.before")+"; then cmp "+quote(remoteRoot+"/containers.before")+" "+quote(remoteRoot+"/containers.inherited")+"; else mv "+quote(remoteRoot+"/containers.inherited")+" "+quote(remoteRoot+"/containers.before")+"; sync -f "+quote(remoteRoot)+"; fi";
      run(machine.uuid,cmd);
    }
  }
  // Retirement has separately verified the canonical inventory.  Replace only
  // the operation-local stopped baseline that activation compares; no runtime
  // or database path is changed here.
  void acceptStoppedContainerBaseline() {
    for(auto& machine:plan.machines)run(machine.uuid,observeContainers()+"snapshot_containers > "+quote(remoteRoot+"/containers.canonical")+"; mv -T "+quote(remoteRoot+"/containers.canonical")+" "+quote(remoteRoot+"/containers.before")+"; sync -f "+quote(remoteRoot));
  }
  std::string fencePath() const { return remoteRoot+"/writers-fenced"; }
  void fenceWriters() {
    const auto dropin="/etc/systemd/system/prodigy.service.d/99-tidesdb-migration-"+plan.planSHA.substr(0,16)+".conf";
    const auto content="[Unit]\nConditionPathExists=!"+fencePath()+"\n";
    for(auto& machine:plan.machines) {
      // Persist the startup fence before stop. Unlike a runtime-only systemd
      // mask it survives a host reboot during directory or executable swaps.
      std::string cmd="umask 077; printf %s "+quote(plan.planSHA)+" > "+quote(fencePath()+".new")+"; sync -f "+quote(fencePath()+".new")+"; mv -T "+quote(fencePath()+".new")+" "+quote(fencePath())+"; sync -f "+quote(remoteRoot)+"; mkdir -p /etc/systemd/system/prodigy.service.d; ";
      cmd+="printf %s "+quote(content)+" > "+quote(dropin+".new")+"; sync -f "+quote(dropin+".new")+"; mv -T "+quote(dropin+".new")+" "+quote(dropin)+"; sync -f /etc/systemd/system/prodigy.service.d; systemctl daemon-reload";
      run(machine.uuid,cmd);
    }
  }
  void unfence(Machine& machine) {
    run(machine.uuid,"if test -e "+quote(fencePath())+"; then test \"$(cat "+quote(fencePath())+")\" = "+quote(plan.planSHA)+"; rm -- "+quote(fencePath())+"; sync -f "+quote(remoteRoot)+"; fi");
  }
  void quiesce() {
    fenceWriters();
    for(auto& machine:plan.machines) {
      // A stopped unit remains stopped through process failure/reentry; no
      // application leaf belongs to this service's cgroup.
      run(machine.uuid,quiesceServiceCommand(plan.retainedRecovery)+observeContainers()+"snapshot_containers > "+quote(remoteRoot+"/containers.stopped")+"; cmp "+quote(remoteRoot+"/containers.before")+" "+quote(remoteRoot+"/containers.stopped"));
    }
    receipt.phase=MothershipTidesDBMigrationPhase::writersQuiesced; persist(receipt,nullptr);
  }
  void installRuntimes() {
    const auto retained=plan.runtimeRoot+(plan.retainedRecovery ? ".retained10-" : ".tidesdb9-")+plan.planSHA.substr(0,16);
    for(auto& machine:plan.machines) {
      // Both names are on the preflighted filesystem. Reentry examines exact
      // binary identities instead of treating path existence as installation.
      std::string cmd="test \"$(systemctl show -p MainPID --value prodigy)\" = 0; ";
      cmd+="if test -e "+quote(retained)+"; then test \"$(sha256sum "+quote(retained+"/prodigy")+" | cut -d' ' -f1)\" = "+quote(plan.oldRuntimeSHA)+"; else test \"$(sha256sum "+quote(plan.runtimeRoot+"/prodigy")+" | cut -d' ' -f1)\" = "+quote(plan.oldRuntimeSHA)+"; mv -T "+quote(plan.runtimeRoot)+" "+quote(retained)+"; sync -f "+quote(fs::path(plan.runtimeRoot).parent_path().string())+"; fi; ";
      // Keep the utility staging root throughout the operation, including after
      // activation, so receipt validation never depends on the active root.
      cmd+="if test ! -e "+quote(plan.runtimeRoot)+"; then test ! -e "+quote(plan.runtimeRoot+".migration-new")+"; cp -a --reflink=auto "+quote(remoteRuntime)+" "+quote(plan.runtimeRoot+".migration-new")+"; sync -f "+quote(plan.runtimeRoot+".migration-new")+"; mv -T "+quote(plan.runtimeRoot+".migration-new")+" "+quote(plan.runtimeRoot)+"; sync -f "+quote(fs::path(plan.runtimeRoot).parent_path().string())+"; fi; ";
      cmd+="test \"$(sha256sum "+quote(plan.runtimeRoot+"/prodigy")+" | cut -d' ' -f1)\" = "+quote(str(receipt.newRuntimeSHA256)); run(machine.uuid,cmd);
    }
  }
  void activate() {
    require(mothershipTidesDBMigrationAllDatabasesSwapped(receipt),"not all databases are prepared for activation");
    if(!receipt.activationBoundaryCrossed) {
      for(auto& machine:plan.machines) {
        verifyRuntime(machine,plan.runtimeRoot);
        run(machine.uuid,"test \"$(systemctl show -p MainPID --value prodigy)\" = 0; "+observeContainers()+"snapshot_containers > "+quote(remoteRoot+"/containers.pre-activation")+"; cmp "+quote(remoteRoot+"/containers.before")+" "+quote(remoteRoot+"/containers.pre-activation"));
      }
      receipt.activationBoundaryCrossed=true; receipt.phase=MothershipTidesDBMigrationPhase::activationStarted; persist(receipt,nullptr);
    }
    for(auto& machine:plan.machines) {
      upload(machine,plan.operationRoot+"/runtime.files.sha256",remoteRoot+"/runtime.files.sha256");
      verifyRuntime(machine,plan.runtimeRoot);
      unfence(machine);
      run(machine.uuid,"test \"$(sha256sum "+quote(plan.runtimeRoot+"/prodigy")+" | cut -d' ' -f1)\" = "+quote(str(receipt.newRuntimeSHA256))+"; systemctl start prodigy; systemctl is-active --quiet prodigy; pid=$(systemctl show -p MainPID --value prodigy); test \"$pid\" -gt 1; test \"$(sha256sum /proc/$pid/exe | cut -d' ' -f1)\" = "+quote(str(receipt.newRuntimeSHA256)));
    }
    receipt.phase=MothershipTidesDBMigrationPhase::completed; persist(receipt,nullptr);
  }
  void rollback() {
    initialize(); require(!receipt.activationBoundaryCrossed,"automatic rollback is forbidden after new writers may have committed");
    lockRegistry(); resolveMachines();
    // No stop is needed before preflight: that phase cannot have changed a
    // service or original database. Later phases must restore every old owner
    // before restarting any Brain.
    if(receipt.phase<MothershipTidesDBMigrationPhase::preflighted) { receipt.phase=MothershipTidesDBMigrationPhase::rolledBack; persist(receipt,nullptr); return; }
    if(receipt.phase==MothershipTidesDBMigrationPhase::preflighted) {
      // Before quiescence is checkpointed, no database or runtime swap can have
      // begun. Remove startup fences and restart only already-stopped old units.
      for(auto& db:receipt.databases) require(exists(db,db.livePath) && !exists(db,db.retainedV9Path),"unexpected database swap before quiescence");
      for(auto& m:plan.machines) run(m.uuid,"test \"$(sha256sum "+quote(plan.runtimeRoot+"/prodigy")+" | cut -d' ' -f1)\" = "+quote(plan.oldRuntimeSHA));
      for(auto& m:plan.machines) { unfence(m); run(m.uuid,"systemctl start prodigy; systemctl is-active --quiet prodigy"); }
      receipt.phase=MothershipTidesDBMigrationPhase::rolledBack; persist(receipt,nullptr); return;
    }
    for(auto& m:plan.machines) run(m.uuid,quiesceServiceCommand());
    receipt.phase=MothershipTidesDBMigrationPhase::rollbackRequired; persist(receipt,nullptr);
    for(auto& db:receipt.databases) {
      if(exists(db,db.retainedV9Path)) {
        String failure;
        if(exists(db,db.livePath)) {
          require(!exists(db,db.preparedV10Path) && validate(db,db.livePath,&failure),"rollback found unverified live data");
          require(rename(db,db.livePath,db.preparedV10Path,&failure),"rollback could not retain prepared v10 data");
        }
        require(rename(db,db.retainedV9Path,db.livePath,&failure),"rollback could not restore original database");
      }
      db.swapped=false; persist(receipt,nullptr);
    }
    const auto retained=plan.runtimeRoot+".tidesdb9-"+plan.planSHA.substr(0,16);
    for(auto& m:plan.machines) {
      std::string cmd="if test -e "+quote(retained)+"; then test \"$(sha256sum "+quote(retained+"/prodigy")+" | cut -d' ' -f1)\" = "+quote(plan.oldRuntimeSHA)+"; if test -e "+quote(plan.runtimeRoot)+"; then test \"$(sha256sum "+quote(plan.runtimeRoot+"/prodigy")+" | cut -d' ' -f1)\" = "+quote(str(receipt.newRuntimeSHA256))+"; test ! -e "+quote(remoteRoot+"/rolled-back-runtime")+"; mv -T "+quote(plan.runtimeRoot)+" "+quote(remoteRoot+"/rolled-back-runtime")+"; fi; mv -T "+quote(retained)+" "+quote(plan.runtimeRoot)+"; sync -f "+quote(fs::path(plan.runtimeRoot).parent_path().string())+"; fi; test \"$(sha256sum "+quote(plan.runtimeRoot+"/prodigy")+" | cut -d' ' -f1)\" = "+quote(plan.oldRuntimeSHA); run(m.uuid,cmd);
    }
    for(auto& m:plan.machines) { unfence(m); run(m.uuid,"systemctl start prodigy; systemctl is-active --quiet prodigy"); }
    receipt.phase=MothershipTidesDBMigrationPhase::rolledBack; persist(receipt,nullptr);
  }
  void execute() {
    initialize();
    require(receipt.phase < MothershipTidesDBMigrationPhase::rollbackRequired,"migration is in rollback state");
    buildArtifactManifest();
    if(receipt.phase==MothershipTidesDBMigrationPhase::completed) { resolveMachines(); activate(); return; }
    if(!receipt.activationBoundaryCrossed) lockRegistry();
    resolveMachines();
    if(receipt.activationBoundaryCrossed) { activate(); return; }
    if(receipt.phase < MothershipTidesDBMigrationPhase::preflighted) prepareDB(receipt.databases[1]);
    stageAndPreflight();
    if(receipt.phase < MothershipTidesDBMigrationPhase::preflighted) { receipt.phase=MothershipTidesDBMigrationPhase::preflighted; persist(receipt,nullptr); }
    if(receipt.phase<MothershipTidesDBMigrationPhase::writersQuiesced) quiesce();
    else for(auto& m:plan.machines) run(m.uuid,"test \"$(systemctl show -p MainPID --value prodigy)\" = 0");
    String failure;
    if(!mothershipMigrateTidesDB9To10Offline(receipt,"prodigy_tidesdb9_export"_ctv,"prodigy_tidesdb10_import"_ctv,*this,&failure))
      throw std::runtime_error("migration database preparation/swap failed: "+str(failure));
    installRuntimes(); activate();
  }

};

inline bool run(const char *planPath, bool rollback, String *failure) {
  try { Execution execution(parse(planPath)); if(rollback) execution.rollback(); else execution.execute(); return true; }
  catch(const std::exception& error) { if(failure) failure->assign(error.what()); return false; }
}
} // namespace MothershipTidesMigration
