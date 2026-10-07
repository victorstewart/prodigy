#pragma once

#include <cctype>
#include <cstdint>
#include <cstring>
#include <simdjson.h>

#include <networking/includes.h>
#include <prodigy/types.h>

// This is intentionally only a single, externally-authorized VM resize request.
// It does not retain desired hardware state or own any guest lifecycle policy.
struct MothershipMachineResizePlan {
  String schema, clusterUUID, targetMachineUUID, controllerMachineID, guestMachineID, expectedGuestBootID;
  String hypervisorAddress, hypervisorUser, hypervisorPrivateKeyPath, hypervisorHostPublicKey, hypervisorNativeID;
  uint16_t hypervisorPort = 0;
  String supervisorPath, supervisorSHA256, configPath, configSHA256, ingressPolicyPath, ingressPolicySHA256, unit, operationID;
  uint64_t expectedPID = 0, expectedStarttime = 0;
  uint32_t targetCPUs = 0, targetMemoryMiB = 0;
};

static inline bool mothershipMachineResizeHexDigest(const String& value, uint64_t length = 64)
{
  if (value.size() != length) return false;
  for (uint64_t index = 0; index < value.size(); ++index)
    if (!((value.data()[index] >= '0' && value.data()[index] <= '9') || (value.data()[index] >= 'a' && value.data()[index] <= 'f'))) return false;
  return true;
}

static inline bool mothershipMachineResizeAbsolutePath(const String& value)
{
  return value.size() > 1 && value.data()[0] == '/' && std::memchr(value.data(), '\0', value.size()) == nullptr;
}

static inline bool mothershipMachineResizeSafeToken(const String& value)
{
  if (value.size() == 0 || value.size() > 255) return false;
  for (uint64_t index = 0; index < value.size(); ++index) {
    const uint8_t c = value.data()[index];
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
          (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.')) return false;
  }
  return true;
}

static inline bool mothershipValidateMachineResizePlan(const MothershipMachineResizePlan& plan, String *failure = nullptr)
{
  auto reject = [&](const char *reason) { if (failure) failure->assign(reason); return false; };
  if (!plan.schema.equal("prodigy.mothership.kvm-resize.v1"_ctv)) return reject("machine resize plan schema invalid");
  if (!mothershipMachineResizeSafeToken(plan.clusterUUID) || !mothershipMachineResizeSafeToken(plan.targetMachineUUID) ||
      !mothershipMachineResizeSafeToken(plan.controllerMachineID) || !mothershipMachineResizeSafeToken(plan.guestMachineID) ||
      !mothershipMachineResizeSafeToken(plan.expectedGuestBootID) || !mothershipMachineResizeSafeToken(plan.hypervisorNativeID) ||
      !mothershipMachineResizeSafeToken(plan.unit) || !mothershipMachineResizeSafeToken(plan.operationID)) return reject("machine resize plan identity invalid");
  if (plan.hypervisorAddress.size() == 0 || plan.hypervisorUser.size() == 0 || plan.hypervisorHostPublicKey.size() == 0 ||
      !mothershipMachineResizeAbsolutePath(plan.hypervisorPrivateKeyPath) || plan.hypervisorPort == 0 || !mothershipMachineResizeAbsolutePath(plan.supervisorPath) || !mothershipMachineResizeAbsolutePath(plan.configPath) || !mothershipMachineResizeAbsolutePath(plan.ingressPolicyPath)) return reject("machine resize plan endpoint invalid");
  if (!mothershipMachineResizeHexDigest(plan.supervisorSHA256) || !mothershipMachineResizeHexDigest(plan.configSHA256) || !mothershipMachineResizeHexDigest(plan.ingressPolicySHA256)) return reject("machine resize plan sha256 invalid");
  if (!mothershipMachineResizeHexDigest(plan.controllerMachineID, 32) ||
      !mothershipMachineResizeHexDigest(plan.guestMachineID, 32) ||
      !mothershipMachineResizeHexDigest(plan.hypervisorNativeID, 32) ||
      !prodigyCanonicalOperationUUID(plan.operationID) ||
      !prodigyCanonicalOperationUUID(plan.expectedGuestBootID)) return reject("machine resize machine or operation identity invalid");
  if (plan.expectedPID <= 1 || plan.expectedStarttime == 0 || plan.targetCPUs == 0 || plan.targetMemoryMiB == 0) return reject("machine resize plan target invalid");
  if (failure) failure->clear();
  return true;
}

static inline void mothershipAppendMachineResizeShellQuoted(String& command, const String& argument)
{
  command.append('\'');
  for (uint64_t index = 0; index < argument.size(); ++index) {
    if (argument.data()[index] == '\'') command.append("'\\''"_ctv);
    else command.append(argument.data() + index, 1);
  }
  command.append('\'');
}

enum class MothershipMachineResizePhase : uint8_t { preflight, prepare, resize };

static inline bool mothershipBuildMachineResizeCommand(const MothershipMachineResizePlan& plan, MothershipMachineResizePhase phase, String& command, String *failure = nullptr)
{
  if (!mothershipValidateMachineResizePlan(plan, failure)) return false;
  command.clear();
  mothershipAppendMachineResizeShellQuoted(command, plan.supervisorPath);
  if (phase == MothershipMachineResizePhase::preflight) command.append(" preflight"_ctv);
  else if (phase == MothershipMachineResizePhase::prepare) command.append(" prepare"_ctv);
  else command.append(" resize"_ctv);
  auto append = [&](const char *name, const String& value) { command.append(' '); command.append(name); command.append(' '); mothershipAppendMachineResizeShellQuoted(command, value); };
  auto appendNumber = [&](const char *name, uint64_t value) { String text = {}; text.assignItoa(value); append(name, text); };
  append("--config", plan.configPath);
  appendNumber("--cpus", plan.targetCPUs);
  appendNumber("--memory-mib", plan.targetMemoryMiB);
  append("--unit", plan.unit);
  appendNumber("--expected-pid", plan.expectedPID);
  appendNumber("--expected-starttime", plan.expectedStarttime);
  append("--expected-config-sha256", plan.configSHA256);
  append("--ingress-policy", plan.ingressPolicyPath);
  append("--ingress-policy-sha256", plan.ingressPolicySHA256);
  append("--expected-native-id", plan.hypervisorNativeID);
  append("--operation-id", plan.operationID);
  if (failure) failure->clear();
  return true;
}

static inline bool mothershipBuildMachineResizeGuestShutdownCommand(const MothershipMachineResizePlan& plan, String& command, String *failure = nullptr)
{
  if (!mothershipValidateMachineResizePlan(plan, failure)) return false;
  command.assign(R"CMD(set -eu; [ "$(systemd-detect-virt)" = kvm ]; [ "$(cat /etc/machine-id)" = )CMD"_ctv);
  mothershipAppendMachineResizeShellQuoted(command, plan.guestMachineID);
  command.append(R"CMD( ]; [ "$(cat /proc/sys/kernel/random/boot_id)" = )CMD"_ctv);
  mothershipAppendMachineResizeShellQuoted(command, plan.expectedGuestBootID);
  command.append(" ]; exec /usr/bin/systemd-run --unit="_ctv);
  String unit = {}; unit.append("prodigy-mothership-resize-"_ctv); unit.append(plan.operationID);
  mothershipAppendMachineResizeShellQuoted(command, unit);
  command.append(" --on-active=2s /usr/bin/systemctl poweroff"_ctv);
  if (failure) failure->clear();
  return true;
}

struct MothershipMachineResizeDeploymentWitness {
  uint16_t applicationID = 0;
  uint64_t versionID = 0;
  uint32_t target = 0;
};

struct MothershipMachineResizeHealthWitness {
  Vector<String> machineUUIDs;
  Vector<MothershipMachineResizeDeploymentWitness> deployments;
};

static inline bool mothershipCaptureMachineResizeHealthWitness(
    const ClusterStatusReport& report,
    const MothershipMachineResizePlan& plan,
    bool after,
    MothershipMachineResizeHealthWitness& witness,
    String& failure)
{
  witness = {};
  // Linux reserves part of assigned guest RAM; the pinned provider verifies the
  // exact QEMU allocation, while the report must expose all but at most 1 GiB.
  if (report.nApplications != report.applicationReports.size()) { failure.assign("machine resize application inventory incomplete"); return false; }
  if (report.nMachines == 0 || report.machineReports.size() != report.nMachines) { failure.assign("machine resize report machine inventory incomplete"); return false; }
  bool targetFound = false;
  for (const MachineStatusReport& machine : report.machineReports) {
    if (!machine.controlPlaneReachable || !machine.runtimeReady || machine.decommissioning || machine.rebooting || machine.updatingOS || machine.hardwareFailure) { failure.assign("machine resize requires every machine healthy"); return false; }
    for (const String& previous : witness.machineUUIDs) if (previous.equals(machine.machineUUID)) { failure.assign("machine resize report has duplicate machine identity"); return false; }
    witness.machineUUIDs.push_back(machine.machineUUID);
    if (machine.machineUUID.equals(plan.targetMachineUUID)) {
      targetFound = true;
      if (after && (machine.totalLogicalCores != plan.targetCPUs || uint64_t(machine.totalMemoryMB) + 1024 < plan.targetMemoryMiB)) { failure.assign("machine resize target capacity did not reach requested values"); return false; }
      if (!after && (machine.totalLogicalCores > plan.targetCPUs || machine.totalMemoryMB > plan.targetMemoryMiB || (machine.totalLogicalCores == plan.targetCPUs && machine.totalMemoryMB == plan.targetMemoryMiB)) ) { failure.assign("machine resize must be grow-only"); return false; }
    }
  }
  if (!targetFound) { failure.assign("machine resize target not in cluster report"); return false; }
  for (const ApplicationStatusReport& application : report.applicationReports) for (const DeploymentStatusReport& deployment : application.deploymentReports) {
    if (deployment.state != DeploymentState::running || deployment.nHealthy < deployment.nTarget) { failure.assign("machine resize requires every application deployment healthy"); return false; }
    witness.deployments.push_back({application.applicationID, deployment.versionID, deployment.nTarget});
  }
  return true;
}

static inline bool mothershipMachineResizeHealthWitnessMatches(
    const MothershipMachineResizeHealthWitness& before,
    const MothershipMachineResizeHealthWitness& after,
    String& failure)
{
  if (before.machineUUIDs.size() != after.machineUUIDs.size() || before.deployments.size() != after.deployments.size()) { failure.assign("machine resize changed cluster membership or deployment count"); return false; }
  for (const String& machineUUID : before.machineUUIDs) { bool found = false; for (const String& observed : after.machineUUIDs) if (observed.equals(machineUUID)) { found = true; break; } if (!found) { failure.assign("machine resize changed cluster member identity"); return false; } }
  for (const MothershipMachineResizeDeploymentWitness& deployment : before.deployments) { bool found = false; for (const MothershipMachineResizeDeploymentWitness& observed : after.deployments) if (deployment.applicationID == observed.applicationID && deployment.versionID == observed.versionID && deployment.target == observed.target) { found = true; break; } if (!found) { failure.assign("machine resize changed deployment identity or desired replicas"); return false; } }
  failure.clear(); return true;
}

static inline bool parseMothershipMachineResizePlanJSON(const char *text, MothershipMachineResizePlan& plan, String& failure)
{
  plan = {};
  failure.clear();
  if (text == nullptr || text[0] == '\0') { failure.assign("machine resize plan missing"); return false; }
  String json = {}; json.assign(text); json.need(simdjson::SIMDJSON_PADDING);
  simdjson::dom::parser parser; simdjson::dom::element document;
  if (parser.parse(json.data(), json.size()).get(document) || document.type() != simdjson::dom::element_type::OBJECT) { failure.assign("machine resize plan invalid json"); return false; }
  Vector<String> seen = {};
  for (auto field : document.get_object()) {
    String key = {}; key.setInvariant(field.key.data(), field.key.size());
    for (const String& previous : seen) if (previous.equals(key)) { failure.assign("duplicate machine resize plan field"); return false; }
    String ownedKey = {}; ownedKey.assign(key); seen.push_back(std::move(ownedKey));
    auto textField = [&](String& destination) -> bool {
      std::string_view value;
      if (field.value.get(value) != simdjson::SUCCESS || value.find('\0') != std::string_view::npos) return false;
      destination.assign(value.data(), value.size()); return true;
    };
    auto numberField = [&](uint64_t& destination) -> bool { return field.value.get(destination) == simdjson::SUCCESS; };
    uint64_t number = 0; bool valid = true;
    if (key.equal("schema"_ctv)) valid = textField(plan.schema);
    else if (key.equal("clusterUUID"_ctv)) valid = textField(plan.clusterUUID);
    else if (key.equal("targetMachineUUID"_ctv)) valid = textField(plan.targetMachineUUID);
    else if (key.equal("controllerMachineID"_ctv)) valid = textField(plan.controllerMachineID);
    else if (key.equal("guestMachineID"_ctv)) valid = textField(plan.guestMachineID);
    else if (key.equal("expectedGuestBootID"_ctv)) valid = textField(plan.expectedGuestBootID);
    else if (key.equal("hypervisorAddress"_ctv)) valid = textField(plan.hypervisorAddress);
    else if (key.equal("hypervisorPort"_ctv)) { valid = numberField(number) && number > 0 && number <= UINT16_MAX; plan.hypervisorPort = uint16_t(number); }
    else if (key.equal("hypervisorUser"_ctv)) valid = textField(plan.hypervisorUser);
    else if (key.equal("hypervisorPrivateKeyPath"_ctv)) valid = textField(plan.hypervisorPrivateKeyPath);
    else if (key.equal("hypervisorHostPublicKey"_ctv)) valid = textField(plan.hypervisorHostPublicKey);
    else if (key.equal("hypervisorNativeID"_ctv)) valid = textField(plan.hypervisorNativeID);
    else if (key.equal("supervisorPath"_ctv)) valid = textField(plan.supervisorPath);
    else if (key.equal("supervisorSHA256"_ctv)) valid = textField(plan.supervisorSHA256);
    else if (key.equal("configPath"_ctv)) valid = textField(plan.configPath);
    else if (key.equal("configSHA256"_ctv)) valid = textField(plan.configSHA256);
    else if (key.equal("ingressPolicyPath"_ctv)) valid = textField(plan.ingressPolicyPath);
    else if (key.equal("ingressPolicySHA256"_ctv)) valid = textField(plan.ingressPolicySHA256);
    else if (key.equal("unit"_ctv)) valid = textField(plan.unit);
    else if (key.equal("expectedPID"_ctv)) valid = numberField(plan.expectedPID);
    else if (key.equal("expectedStarttime"_ctv)) valid = numberField(plan.expectedStarttime);
    else if (key.equal("targetCPUs"_ctv)) { valid = numberField(number) && number <= UINT32_MAX; plan.targetCPUs = uint32_t(number); }
    else if (key.equal("targetMemoryMiB"_ctv)) { valid = numberField(number) && number <= UINT32_MAX; plan.targetMemoryMiB = uint32_t(number); }
    else if (key.equal("operationID"_ctv)) valid = textField(plan.operationID);
    else valid = false;
    if (!valid) { failure.snprintf<"machine resize plan field invalid: {}"_ctv>(key); return false; }
  }
  return mothershipValidateMachineResizePlan(plan, &failure);
}

static inline bool mothershipValidateMachineResizeReceipt(const String& json, const MothershipMachineResizePlan& plan, MothershipMachineResizePhase phase, String& failure)
{
  String input = {}; input.assign(json); input.need(simdjson::SIMDJSON_PADDING);
  simdjson::dom::parser parser; simdjson::dom::element doc;
  if (parser.parse(input.data(), input.size()).get(doc) || doc.type() != simdjson::dom::element_type::OBJECT) { failure.assign("machine resize provider receipt invalid json"); return false; }
  String schema = {}, state = {}, operationID = {}, nativeID = {}, unit = {}, configPath = {}, beforeConfig = {}, afterConfig = {}, beforeStart = {}, afterStart = {};
  uint64_t requestedCPUs = 0, requestedMemory = 0, beforePID = 0, afterPID = 0;
  for (auto field : doc.get_object()) {
    String key = {}; key.setInvariant(field.key.data(), field.key.size());
    auto text = [&](String& out) { if (field.value.type() != simdjson::dom::element_type::STRING) return false; out.setInvariant(field.value.get_c_str()); return true; };
    if (key.equal("schema"_ctv)) { if (!text(schema)) return false; }
    else if (key.equal("state"_ctv)) { if (!text(state)) return false; }
    else if (key.equal("operationID"_ctv)) { if (!text(operationID)) return false; }
    else if (key.equal("nativeID"_ctv)) { if (!text(nativeID)) return false; }
    else if (key.equal("unit"_ctv)) { if (!text(unit)) return false; }
    else if (key.equal("configPath"_ctv)) { if (!text(configPath)) return false; }
    else if (key.equal("requested"_ctv)) { if (field.value.type() != simdjson::dom::element_type::OBJECT) return false; for (auto f : field.value.get_object()) { String k = {}; k.setInvariant(f.key.data(), f.key.size()); if (k.equal("cpus"_ctv)) { if (f.value.get(requestedCPUs) != simdjson::SUCCESS) return false; } else if (k.equal("memoryMiB"_ctv)) { if (f.value.get(requestedMemory) != simdjson::SUCCESS) return false; } else return false; } }
    else if (key.equal("before"_ctv) || key.equal("after"_ctv)) { const bool isAfter = key.equal("after"_ctv); if (field.value.type() != simdjson::dom::element_type::OBJECT) return false; for (auto f : field.value.get_object()) { String k = {}; k.setInvariant(f.key.data(), f.key.size()); if (k.equal("pid"_ctv)) { if (f.value.get(isAfter ? afterPID : beforePID) != simdjson::SUCCESS) return false; } else if (k.equal("starttime"_ctv)) { if (f.value.type() != simdjson::dom::element_type::STRING) return false; (isAfter ? afterStart : beforeStart).setInvariant(f.value.get_c_str()); } else if (k.equal("configSHA256"_ctv)) { if (f.value.type() != simdjson::dom::element_type::STRING) return false; (isAfter ? afterConfig : beforeConfig).setInvariant(f.value.get_c_str()); } else return false; } }
    else return false;
  }
  String expectedStart = {}; expectedStart.assignItoa(plan.expectedStarttime);
  const bool stateMatches = phase == MothershipMachineResizePhase::preflight ? state.equal("PREFLIGHT_OK"_ctv) : (phase == MothershipMachineResizePhase::prepare ? state.equal("PREPARED"_ctv) : state.equal("COMPLETE"_ctv));
  if (!schema.equal("nametag.kvm-resize.v1"_ctv) || !stateMatches || !operationID.equals(plan.operationID) || !nativeID.equals(plan.hypervisorNativeID) || !unit.equals(plan.unit) || !configPath.equals(plan.configPath) || requestedCPUs != plan.targetCPUs || requestedMemory != plan.targetMemoryMiB || beforePID != plan.expectedPID || !beforeStart.equals(expectedStart) || !beforeConfig.equals(plan.configSHA256)) { failure.assign("machine resize provider receipt differs from plan"); return false; }
  if (phase == MothershipMachineResizePhase::resize && (afterPID == 0 || afterStart.size() == 0 || !mothershipMachineResizeHexDigest(afterConfig) || afterConfig.equals(beforeConfig) || (afterPID == beforePID && afterStart.equals(beforeStart)))) { failure.assign("machine resize provider receipt lacks new runtime identity"); return false; }
  failure.clear(); return true;
}

