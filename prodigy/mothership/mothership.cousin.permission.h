#pragma once

#include <simdjson.h>
#include <string_view>

#include <prodigy/cousin.service.permission.h>
#include <prodigy/persistent.state.h>

// Initial deployment policy only. Runtime routes and keys are never obtained
// through this parser or Mothership command.
static inline bool mothershipParseLocalCousinPermissionJSON(
    simdjson::dom::element document, ProdigyLocalCousinServicePermission& permission,
    String& failure)
{
  permission = {};
  failure.clear();
  auto reject = [&]() {
    permission = {};
    failure.assign("invalid cousin permission: require all canonical policy fields, without duplicates or unknown fields"_ctv);
    return false;
  };
  if (document.type() != simdjson::dom::element_type::OBJECT) return reject();
  constexpr std::string_view names[] = {
    "permissionUUID", "pairUUID", "logicalWorkloadUUID", "logicalServiceUUID",
    "localClusterUUID", "peerClusterUUID", "localHalf", "localApplicationID",
    "peerApplicationID", "localCousinServicePrefix", "peerCousinServicePrefix",
    "slots", "localDeploymentID", "canonicalPlanSHA256", "artifactSHA256", "artifactBytes"
  };
  uint32_t seen = 0;
  for (auto field : document.get_object()) {
    uint32_t index = 0;
    while (index < 16 && names[index] != field.key) ++index;
    if (index == 16 || (seen & (uint32_t(1) << index))) return reject();
    seen |= uint32_t(1) << index;
    if (index <= 5) {
      std::string_view value;
      if (field.value.get(value) != simdjson::SUCCESS) return reject();
      String text; text.setInvariant(value.data(), value.size());
      uint128_t parsed = 0;
      if (!prodigyParseCanonicalHex128(text, parsed) || parsed == 0) return reject();
      uint128_t *targets[] = {&permission.permissionUUID, &permission.pairUUID,
        &permission.logicalWorkloadUUID, &permission.logicalServiceUUID,
        &permission.localClusterUUID, &permission.peerClusterUUID};
      *targets[index] = parsed;
    } else if (index == 6) {
      std::string_view value;
      if (field.value.get(value) != simdjson::SUCCESS) return reject();
      if (value == "source") permission.localHalf = CousinRouteHalf::source;
      else if (value == "destination") permission.localHalf = CousinRouteHalf::destination;
      else return reject();
    } else if (index == 11) {
      if (field.value.type() != simdjson::dom::element_type::ARRAY) return reject();
      uint32_t count = 0;
      for (auto entry : field.value.get_array()) {
        uint64_t slot = 0;
        if (++count > CousinRouteSlotBitmap::slotCount || entry.get(slot) != simdjson::SUCCESS ||
            slot >= CousinRouteSlotBitmap::slotCount || permission.slots.contains(uint16_t(slot))) return reject();
        permission.slots.insert(uint16_t(slot));
      }
      if (count == 0) return reject();
    } else if (index == 13 || index == 14) {
      std::string_view value;
      if (field.value.get(value) != simdjson::SUCCESS || value.size() != 64) return reject();
      String text; text.setInvariant(value.data(), value.size());
      (index == 13 ? permission.canonicalPlanSHA256 : permission.artifactSHA256).assign(text);
    } else {
      uint64_t value = 0;
      if (field.value.get(value) != simdjson::SUCCESS || value == 0) return reject();
      if (index == 7 || index == 8) {
        if (value > UINT16_MAX) return reject();
        (index == 7 ? permission.localApplicationID : permission.peerApplicationID) = uint16_t(value);
      } else if (index == 9) permission.localCousinServicePrefix = value;
      else if (index == 10) permission.peerCousinServicePrefix = value;
      else if (index == 12) permission.localDeploymentID = value;
      else if (index == 15) permission.artifactBytes = value;
    }
  }
  permission.generation = 1;
  permission.state = ProdigyLocalCousinServicePermissionState::active;
  if (seen != 0xffff || !prodigyLocalCousinServicePermissionValid(permission, false)) return reject();
  return true;
}
