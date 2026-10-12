#pragma once

#include <arpa/inet.h>
#include <cstring>
#include <iterator>
#include <simdjson.h>
#include <string_view>

#include <prodigy/cousin.route.h>

// Caller-owned fields for one retry-stable route generation.  Mothership
// derives the pair, cluster, application, and service identities from the
// durable enrollment plus the two exact local permissions; callers cannot
// relabel those authority-owned fields in JSON.
class MothershipCousinRouteIntent {
public:
  uint128_t routeUUID = 0;
  uint128_t operationUUID = 0;
  uint128_t logicalWorkloadUUID = 0;
  uint128_t logicalServiceUUID = 0;
  uint128_t sourcePermissionUUID = 0;
  uint128_t destinationPermissionUUID = 0;
  CousinRouteSlotBitmap slots = {};
  uint128_t destinationRoutablePrefixUUID = 0;
  IPAddress destinationPublicAddress = {};
  uint8_t transportProtocol = 0;
  uint8_t destinationCIDR = 0;
  uint16_t destinationTCPPort = 0;
  uint16_t pathMTU = 0;
  uint64_t generation = 0;
  int64_t issuedAtMs = 0;
  int64_t expiresAtMs = 0;
  CousinRouteState state = CousinRouteState::active;
};

static inline bool mothershipParseCousinRouteIntentJSON(
    simdjson::dom::element document, MothershipCousinRouteIntent& intent,
    String& failure)
{
  intent = {};
  failure.clear();
  auto reject = [&]() {
    intent = {};
    failure.assign("invalid cousin route: require all canonical fields, without duplicates or unknown fields"_ctv);
    return false;
  };
  if (document.type() != simdjson::dom::element_type::OBJECT) return reject();
  constexpr std::string_view names[] = {
    "routeUUID", "operationUUID", "logicalWorkloadUUID", "logicalServiceUUID",
    "sourcePermissionUUID", "destinationPermissionUUID", "slots",
    "destinationRoutablePrefixUUID", "destinationPublicAddress", "transportProtocol",
    "destinationCIDR", "destinationTCPPort", "pathMTU", "generation",
    "issuedAtMs", "expiresAtMs", "state"
  };
  uint32_t seen = 0;
  for (auto field : document.get_object())
  {
    uint32_t index = 0;
    while (index < std::size(names) && names[index] != field.key) ++index;
    if (index == std::size(names) || (seen & (uint32_t(1) << index))) return reject();
    seen |= uint32_t(1) << index;
    if (index <= 5 || index == 7)
    {
      std::string_view value;
      if (field.value.get(value) != simdjson::SUCCESS) return reject();
      String text; text.setInvariant(value.data(), value.size());
      uint128_t parsed = 0;
      if (!prodigyParseCanonicalHex128(text, parsed) || parsed == 0) return reject();
      uint128_t *targets[] = {&intent.routeUUID, &intent.operationUUID,
        &intent.logicalWorkloadUUID, &intent.logicalServiceUUID,
        &intent.sourcePermissionUUID, &intent.destinationPermissionUUID};
      if (index <= 5) *targets[index] = parsed;
      else intent.destinationRoutablePrefixUUID = parsed;
    }
    else if (index == 6)
    {
      if (field.value.type() != simdjson::dom::element_type::ARRAY) return reject();
      uint32_t count = 0;
      for (auto entry : field.value.get_array())
      {
        uint64_t slot = 0;
        if (++count > CousinRouteSlotBitmap::slotCount || entry.get(slot) != simdjson::SUCCESS ||
            slot >= CousinRouteSlotBitmap::slotCount || intent.slots.contains(uint16_t(slot))) return reject();
        intent.slots.insert(uint16_t(slot));
      }
      if (count == 0) return reject();
    }
    else if (index == 8)
    {
      std::string_view value;
      if (field.value.get(value) != simdjson::SUCCESS || value.empty() || value.size() >= INET6_ADDRSTRLEN) return reject();
      char text[INET6_ADDRSTRLEN] = {};
      std::memcpy(text, value.data(), value.size());
      intent.destinationPublicAddress = {};
      intent.destinationPublicAddress.is6 = true;
      if (::inet_pton(AF_INET6, text, intent.destinationPublicAddress.v6) != 1 ||
          intent.destinationPublicAddress.isNull()) return reject();
      char canonical[INET6_ADDRSTRLEN] = {};
      if (::inet_ntop(AF_INET6, intent.destinationPublicAddress.v6, canonical, sizeof(canonical)) == nullptr ||
          value != std::string_view(canonical)) return reject();
    }
    else if (index == 9)
    {
      std::string_view value;
      if (field.value.get(value) != simdjson::SUCCESS || value != "TCP") return reject();
      intent.transportProtocol = IPPROTO_TCP;
    }
    else if (index == 16)
    {
      std::string_view value;
      if (field.value.get(value) != simdjson::SUCCESS) return reject();
      if (value == "active") intent.state = CousinRouteState::active;
      else if (value == "draining") intent.state = CousinRouteState::draining;
      else if (value == "withdrawn") intent.state = CousinRouteState::withdrawn;
      else if (value == "revoked") intent.state = CousinRouteState::revoked;
      else return reject();
    }
    else if (index == 14 || index == 15)
    {
      int64_t value = 0;
      if (field.value.get(value) != simdjson::SUCCESS || value <= 0) return reject();
      (index == 14 ? intent.issuedAtMs : intent.expiresAtMs) = value;
    }
    else
    {
      uint64_t value = 0;
      if (field.value.get(value) != simdjson::SUCCESS || value == 0) return reject();
      if (index == 10) {
        if (value > UINT8_MAX) return reject();
        intent.destinationCIDR = uint8_t(value);
      } else if (index == 11) {
        if (value > UINT16_MAX) return reject();
        intent.destinationTCPPort = uint16_t(value);
      } else if (index == 12) {
        if (value > UINT16_MAX) return reject();
        intent.pathMTU = uint16_t(value);
      } else if (index == 13) intent.generation = value;
      else return reject();
    }
  }
  constexpr uint32_t all = (uint32_t(1) << std::size(names)) - 1;
  if (seen != all || intent.expiresAtMs <= intent.issuedAtMs ||
      intent.expiresAtMs - intent.issuedAtMs > cousinRouteMaximumLifetimeMs ||
      intent.destinationCIDR == 0 || intent.destinationCIDR > 128 ||
      intent.pathMTU < cousinRouteMinimumPathMTU || intent.pathMTU > cousinRouteMaximumPathMTU)
    return reject();
  return true;
}
