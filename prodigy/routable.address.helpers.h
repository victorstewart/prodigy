#pragma once

#include <algorithm>

#include <prodigy/types.h>

static inline const DistributableExternalSubnet *findRegisteredRoutablePrefix(const Vector<DistributableExternalSubnet>& prefixes, uint128_t uuid)
{
  for (const DistributableExternalSubnet& prefix : prefixes)
  {
    if (uuid != 0 && prefix.uuid == uuid)
    {
      return &prefix;
    }
  }

  return nullptr;
}

static inline bool makeHostedIngressPrefixForAddress(const IPAddress& address, IPPrefix& prefix)
{
  if (address.isNull())
  {
    prefix = {};
    return false;
  }

  prefix = {};
  prefix.network = address;
  prefix.cidr = address.is6 ? 128 : 32;
  prefix.canonicalize();
  return true;
}

static inline RoutableResourceLeaseOwner deploymentRoutableResourceLeaseOwner(const DeploymentPlan& plan)
{
  RoutableResourceLeaseOwner owner = {};
  owner.applicationID = plan.config.applicationID;
  owner.deploymentID = plan.config.deploymentID();
  owner.lineageID = plan.config.applicationID;
  return owner;
}

static inline bool routablePrefixAddressAtOffset(const IPPrefix& source, uint64_t offset, IPAddress& address)
{
  IPPrefix prefix = source.canonicalized();
  uint8_t maxCidr = prefix.network.is6 ? 128 : 32;
  if (prefix.cidr > maxCidr || (prefix.cidr == maxCidr && offset != 0))
  {
    return false;
  }

  address = prefix.network;
  if (address.is6 == false)
  {
    uint64_t value = uint64_t(ntohl(address.v4)) + offset;
    if (value > UINT32_MAX)
    {
      return false;
    }
    address.v4 = htonl(uint32_t(value));
  }
  else
  {
    for (int index = 15; offset != 0 && index >= 0; --index)
    {
      uint64_t value = uint64_t(address.v6[index]) + (offset & 0xffu);
      address.v6[index] = uint8_t(value);
      offset = (offset >> 8u) + (value >> 8u);
    }
    if (offset != 0)
    {
      return false;
    }
  }

  return prefix.containsAddress(address);
}

static inline bool wormholeAddressLeaseConflicts(const Vector<RoutableResourceLease> *leases, const RoutableResourceLeaseOwner *owner, uint128_t prefixUUID, const IPAddress& address)
{
  if (leases == nullptr || owner == nullptr)
  {
    return false;
  }

  RoutableResourceLease lease = {};
  lease.kind = RoutableResourceLeaseKind::wormholeAddress;
  lease.owner = *owner;
  lease.registeredPrefixUUID = prefixUUID;
  lease.address = address;
  for (const RoutableResourceLease& existing : *leases)
  {
    if (routableResourceLeasesConflict(existing, lease))
    {
      return true;
    }
  }
  return false;
}

static inline bool resolveWormholeDeliveryAddress(const DistributableExternalSubnet& prefix, Wormhole& wormhole, String *failure)
{
  wormhole.deliveryAddress = {};
  if (prefix.deliverySubnet.network.isNull())
  {
    return true;
  }

  IPPrefix delivery = prefix.deliverySubnet.canonicalized();
  if (distributableExternalSubnetIsHostPrefix(prefix) && delivery.cidr == prefix.subnet.cidr && delivery.network.is6 == wormhole.externalAddress.is6)
  {
    wormhole.deliveryAddress = delivery.network;
    return true;
  }

  if (failure)
  {
    failure->assign("registered routable prefix deliverySubnet must match a host prefix"_ctv);
  }
  return false;
}

static inline bool resolveWormholeRegisteredRoutablePrefix(const Vector<DistributableExternalSubnet>& prefixes,
                                                           Wormhole& wormhole,
                                                           String *failure = nullptr,
                                                           const Vector<RoutableResourceLease> *leases = nullptr,
                                                           const RoutableResourceLeaseOwner *owner = nullptr)
{
  if (failure)
  {
    failure->clear();
  }

  if (wormhole.source != ExternalAddressSource::registeredRoutablePrefix)
  {
    if (failure)
    {
      failure->assign("wormhole source is not registeredRoutablePrefix"_ctv);
    }

    return false;
  }

  if (wormhole.routablePrefixUUID == 0)
  {
    if (failure)
    {
      failure->assign("wormhole source=registeredRoutablePrefix requires routablePrefixUUID"_ctv);
    }

    return false;
  }

  const DistributableExternalSubnet *prefix = findRegisteredRoutablePrefix(prefixes, wormhole.routablePrefixUUID);
  if (prefix == nullptr)
  {
    if (failure)
    {
      failure->assign("wormhole routablePrefixUUID is not a registered prefix"_ctv);
    }

    return false;
  }

  if (distributableExternalSubnetAllowsWormholes(*prefix) == false)
  {
    if (failure)
    {
      failure->assign("registered routable prefix is not usable for wormholes"_ctv);
    }

    return false;
  }

  IPPrefix registered = prefix->subnet.canonicalized();
  if (wormhole.externalAddress.isNull() == false)
  {
    if (registered.containsAddress(wormhole.externalAddress))
    {
      return resolveWormholeDeliveryAddress(*prefix, wormhole, failure);
    }

    if (failure)
    {
      failure->assign("wormhole externalAddress is outside registered routable prefix"_ctv);
    }

    return false;
  }

  uint64_t firstOffset = distributableExternalSubnetIsHostPrefix(*prefix) ? 0 : 1;
  for (uint64_t offset = firstOffset; offset < firstOffset + 65'536u; ++offset)
  {
    IPAddress candidate = {};
    if (routablePrefixAddressAtOffset(registered, offset, candidate) == false)
    {
      break;
    }
    if (candidate.isNull() == false && wormholeAddressLeaseConflicts(leases, owner, prefix->uuid, candidate) == false)
    {
      wormhole.externalAddress = candidate;
      return resolveWormholeDeliveryAddress(*prefix, wormhole, failure);
    }
  }

  if (failure)
  {
    failure->assign("no free address in registered routable prefix"_ctv);
  }

  return false;
}
