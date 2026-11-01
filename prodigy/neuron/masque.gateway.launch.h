#pragma once

#include <linux/memfd.h>
#include <services/memfd.h>
#include <prodigy/types.h>

// Launch-only files. Nothing is written into a container image, retained
// rootfs, public plan, or environment. The child owns these sealed descriptors
// across exec; the kernel releases them on failed exec or process exit.
static inline bool prodigyMasqueGatewayExecFile(const String& value, String& path,
                                               Vector<int32_t>& descriptors)
{
  path.clear();
  if (value.empty() || value.size() > 32768) return false;
  int fd = Memfd::create("prodigy-masque-launch", MFD_ALLOW_SEALING | MFD_CLOEXEC);
  if (fd < 0) return false;
  const bool ready = Memfd::writeAll(fd, value) && fchmod(fd, 0400) == 0 &&
      fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) == 0;
  const int inherited = ready ? fcntl(fd, F_DUPFD, 64) : -1;
  close(fd);
  if (inherited < 0) return false;
  descriptors.push_back(inherited);
  path.assign("/proc/self/fd/"_ctv);
  String number = {}; number.assignItoa(uint64_t(inherited)); path.append(number);
  return true;
}

static inline bool prodigyBuildMasqueGatewayExecArguments(
    const CrossClusterMasqueGatewayAuthority& authority,
    const String& rootCert, const String& leafCert, const String& leafKey,
    const String& peerLeafDERHex, Vector<String>& arguments,
    Vector<int32_t>& descriptors, String *failure = nullptr)
{
  // Caller has validated the Vault material against this exact authority.
  // Build transactionally: failed preparation leaves no inherited descriptors.
  Vector<String> built = {};
  Vector<int32_t> opened = {};
  auto fail = [&]() {
    for (int fd : opened) close(fd);
    if (failure) failure->assign("MASQUE launch material or exact authority is unavailable"_ctv);
    return false;
  };
  if (!prodigyCrossClusterMasqueGatewayAuthorityStructurallyValid(authority) ||
      authority.state != CrossClusterMasqueGatewayState::active ||
      std::memcmp(authority.privateTunnelLocalIPv6.v6, authority.privateTunnelPeerIPv6.v6, 15) != 0 ||
      (authority.privateTunnelLocalIPv6.v6[15] ^ authority.privateTunnelPeerIPv6.v6[15]) != 1 ||
      peerLeafDERHex.empty() || peerLeafDERHex.size() > 16384 || (peerLeafDERHex.size() & 1)) return fail();
  for (char byte : peerLeafDERHex)
    if (!((byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f'))) return fail();
  String caPath = {}, certPath = {}, keyPath = {};
  if (!prodigyMasqueGatewayExecFile(rootCert, caPath, opened) ||
      !prodigyMasqueGatewayExecFile(leafCert, certPath, opened) ||
      !prodigyMasqueGatewayExecFile(leafKey, keyPath, opened)) return fail();
  auto add = [&](StringType auto&& value) { String owned = {}; owned.assign(value); built.push_back(std::move(owned)); };
  auto option = [&](StringType auto&& name, const String& value) { add(name); add(value); };
  auto ipText = [&](const IPAddress& address, String& out) {
    return ClusterMachine::renderIPAddressLiteral(address, out);
  };
  String localIP = {}, peerIP = {}, localRoute = {}, peerRoute = {}, port = {};
  if (!ipText(authority.privateTunnelLocalIPv6, localIP) ||
      !ipText(authority.privateTunnelPeerIPv6, peerIP) ||
      !ipText(authority.localSitePrefix.network, localRoute) ||
      !ipText(authority.peerSitePrefix.network, peerRoute)) return fail();
  localRoute.append("/96"_ctv); peerRoute.append("/96"_ctv);
  port.assignItoa(authority.listenerPublicUDPPort);
  if (authority.localRole == CrossClusterMasqueGatewayRole::listener)
  {
    add("server"_ctv);
    String listen = {}; listen.assign("[::]:"_ctv); listen.append(port);
    option("--listen"_ctv, listen);
    option("--cert"_ctv, certPath); option("--key"_ctv, keyPath);
    option("--client-ca"_ctv, caPath);
    option("--ip-tun-name"_ctv, authority.privateTunnelInterface);
    String authorized = {}; authorized.assign(peerLeafDERHex); authorized.append('='); authorized.append(peerRoute);
    option("--authorized-peer-route"_ctv, authorized);
    String routeFile = {}, routes = {}; routes.assign(localRoute); routes.append('\n');
    if (!prodigyMasqueGatewayExecFile(routes, routeFile, opened)) return fail();
    option("--ip-routes-file"_ctv, routeFile);
    add("--ip-allow-private"_ctv);
  }
  else
  {
    add("client-ip"_ctv);
    String endpoint = {}, url = {};
    if (!ipText(authority.listenerPublicUDPEndpoint, endpoint)) return fail();
    url.assign("https://"_ctv);
    if (authority.listenerPublicUDPEndpoint.is6) url.append('[');
    url.append(endpoint);
    if (authority.listenerPublicUDPEndpoint.is6) url.append(']');
    url.append(':'); url.append(port);
    option("--proxy-url"_ctv, url); option("--ca"_ctv, caPath);
    option("--client-cert"_ctv, certPath); option("--client-key"_ctv, keyPath);
    option("--tun-name"_ctv, authority.privateTunnelInterface);
    option("--local-ip6-route"_ctv, localRoute);
  }
  option("--ip6-p2p-local"_ctv, localIP);
  option("--ip6-p2p-peer"_ctv, peerIP);
  arguments = std::move(built);
  for (int fd : opened) descriptors.push_back(fd);
  return true;
}
