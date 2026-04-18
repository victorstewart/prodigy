#include <arpa/inet.h>
#include <services/debug.h>
#include <cctype>
#include <cerrno>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <libssh2.h>
#include <linux/capability.h>
#include <netdb.h>
#include <simdjson.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include <networking/includes.h>
#include <services/prodigy.h>

#include <prodigy/bootstrap.config.h>
#include <prodigy/iaas/runtime/runtime.h>
#include <prodigy/persistent.state.h>
#include <prodigy/remote.bootstrap.h>
#include <prodigy/routable.address.helpers.h>
#include <prodigy/wire.h>
#include <prodigy/mothership/mothership.cluster.create.h>
#include <prodigy/mothership/mothership.cluster.remove.h>
#include <prodigy/mothership/mothership.addmachines.progress.h>
#include <prodigy/mothership/mothership.cluster.reconcile.h>
#include <prodigy/mothership/mothership.cluster.registry.h>
#include <prodigy/mothership/mothership.ssh.h>
#include <prodigy/mothership/mothership.deployment.plan.helpers.h>
#include <prodigy/mothership/mothership.pricing.command.helpers.h>
#include <prodigy/mothership/mothership.pricing.h>
#include <prodigy/mothership/mothership.provider.credentials.h>
#include <prodigy/mothership/mothership.provider.machine.destroy.h>
#include <prodigy/types.h>

// for now every time we create a new application or service we're going to have to recompile the mothership so that
// it can read the enum values from enums.datacenter.h, but in the future we can do something else more flexible

// ncurses

// we could expand this to a program that doesn't exit but lingers..
// as soon as the program runs we could gather the cluster state and display it in a top window
// we could have a lower window for user input and responses from the cluster
// we could use io_uring to accept user input too io_uring_prep_read(sqe, STDIN_FILENO, buffer, BUFFER_SIZE, 0);

// seems like it makes sense to have an option to get all machines and all resources... even if we had a million machines that's only megabytes of data at worst. we'd still 
// need to factor in the existing machine allowance budget we gave it

static void mothershipCliLog(const char *text)
{
   if (text != nullptr)
   {
      std::fputs(text, stdout);
   }

   std::fflush(stdout);
}

template <typename... Args>
static void mothershipCliLog(const char *format, Args&&... args)
{
   std::fprintf(stdout, format, std::forward<Args>(args)...);
   std::fflush(stdout);
}

#define basics_log mothershipCliLog

static bool parseU32Arg(const char *text, uint32_t& value)
{
	if (text == nullptr || text[0] == '\0') return false;

	char *end = nullptr;
	unsigned long parsed = std::strtoul(text, &end, 10);
	if (end == text || *end != '\0') return false;

	value = static_cast<uint32_t>(parsed);
	return true;
}

static bool parseBoolArg(const char *text, bool& value)
{
   if (text == nullptr)
   {
      return false;
   }

   if ((std::strcmp(text, "1") == 0) || (std::strcmp(text, "true") == 0) || (std::strcmp(text, "TRUE") == 0))
   {
      value = true;
      return true;
   }

   if ((std::strcmp(text, "0") == 0) || (std::strcmp(text, "false") == 0) || (std::strcmp(text, "FALSE") == 0))
   {
      value = false;
      return true;
   }

   return false;
}

static bool parseDoubleArg(const char *text, double& value)
{
   if (text == nullptr || text[0] == '\0')
   {
      return false;
   }

   char *end = nullptr;
   errno = 0;
   double parsed = std::strtod(text, &end);
   if (end == text || *end != '\0' || errno != 0 || std::isfinite(parsed) == false)
   {
      return false;
   }

   value = parsed;
   return true;
}

static bool parseCIDRPrefix(const char *text, IPPrefix& prefix)
{
   if (text == nullptr || text[0] == '\0')
   {
      return false;
   }

   const char *slash = std::strrchr(text, '/');
   if (slash == nullptr || slash == text || slash[1] == '\0')
   {
      return false;
   }

   char addressText[INET6_ADDRSTRLEN + 1] = {0};
   size_t addressLength = size_t(slash - text);
   if (addressLength == 0 || addressLength >= sizeof(addressText))
   {
      return false;
   }

   std::memcpy(addressText, text, addressLength);

   char *end = nullptr;
   unsigned long cidr = std::strtoul(slash + 1, &end, 10);
   if (end == slash + 1 || *end != '\0')
   {
      return false;
   }

   IPPrefix parsed = {};
   if (inet_pton(AF_INET, addressText, parsed.network.v6) == 1)
   {
      if (cidr > 32)
      {
         return false;
      }

      parsed.network.is6 = false;
      parsed.cidr = static_cast<uint8_t>(cidr);
      parsed.canonicalize();
      prefix = parsed;
      return true;
   }

   if (inet_pton(AF_INET6, addressText, parsed.network.v6) == 1)
   {
      if (cidr > 128)
      {
         return false;
      }

      parsed.network.is6 = true;
      parsed.cidr = static_cast<uint8_t>(cidr);
      parsed.canonicalize();
      prefix = parsed;
      return true;
   }

   return false;
}

static bool parseExternalAddressTransport(const String& value, ExternalAddressTransport& transport)
{
   if (value.equal("tcp"_ctv) || value.equal("TCP"_ctv) || value.equal("ExternalAddressTransport::tcp"_ctv))
   {
      transport = ExternalAddressTransport::tcp;
      return true;
   }

   if (value.equal("quic"_ctv) || value.equal("QUIC"_ctv) || value.equal("ExternalAddressTransport::quic"_ctv))
   {
      transport = ExternalAddressTransport::quic;
      return true;
   }

   return false;
}

static bool parseExternalAddressFamily(const String& value, ExternalAddressFamily& family)
{
   if (value.equal("ipv4"_ctv) || value.equal("IPv4"_ctv) || value.equal("ExternalAddressFamily::ipv4"_ctv))
   {
      family = ExternalAddressFamily::ipv4;
      return true;
   }

   if (value.equal("ipv6"_ctv) || value.equal("IPv6"_ctv) || value.equal("ExternalAddressFamily::ipv6"_ctv))
   {
      family = ExternalAddressFamily::ipv6;
      return true;
   }

   return false;
}

static bool parseExternalAddressSource(const String& value, ExternalAddressSource& source)
{
   if (value.equal("distributableSubnet"_ctv) || value.equal("distributedSubnet"_ctv) || value.equal("ExternalAddressSource::distributableSubnet"_ctv))
   {
      source = ExternalAddressSource::distributableSubnet;
      return true;
   }

   if (value.equal("hostPublicAddress"_ctv) || value.equal("ExternalAddressSource::hostPublicAddress"_ctv))
   {
      source = ExternalAddressSource::hostPublicAddress;
      return true;
   }

   if (value.equal("registeredRoutableAddress"_ctv) || value.equal("ExternalAddressSource::registeredRoutableAddress"_ctv))
   {
      source = ExternalAddressSource::registeredRoutableAddress;
      return true;
   }

   return false;
}

static bool parseExternalSubnetRouting(const String& value, ExternalSubnetRouting& routing)
{
   if (value.equal("switchboardBGP"_ctv) || value.equal("bgp"_ctv) || value.equal("ExternalSubnetRouting::switchboardBGP"_ctv))
   {
      routing = ExternalSubnetRouting::switchboardBGP;
      return true;
   }

   if (value.equal("switchboardPinnedRoute"_ctv) || value.equal("pinnedRoute"_ctv) || value.equal("ExternalSubnetRouting::switchboardPinnedRoute"_ctv))
   {
      routing = ExternalSubnetRouting::switchboardPinnedRoute;
      return true;
   }

   return false;
}

static bool parseExternalSubnetUsage(const String& value, ExternalSubnetUsage& usage)
{
   if (value.equal("wormholes"_ctv) || value.equal("ExternalSubnetUsage::wormholes"_ctv))
   {
      usage = ExternalSubnetUsage::wormholes;
      return true;
   }

   if (value.equal("whiteholes"_ctv) || value.equal("ExternalSubnetUsage::whiteholes"_ctv))
   {
      usage = ExternalSubnetUsage::whiteholes;
      return true;
   }

   if (value.equal("both"_ctv) || value.equal("ExternalSubnetUsage::both"_ctv))
   {
      usage = ExternalSubnetUsage::both;
      return true;
   }

   return false;
}

static const char *externalSubnetRoutingName(ExternalSubnetRouting routing)
{
   switch (routing)
   {
      case ExternalSubnetRouting::switchboardBGP:
      {
         return "switchboardBGP";
      }
      case ExternalSubnetRouting::switchboardPinnedRoute:
      {
         return "switchboardPinnedRoute";
      }
   }

   return "unknown";
}

static const char *externalSubnetUsageName(ExternalSubnetUsage usage)
{
   switch (usage)
   {
      case ExternalSubnetUsage::wormholes:
      {
         return "wormholes";
      }
      case ExternalSubnetUsage::whiteholes:
      {
         return "whiteholes";
      }
      case ExternalSubnetUsage::both:
      {
         return "both";
      }
   }

   return "unknown";
}

static bool parseMothershipClusterDeploymentMode(const String& value, MothershipClusterDeploymentMode& mode)
{
   if (value.equal("local"_ctv) || value.equal("MothershipClusterDeploymentMode::local"_ctv))
   {
      mode = MothershipClusterDeploymentMode::local;
      return true;
   }

   if (value.equal("remote"_ctv) || value.equal("MothershipClusterDeploymentMode::remote"_ctv))
   {
      mode = MothershipClusterDeploymentMode::remote;
      return true;
   }

   if (value.equal("test"_ctv) || value.equal("MothershipClusterDeploymentMode::test"_ctv))
   {
      mode = MothershipClusterDeploymentMode::test;
      return true;
   }

   return false;
}

static bool parseMothershipClusterControlKind(const String& value, MothershipClusterControlKind& kind)
{
   if (value.equal("unixSocket"_ctv) || value.equal("unix"_ctv) || value.equal("MothershipClusterControlKind::unixSocket"_ctv))
   {
      kind = MothershipClusterControlKind::unixSocket;
      return true;
   }

   return false;
}

static bool parseMothershipClusterTestHostMode(const String& value, MothershipClusterTestHostMode& mode)
{
   if (value.equal("local"_ctv) || value.equal("MothershipClusterTestHostMode::local"_ctv))
   {
      mode = MothershipClusterTestHostMode::local;
      return true;
   }

   if (value.equal("ssh"_ctv) || value.equal("MothershipClusterTestHostMode::ssh"_ctv))
   {
      mode = MothershipClusterTestHostMode::ssh;
      return true;
   }

   return false;
}

static bool parseMothershipClusterTestBootstrapFamily(const String& value, MothershipClusterTestBootstrapFamily& family)
{
   if (value.equal("ipv4"_ctv) || value.equal("MothershipClusterTestBootstrapFamily::ipv4"_ctv))
   {
      family = MothershipClusterTestBootstrapFamily::ipv4;
      return true;
   }

   if (value.equal("private6"_ctv) || value.equal("MothershipClusterTestBootstrapFamily::private6"_ctv))
   {
      family = MothershipClusterTestBootstrapFamily::private6;
      return true;
   }

   if (value.equal("public6"_ctv) || value.equal("MothershipClusterTestBootstrapFamily::public6"_ctv))
   {
      family = MothershipClusterTestBootstrapFamily::public6;
      return true;
   }

   if (value.equal("multihome6"_ctv) || value.equal("MothershipClusterTestBootstrapFamily::multihome6"_ctv))
   {
      family = MothershipClusterTestBootstrapFamily::multihome6;
      return true;
   }

   return false;
}

static bool parseMothershipClusterMachineSource(const String& value, MothershipClusterMachineSource& source)
{
   if (value.equal("adopted"_ctv) || value.equal("MothershipClusterMachineSource::adopted"_ctv))
   {
      source = MothershipClusterMachineSource::adopted;
      return true;
   }

   if (value.equal("created"_ctv) || value.equal("MothershipClusterMachineSource::created"_ctv))
   {
      source = MothershipClusterMachineSource::created;
      return true;
   }

   return false;
}

static bool parseMachineKind(const String& value, MachineConfig::MachineKind& kind)
{
   if (value.equal("bareMetal"_ctv) || value.equal("MachineKind::bareMetal"_ctv) || value.equal("MachineConfig::MachineKind::bareMetal"_ctv))
   {
      kind = MachineConfig::MachineKind::bareMetal;
      return true;
   }

   if (value.equal("vm"_ctv) || value.equal("MachineKind::vm"_ctv) || value.equal("MachineConfig::MachineKind::vm"_ctv))
   {
      kind = MachineConfig::MachineKind::vm;
      return true;
   }

   return false;
}

static bool parseMachineLifetime(const String& value, MachineLifetime& lifetime)
{
   if (value.equal("owned"_ctv) || value.equal("MachineLifetime::owned"_ctv))
   {
      lifetime = MachineLifetime::owned;
      return true;
   }

   if (value.equal("reserved"_ctv) || value.equal("MachineLifetime::reserved"_ctv))
   {
      lifetime = MachineLifetime::reserved;
      return true;
   }

   if (value.equal("ondemand"_ctv) || value.equal("MachineLifetime::ondemand"_ctv))
   {
      lifetime = MachineLifetime::ondemand;
      return true;
   }

   if (value.equal("spot"_ctv) || value.equal("MachineLifetime::spot"_ctv))
   {
      lifetime = MachineLifetime::spot;
      return true;
   }

   return false;
}

static bool parseClusterMachineBacking(const String& value, ClusterMachineBacking& backing)
{
   if (value.equal("owned"_ctv) || value.equal("ClusterMachineBacking::owned"_ctv))
   {
      backing = ClusterMachineBacking::owned;
      return true;
   }

   if (value.equal("cloud"_ctv) || value.equal("ClusterMachineBacking::cloud"_ctv))
   {
      backing = ClusterMachineBacking::cloud;
      return true;
   }

   return false;
}

static const char *machineLifetimeName(MachineLifetime lifetime)
{
   switch (lifetime)
   {
      case MachineLifetime::owned:
      {
         return "owned";
      }
      case MachineLifetime::reserved:
      {
         return "reserved";
      }
      case MachineLifetime::ondemand:
      {
         return "ondemand";
      }
      case MachineLifetime::spot:
      {
         return "spot";
      }
   }

   return "unknown";
}

static bool parseClusterMachineOwnershipMode(const String& value, ClusterMachineOwnershipMode& mode)
{
   if (value.equal("wholeMachine"_ctv) || value.equal("ClusterMachineOwnershipMode::wholeMachine"_ctv))
   {
      mode = ClusterMachineOwnershipMode::wholeMachine;
      return true;
   }

   if (value.equal("hardCaps"_ctv) || value.equal("ClusterMachineOwnershipMode::hardCaps"_ctv))
   {
      mode = ClusterMachineOwnershipMode::hardCaps;
      return true;
   }

   if (value.equal("percentages"_ctv) || value.equal("ClusterMachineOwnershipMode::percentages"_ctv))
   {
      mode = ClusterMachineOwnershipMode::percentages;
      return true;
   }

   return false;
}

static const char *clusterMachineOwnershipModeName(ClusterMachineOwnershipMode mode)
{
   switch (mode)
   {
      case ClusterMachineOwnershipMode::wholeMachine:
      {
         return "wholeMachine";
      }
      case ClusterMachineOwnershipMode::hardCaps:
      {
         return "hardCaps";
      }
      case ClusterMachineOwnershipMode::percentages:
      {
         return "percentages";
      }
   }

   return "unknown";
}

static bool parseClusterMachineOwnershipJSON(simdjson::dom::element value, ClusterMachineOwnership& ownership, const char *context)
{
   if (value.type() != simdjson::dom::element_type::OBJECT)
   {
      basics_log("%s requires object\n", context);
      return false;
   }

   ClusterMachineOwnership parsed = {};
   for (auto field : value.get_object())
   {
      String key;
      key.setInvariant(field.key.data(), field.key.size());

      if (key.equal("mode"_ctv))
      {
         if (field.value.type() != simdjson::dom::element_type::STRING)
         {
            basics_log("%s.mode requires string\n", context);
            return false;
         }

         String mode;
         mode.setInvariant(field.value.get_c_str());
         if (parseClusterMachineOwnershipMode(mode, parsed.mode) == false)
         {
            basics_log("%s.mode invalid\n", context);
            return false;
         }
      }
      else if (key.equal("nLogicalCoresCap"_ctv))
      {
         int64_t number = 0;
         if (field.value.type() != simdjson::dom::element_type::INT64 || field.value.get(number) != simdjson::SUCCESS || number < 0 || number > INT32_MAX)
         {
            basics_log("%s.nLogicalCoresCap invalid\n", context);
            return false;
         }

         parsed.nLogicalCoresCap = uint32_t(number);
      }
      else if (key.equal("nMemoryMBCap"_ctv))
      {
         int64_t number = 0;
         if (field.value.type() != simdjson::dom::element_type::INT64 || field.value.get(number) != simdjson::SUCCESS || number < 0 || number > INT32_MAX)
         {
            basics_log("%s.nMemoryMBCap invalid\n", context);
            return false;
         }

         parsed.nMemoryMBCap = uint32_t(number);
      }
      else if (key.equal("nStorageMBCap"_ctv))
      {
         int64_t number = 0;
         if (field.value.type() != simdjson::dom::element_type::INT64 || field.value.get(number) != simdjson::SUCCESS || number < 0 || number > INT32_MAX)
         {
            basics_log("%s.nStorageMBCap invalid\n", context);
            return false;
         }

         parsed.nStorageMBCap = uint32_t(number);
      }
      else if (key.equal("nLogicalCoresBasisPoints"_ctv))
      {
         int64_t number = 0;
         if (field.value.type() != simdjson::dom::element_type::INT64 || field.value.get(number) != simdjson::SUCCESS || number < 0 || number > UINT16_MAX)
         {
            basics_log("%s.nLogicalCoresBasisPoints invalid\n", context);
            return false;
         }

         parsed.nLogicalCoresBasisPoints = uint16_t(number);
      }
      else if (key.equal("nMemoryBasisPoints"_ctv))
      {
         int64_t number = 0;
         if (field.value.type() != simdjson::dom::element_type::INT64 || field.value.get(number) != simdjson::SUCCESS || number < 0 || number > UINT16_MAX)
         {
            basics_log("%s.nMemoryBasisPoints invalid\n", context);
            return false;
         }

         parsed.nMemoryBasisPoints = uint16_t(number);
      }
      else if (key.equal("nStorageBasisPoints"_ctv))
      {
         int64_t number = 0;
         if (field.value.type() != simdjson::dom::element_type::INT64 || field.value.get(number) != simdjson::SUCCESS || number < 0 || number > UINT16_MAX)
         {
            basics_log("%s.nStorageBasisPoints invalid\n", context);
            return false;
         }

         parsed.nStorageBasisPoints = uint16_t(number);
      }
      else
      {
         basics_log("%s invalid field\n", context);
         return false;
      }
   }

   ownership = parsed;
   return true;
}

static bool parseClusterMachineCloudJSON(simdjson::dom::element value, ClusterMachineCloud& cloud, const char *context)
{
   if (value.type() != simdjson::dom::element_type::OBJECT)
   {
      basics_log("%s requires object\n", context);
      return false;
   }

   ClusterMachineCloud parsed = {};
   for (auto field : value.get_object())
   {
      String key;
      key.setInvariant(field.key.data(), field.key.size());

      if (key.equal("schema"_ctv))
      {
         if (field.value.type() != simdjson::dom::element_type::STRING)
         {
            basics_log("%s.schema requires string\n", context);
            return false;
         }

         parsed.schema.assign(field.value.get_c_str());
      }
      else if (key.equal("providerMachineType"_ctv))
      {
         if (field.value.type() != simdjson::dom::element_type::STRING)
         {
            basics_log("%s.providerMachineType requires string\n", context);
            return false;
         }

         parsed.providerMachineType.assign(field.value.get_c_str());
      }
      else if (key.equal("cloudID"_ctv))
      {
         if (field.value.type() != simdjson::dom::element_type::STRING)
         {
            basics_log("%s.cloudID requires string\n", context);
            return false;
         }

         parsed.cloudID.assign(field.value.get_c_str());
      }
      else
      {
         basics_log("%s invalid field\n", context);
         return false;
      }
   }

   cloud = std::move(parsed);
   return true;
}

static bool parseClusterMachineSchemaJSON(simdjson::dom::element value, MothershipProdigyClusterMachineSchema& schema, const char *context)
{
   if (value.type() != simdjson::dom::element_type::OBJECT)
   {
      basics_log("%s requires object\n", context);
      return false;
   }

   MothershipProdigyClusterMachineSchema parsed = {};
   for (auto field : value.get_object())
   {
      String key = {};
      key.setInvariant(field.key.data(), field.key.size());

      if (key.equal("schema"_ctv))
      {
         if (field.value.type() != simdjson::dom::element_type::STRING)
         {
            basics_log("%s.schema requires string\n", context);
            return false;
         }

         parsed.schema.assign(field.value.get_c_str());
      }
      else if (key.equal("kind"_ctv))
      {
         if (field.value.type() != simdjson::dom::element_type::STRING)
         {
            basics_log("%s.kind requires string\n", context);
            return false;
         }

         String kind = {};
         kind.setInvariant(field.value.get_c_str());
         if (parseMachineKind(kind, parsed.kind) == false)
         {
            basics_log("%s.kind invalid\n", context);
            return false;
         }
      }
      else if (key.equal("lifetime"_ctv))
      {
         if (field.value.type() != simdjson::dom::element_type::STRING)
         {
            basics_log("%s.lifetime requires string\n", context);
            return false;
         }

         String lifetime = {};
         lifetime.setInvariant(field.value.get_c_str());
         if (parseMachineLifetime(lifetime, parsed.lifetime) == false)
         {
            basics_log("%s.lifetime invalid\n", context);
            return false;
         }
      }
      else if (key.equal("ipxeScriptURL"_ctv))
      {
         if (field.value.type() != simdjson::dom::element_type::STRING)
         {
            basics_log("%s.ipxeScriptURL requires string\n", context);
            return false;
         }

         parsed.ipxeScriptURL.assign(field.value.get_c_str());
      }
      else if (key.equal("vmImageURI"_ctv))
      {
         if (field.value.type() != simdjson::dom::element_type::STRING)
         {
            basics_log("%s.vmImageURI requires string\n", context);
            return false;
         }

         parsed.vmImageURI.assign(field.value.get_c_str());
      }
      else if (key.equal("gcpInstanceTemplate"_ctv))
      {
         if (field.value.type() != simdjson::dom::element_type::STRING)
         {
            basics_log("%s.gcpInstanceTemplate requires string\n", context);
            return false;
         }

         parsed.gcpInstanceTemplate.assign(field.value.get_c_str());
      }
      else if (key.equal("gcpInstanceTemplateSpot"_ctv))
      {
         if (field.value.type() != simdjson::dom::element_type::STRING)
         {
            basics_log("%s.gcpInstanceTemplateSpot requires string\n", context);
            return false;
         }

         parsed.gcpInstanceTemplateSpot.assign(field.value.get_c_str());
      }
      else if (key.equal("providerMachineType"_ctv))
      {
         if (field.value.type() != simdjson::dom::element_type::STRING)
         {
            basics_log("%s.providerMachineType requires string\n", context);
            return false;
         }

         parsed.providerMachineType.assign(field.value.get_c_str());
      }
      else if (key.equal("providerReservationID"_ctv))
      {
         if (field.value.type() != simdjson::dom::element_type::STRING)
         {
            basics_log("%s.providerReservationID requires string\n", context);
            return false;
         }

         parsed.providerReservationID.assign(field.value.get_c_str());
      }
      else if (key.equal("region"_ctv))
      {
         if (field.value.type() != simdjson::dom::element_type::STRING)
         {
            basics_log("%s.region requires string\n", context);
            return false;
         }

         parsed.region.assign(field.value.get_c_str());
      }
      else if (key.equal("zone"_ctv))
      {
         if (field.value.type() != simdjson::dom::element_type::STRING)
         {
            basics_log("%s.zone requires string\n", context);
            return false;
         }

         parsed.zone.assign(field.value.get_c_str());
      }
      else if (key.equal("budget"_ctv))
      {
         int64_t number = 0;
         if (field.value.type() != simdjson::dom::element_type::INT64
            || field.value.get(number) != simdjson::SUCCESS
            || number < 0
            || number > INT32_MAX)
         {
            basics_log("%s.budget invalid\n", context);
            return false;
         }

         parsed.budget = uint32_t(number);
      }
      else
      {
         basics_log("%s invalid field\n", context);
         return false;
      }
   }

   schema = std::move(parsed);
   return true;
}

static bool parseClusterGcpConfigJSON(simdjson::dom::element value, MothershipProdigyClusterGcpConfig& config, const char *context)
{
   if (value.type() != simdjson::dom::element_type::OBJECT)
   {
      basics_log("%s requires object\n", context);
      return false;
   }

   MothershipProdigyClusterGcpConfig parsed = {};
   for (auto field : value.get_object())
   {
      String key = {};
      key.setInvariant(field.key.data(), field.key.size());

      if (key.equal("serviceAccountEmail"_ctv))
      {
         if (field.value.type() != simdjson::dom::element_type::STRING)
         {
            basics_log("%s.serviceAccountEmail requires string\n", context);
            return false;
         }

         parsed.serviceAccountEmail.assign(field.value.get_c_str());
      }
      else if (key.equal("network"_ctv))
      {
         if (field.value.type() != simdjson::dom::element_type::STRING)
         {
            basics_log("%s.network requires string\n", context);
            return false;
         }

         parsed.network.assign(field.value.get_c_str());
      }
      else if (key.equal("subnetwork"_ctv))
      {
         if (field.value.type() != simdjson::dom::element_type::STRING)
         {
            basics_log("%s.subnetwork requires string\n", context);
            return false;
         }

         parsed.subnetwork.assign(field.value.get_c_str());
      }
      else
      {
         basics_log("%s invalid field\n", context);
         return false;
      }
   }

   config = std::move(parsed);
   return true;
}

static bool parseClusterAwsConfigJSON(simdjson::dom::element value, MothershipProdigyClusterAwsConfig& config, const char *context)
{
   if (value.type() != simdjson::dom::element_type::OBJECT)
   {
      basics_log("%s requires object\n", context);
      return false;
   }

   MothershipProdigyClusterAwsConfig parsed = {};
   for (auto field : value.get_object())
   {
      String key = {};
      key.setInvariant(field.key.data(), field.key.size());

      if (key.equal("instanceProfileName"_ctv))
      {
         if (field.value.type() != simdjson::dom::element_type::STRING)
         {
            basics_log("%s.instanceProfileName requires string\n", context);
            return false;
         }

         parsed.instanceProfileName.assign(field.value.get_c_str());
      }
      else if (key.equal("instanceProfileArn"_ctv))
      {
         if (field.value.type() != simdjson::dom::element_type::STRING)
         {
            basics_log("%s.instanceProfileArn requires string\n", context);
            return false;
         }

         parsed.instanceProfileArn.assign(field.value.get_c_str());
      }
      else
      {
         basics_log("%s invalid field\n", context);
         return false;
      }
   }

   config = std::move(parsed);
   return true;
}

static bool parseClusterAzureConfigJSON(simdjson::dom::element value, MothershipProdigyClusterAzureConfig& config, const char *context)
{
   if (value.type() != simdjson::dom::element_type::OBJECT)
   {
      basics_log("%s requires object\n", context);
      return false;
   }

   MothershipProdigyClusterAzureConfig parsed = {};
   for (auto field : value.get_object())
   {
      String key = {};
      key.setInvariant(field.key.data(), field.key.size());

      if (key.equal("managedIdentityName"_ctv))
      {
         if (field.value.type() != simdjson::dom::element_type::STRING)
         {
            basics_log("%s.managedIdentityName requires string\n", context);
            return false;
         }

         parsed.managedIdentityName.assign(field.value.get_c_str());
      }
      else if (key.equal("managedIdentityResourceID"_ctv))
      {
         if (field.value.type() != simdjson::dom::element_type::STRING)
         {
            basics_log("%s.managedIdentityResourceID requires string\n", context);
            return false;
         }

         parsed.managedIdentityResourceID.assign(field.value.get_c_str());
      }
      else
      {
         basics_log("%s invalid field\n", context);
         return false;
      }
   }

   config = std::move(parsed);
   return true;
}

static bool parseClusterMachineSchemaPatchJSON(simdjson::dom::element value, MothershipProdigyClusterMachineSchemaPatch& patch, const char *context)
{
   if (value.type() != simdjson::dom::element_type::OBJECT)
   {
      basics_log("%s requires object\n", context);
      return false;
   }

   MothershipProdigyClusterMachineSchemaPatch parsed = {};
   for (auto field : value.get_object())
   {
      String key = {};
      key.setInvariant(field.key.data(), field.key.size());

      if (key.equal("schema"_ctv))
      {
         if (field.value.type() != simdjson::dom::element_type::STRING)
         {
            basics_log("%s.schema requires string\n", context);
            return false;
         }

         parsed.schema.assign(field.value.get_c_str());
      }
      else if (key.equal("kind"_ctv))
      {
         if (field.value.type() != simdjson::dom::element_type::STRING)
         {
            basics_log("%s.kind requires string\n", context);
            return false;
         }

         String kind = {};
         kind.setInvariant(field.value.get_c_str());
         if (parseMachineKind(kind, parsed.kind) == false)
         {
            basics_log("%s.kind invalid\n", context);
            return false;
         }

         parsed.hasKind = true;
      }
      else if (key.equal("lifetime"_ctv))
      {
         if (field.value.type() != simdjson::dom::element_type::STRING)
         {
            basics_log("%s.lifetime requires string\n", context);
            return false;
         }

         String lifetime = {};
         lifetime.setInvariant(field.value.get_c_str());
         if (parseMachineLifetime(lifetime, parsed.lifetime) == false)
         {
            basics_log("%s.lifetime invalid\n", context);
            return false;
         }

         parsed.hasLifetime = true;
      }
      else if (key.equal("ipxeScriptURL"_ctv))
      {
         if (field.value.type() != simdjson::dom::element_type::STRING)
         {
            basics_log("%s.ipxeScriptURL requires string\n", context);
            return false;
         }

         parsed.ipxeScriptURL.assign(field.value.get_c_str());
         parsed.hasIpxeScriptURL = true;
      }
      else if (key.equal("vmImageURI"_ctv))
      {
         if (field.value.type() != simdjson::dom::element_type::STRING)
         {
            basics_log("%s.vmImageURI requires string\n", context);
            return false;
         }

         parsed.vmImageURI.assign(field.value.get_c_str());
         parsed.hasVmImageURI = true;
      }
      else if (key.equal("gcpInstanceTemplate"_ctv))
      {
         if (field.value.type() != simdjson::dom::element_type::STRING)
         {
            basics_log("%s.gcpInstanceTemplate requires string\n", context);
            return false;
         }

         parsed.gcpInstanceTemplate.assign(field.value.get_c_str());
         parsed.hasGcpInstanceTemplate = true;
      }
      else if (key.equal("gcpInstanceTemplateSpot"_ctv))
      {
         if (field.value.type() != simdjson::dom::element_type::STRING)
         {
            basics_log("%s.gcpInstanceTemplateSpot requires string\n", context);
            return false;
         }

         parsed.gcpInstanceTemplateSpot.assign(field.value.get_c_str());
         parsed.hasGcpInstanceTemplateSpot = true;
      }
      else if (key.equal("providerMachineType"_ctv))
      {
         if (field.value.type() != simdjson::dom::element_type::STRING)
         {
            basics_log("%s.providerMachineType requires string\n", context);
            return false;
         }

         parsed.providerMachineType.assign(field.value.get_c_str());
         parsed.hasProviderMachineType = true;
      }
      else if (key.equal("providerReservationID"_ctv))
      {
         if (field.value.type() != simdjson::dom::element_type::STRING)
         {
            basics_log("%s.providerReservationID requires string\n", context);
            return false;
         }

         parsed.providerReservationID.assign(field.value.get_c_str());
         parsed.hasProviderReservationID = true;
      }
      else if (key.equal("region"_ctv))
      {
         if (field.value.type() != simdjson::dom::element_type::STRING)
         {
            basics_log("%s.region requires string\n", context);
            return false;
         }

         parsed.region.assign(field.value.get_c_str());
         parsed.hasRegion = true;
      }
      else if (key.equal("zone"_ctv))
      {
         if (field.value.type() != simdjson::dom::element_type::STRING)
         {
            basics_log("%s.zone requires string\n", context);
            return false;
         }

         parsed.zone.assign(field.value.get_c_str());
         parsed.hasZone = true;
      }
      else if (key.equal("budget"_ctv))
      {
         int64_t number = 0;
         if (field.value.type() != simdjson::dom::element_type::INT64
            || field.value.get(number) != simdjson::SUCCESS
            || number < 0
            || number > INT32_MAX)
         {
            basics_log("%s.budget invalid\n", context);
            return false;
         }

         parsed.budget = uint32_t(number);
         parsed.hasBudget = true;
      }
      else
      {
         basics_log("%s invalid field\n", context);
         return false;
      }
   }

   patch = std::move(parsed);
   return true;
}

static void convertClusterMachineSchemaPatch(const MothershipProdigyClusterMachineSchemaPatch& source, ProdigyManagedMachineSchemaPatch& target)
{
   target = {};
   target.schema = source.schema;
   target.hasKind = source.hasKind;
   target.kind = source.kind;
   target.hasLifetime = source.hasLifetime;
   target.lifetime = source.lifetime;
   target.hasProviderMachineType = source.hasProviderMachineType;
   target.providerMachineType = source.providerMachineType;
   target.hasProviderReservationID = source.hasProviderReservationID;
   target.providerReservationID = source.providerReservationID;
   target.hasRegion = source.hasRegion;
   target.region = source.region;
   target.hasZone = source.hasZone;
   target.zone = source.zone;
   target.hasCpu = source.hasCpu;
   target.cpu = source.cpu;
   target.hasBudget = source.hasBudget;
   target.budget = source.budget;
}

static bool parseClusterMachineAddressJSON(simdjson::dom::element value, ClusterMachineAddress& address, const char *context)
{
   if (value.type() != simdjson::dom::element_type::OBJECT)
   {
      basics_log("%s requires object\n", context);
      return false;
   }

   ClusterMachineAddress parsed = {};
   for (auto field : value.get_object())
   {
      String key;
      key.setInvariant(field.key.data(), field.key.size());

      if (key.equal("address"_ctv))
      {
         if (field.value.type() != simdjson::dom::element_type::STRING)
         {
            basics_log("%s.address requires string\n", context);
            return false;
         }

         parsed.address.assign(field.value.get_c_str());
      }
      else if (key.equal("cidr"_ctv))
      {
         int64_t number = 0;
         if (field.value.type() != simdjson::dom::element_type::INT64 || field.value.get(number) != simdjson::SUCCESS || number < 0 || number > 255)
         {
            basics_log("%s.cidr invalid\n", context);
            return false;
         }

         parsed.cidr = uint8_t(number);
      }
      else if (key.equal("gateway"_ctv))
      {
         if (field.value.type() != simdjson::dom::element_type::STRING)
         {
            basics_log("%s.gateway requires string\n", context);
            return false;
         }

         parsed.gateway.assign(field.value.get_c_str());
      }
      else
      {
         basics_log("%s invalid field\n", context);
         return false;
      }
   }

   if (parsed.address.size() == 0)
   {
      basics_log("%s.address required\n", context);
      return false;
   }

   ClusterMachineAddress normalized = {};
   if (prodigyNormalizeClusterMachineAddress(parsed, normalized) == false)
   {
      basics_log("%s invalid\n", context);
      return false;
   }

   address = std::move(normalized);
   return true;
}

static bool parseClusterMachineAddressArrayJSON(simdjson::dom::element value, Vector<ClusterMachineAddress>& values, const char *context)
{
   values.clear();

   if (value.type() != simdjson::dom::element_type::ARRAY)
   {
      basics_log("%s requires array\n", context);
      return false;
   }

   uint32_t index = 0;
   for (auto item : value.get_array())
   {
      String itemContext = {};
      String contextText = {};
      contextText.assign(context);
      itemContext.snprintf<"{}[{itoa}]"_ctv>(contextText, index);

      ClusterMachineAddress address = {};
      if (parseClusterMachineAddressJSON(item, address, itemContext.c_str()) == false)
      {
         return false;
      }

      values.push_back(address);
      index += 1;
   }

   return true;
}

static bool parseSSHKeyPackageJSON(simdjson::dom::element value, Vault::SSHKeyPackage& package, const char *context)
{
   if (value.type() != simdjson::dom::element_type::OBJECT)
   {
      basics_log("%s requires object\n", context);
      return false;
   }

   Vault::SSHKeyPackage parsed = {};
   for (auto field : value.get_object())
   {
      String key = {};
      key.setInvariant(field.key.data(), field.key.size());

      if (key.equal("privateKeyOpenSSH"_ctv))
      {
         if (field.value.type() != simdjson::dom::element_type::STRING)
         {
            basics_log("%s.privateKeyOpenSSH requires string\n", context);
            return false;
         }

         parsed.privateKeyOpenSSH.assign(field.value.get_c_str());
      }
      else if (key.equal("publicKeyOpenSSH"_ctv))
      {
         if (field.value.type() != simdjson::dom::element_type::STRING)
         {
            basics_log("%s.publicKeyOpenSSH requires string\n", context);
            return false;
         }

         parsed.publicKeyOpenSSH.assign(field.value.get_c_str());
      }
      else
      {
         basics_log("%s invalid field\n", context);
         return false;
      }
   }

   String failure = {};
   if (Vault::validateSSHKeyPackageEd25519(parsed, &failure) == false)
   {
      basics_log("%s invalid: %s\n", context, failure.c_str());
      return false;
   }

   package = std::move(parsed);
   return true;
}

static bool parseClusterMachineSSHJSON(simdjson::dom::element value, ClusterMachineSSH& ssh, const char *context)
{
   if (value.type() != simdjson::dom::element_type::OBJECT)
   {
      basics_log("%s requires object\n", context);
      return false;
   }

   ClusterMachineSSH parsed = {};
   for (auto field : value.get_object())
   {
      String key;
      key.setInvariant(field.key.data(), field.key.size());

      if (key.equal("address"_ctv))
      {
         if (field.value.type() != simdjson::dom::element_type::STRING)
         {
            basics_log("%s.address requires string\n", context);
            return false;
         }

         parsed.address.assign(field.value.get_c_str());
      }
      else if (key.equal("port"_ctv))
      {
         int64_t number = 0;
         if (field.value.type() != simdjson::dom::element_type::INT64 || field.value.get(number) != simdjson::SUCCESS || number < 0 || number > UINT16_MAX)
         {
            basics_log("%s.port invalid\n", context);
            return false;
         }

         parsed.port = uint16_t(number);
      }
      else if (key.equal("user"_ctv))
      {
         if (field.value.type() != simdjson::dom::element_type::STRING)
         {
            basics_log("%s.user requires string\n", context);
            return false;
         }

         parsed.user.assign(field.value.get_c_str());
      }
      else if (key.equal("privateKeyPath"_ctv))
      {
         if (field.value.type() != simdjson::dom::element_type::STRING)
         {
            basics_log("%s.privateKeyPath requires string\n", context);
            return false;
         }

         parsed.privateKeyPath.assign(field.value.get_c_str());
      }
      else if (key.equal("hostPublicKeyOpenSSH"_ctv))
      {
         if (field.value.type() != simdjson::dom::element_type::STRING)
         {
            basics_log("%s.hostPublicKeyOpenSSH requires string\n", context);
            return false;
         }

         parsed.hostPublicKeyOpenSSH.assign(field.value.get_c_str());
      }
      else
      {
         basics_log("%s invalid field\n", context);
         return false;
      }
   }

   ssh = std::move(parsed);
   return true;
}

static bool parseClusterMachineAddressesJSON(simdjson::dom::element value, ClusterMachineAddresses& addresses, const char *context)
{
   String contextText = {};
   contextText.assign(context);

   if (value.type() != simdjson::dom::element_type::OBJECT)
   {
      basics_log("%s requires object\n", context);
      return false;
   }

   ClusterMachineAddresses parsed = {};
   for (auto field : value.get_object())
   {
      String key;
      key.setInvariant(field.key.data(), field.key.size());

      if (key.equal("private"_ctv))
      {
         String nestedContext = {};
         nestedContext.snprintf<"{}.private"_ctv>(contextText);
         if (parseClusterMachineAddressArrayJSON(field.value, parsed.privateAddresses, nestedContext.c_str()) == false)
         {
            return false;
         }
      }
      else if (key.equal("public"_ctv))
      {
         String nestedContext = {};
         nestedContext.snprintf<"{}.public"_ctv>(contextText);
         if (parseClusterMachineAddressArrayJSON(field.value, parsed.publicAddresses, nestedContext.c_str()) == false)
         {
            return false;
         }
      }
      else
      {
         basics_log("%s invalid field\n", context);
         return false;
      }
   }

   addresses = std::move(parsed);
   return true;
}

static bool parseMothershipClusterMachineJSON(simdjson::dom::element value, MothershipProdigyClusterMachine& machine, const char *context)
{
   String contextText = {};
   contextText.assign(context);

   if (value.type() != simdjson::dom::element_type::OBJECT)
   {
      basics_log("%s requires object members\n", context);
      return false;
   }

   MothershipProdigyClusterMachine parsed = {};
   for (auto field : value.get_object())
   {
      String key;
      key.setInvariant(field.key.data(), field.key.size());

      if (key.equal("backing"_ctv))
      {
         if (field.value.type() != simdjson::dom::element_type::STRING)
         {
            basics_log("%s.backing requires string\n", context);
            return false;
         }

         String backing;
         backing.setInvariant(field.value.get_c_str());
         if (parseClusterMachineBacking(backing, parsed.backing) == false)
         {
            basics_log("%s.backing invalid\n", context);
            return false;
         }
      }
      else if (key.equal("source"_ctv))
      {
         if (field.value.type() != simdjson::dom::element_type::STRING)
         {
            basics_log("%s.source requires string\n", context);
            return false;
         }

         String source;
         source.setInvariant(field.value.get_c_str());
         if (parseMothershipClusterMachineSource(source, parsed.source) == false)
         {
            basics_log("%s.source invalid\n", context);
            return false;
         }
      }
      else if (key.equal("kind"_ctv))
      {
         if (field.value.type() != simdjson::dom::element_type::STRING)
         {
            basics_log("%s.kind requires string\n", context);
            return false;
         }

         String kind;
         kind.setInvariant(field.value.get_c_str());
         if (parseMachineKind(kind, parsed.kind) == false)
         {
            basics_log("%s.kind invalid\n", context);
            return false;
         }
      }
      else if (key.equal("lifetime"_ctv))
      {
         if (field.value.type() != simdjson::dom::element_type::STRING)
         {
            basics_log("%s.lifetime requires string\n", context);
            return false;
         }

         String lifetime;
         lifetime.setInvariant(field.value.get_c_str());
         if (parseMachineLifetime(lifetime, parsed.lifetime) == false)
         {
            basics_log("%s.lifetime invalid\n", context);
            return false;
         }
      }
      else if (key.equal("isBrain"_ctv))
      {
         if (field.value.type() != simdjson::dom::element_type::BOOL)
         {
            basics_log("%s.isBrain requires bool\n", context);
            return false;
         }

         bool value = false;
         if (field.value.get(value) != simdjson::SUCCESS)
         {
            basics_log("%s.isBrain invalid\n", context);
            return false;
         }

         parsed.isBrain = value;
      }
      else if (key.equal("cloud"_ctv))
      {
         String nestedContext = {};
         nestedContext.snprintf<"{}.cloud"_ctv>(contextText);
         if (parseClusterMachineCloudJSON(field.value, parsed.cloud, nestedContext.c_str()) == false)
         {
            return false;
         }

         parsed.hasCloud = true;
      }
      else if (key.equal("ssh"_ctv))
      {
         String nestedContext = {};
         nestedContext.snprintf<"{}.ssh"_ctv>(contextText);
         if (parseClusterMachineSSHJSON(field.value, parsed.ssh, nestedContext.c_str()) == false)
         {
            return false;
         }
      }
      else if (key.equal("addresses"_ctv))
      {
         String nestedContext = {};
         nestedContext.snprintf<"{}.addresses"_ctv>(contextText);
         if (parseClusterMachineAddressesJSON(field.value, parsed.addresses, nestedContext.c_str()) == false)
         {
            return false;
         }
      }
      else if (key.equal("ownership"_ctv))
      {
         String nestedContext = {};
         nestedContext.snprintf<"{}.ownership"_ctv>(contextText);
         if (parseClusterMachineOwnershipJSON(field.value, parsed.ownership, nestedContext.c_str()) == false)
         {
            return false;
         }
      }
      else
      {
         basics_log("%s invalid field\n", context);
         return false;
      }
   }

   machine = std::move(parsed);
   return true;
}

static bool parseMothershipClusterMachinesJSON(simdjson::dom::element value, Vector<MothershipProdigyClusterMachine>& machines, const char *context)
{
   String contextText = {};
   contextText.assign(context);

   if (value.type() != simdjson::dom::element_type::ARRAY)
   {
      basics_log("%s requires array\n", context);
      return false;
   }

   Vector<MothershipProdigyClusterMachine> parsed = {};
   uint32_t index = 0;
   for (auto item : value.get_array())
   {
      String itemContext = {};
      itemContext.snprintf<"{}[{itoa}]"_ctv>(contextText, uint64_t(index));

      MothershipProdigyClusterMachine machine = {};
      if (parseMothershipClusterMachineJSON(item, machine, itemContext.c_str()) == false)
      {
         return false;
      }

      parsed.push_back(std::move(machine));
      index += 1;
   }

   machines = std::move(parsed);
   return true;
}

static void printClusterMachineOwnership(const ClusterMachineOwnership& ownership)
{
   basics_log("ownershipMode=%s caps=%u/%u/%u basisPoints=%u/%u/%u",
      clusterMachineOwnershipModeName(ownership.mode),
      unsigned(ownership.nLogicalCoresCap),
      unsigned(ownership.nMemoryMBCap),
      unsigned(ownership.nStorageMBCap),
      unsigned(ownership.nLogicalCoresBasisPoints),
      unsigned(ownership.nMemoryBasisPoints),
      unsigned(ownership.nStorageBasisPoints));
}

static bool formatCIDRPrefix(const IPPrefix& prefix, char *buffer, size_t bufferSize)
{
   if (buffer == nullptr || bufferSize == 0)
   {
      return false;
   }

   char addressBuffer[INET6_ADDRSTRLEN] = {0};
   if (inet_ntop(prefix.network.is6 ? AF_INET6 : AF_INET, prefix.network.v6, addressBuffer, sizeof(addressBuffer)) == nullptr)
   {
      return false;
   }

   int written = std::snprintf(buffer, bufferSize, "%s/%u", addressBuffer, unsigned(prefix.cidr));
   return written > 0 && size_t(written) < bufferSize;
}

static void renderMothershipClusterMachineIdentity(const MothershipProdigyClusterMachine& machine, String& label)
{
   label.clear();

   if (machine.cloudPresent() && machine.cloud.cloudID.size() > 0)
   {
      label.assign(machine.cloud.cloudID);
      return;
   }

   for (const ClusterMachineAddress& candidate : machine.addresses.privateAddresses)
   {
      if (candidate.address.size() > 0)
      {
         label.assign(candidate.address);
         return;
      }
   }

   if (machine.ssh.address.size() > 0)
   {
      label.assign(machine.ssh.address);
      return;
   }

   for (const ClusterMachineAddress& candidate : machine.addresses.publicAddresses)
   {
      if (candidate.address.size() > 0)
      {
         label.assign(candidate.address);
         return;
      }
   }

   label.assign("unknown-machine"_ctv);
}

static void mothershipHydrateTopologyRemoteCandidateSSH(const MothershipProdigyCluster& cluster, MothershipProdigyClusterMachine& candidate)
{
   if (candidate.ssh.address.size() == 0)
   {
      // Managed remote topology machines often do not carry an explicit SSH
      // address; prefer public reachability for Mothership-originated control.
      if (const ClusterMachineAddress *publicAddress = prodigyFirstClusterMachineAddress(candidate.addresses.publicAddresses); publicAddress != nullptr)
      {
         candidate.ssh.address = publicAddress->address;
      }
      else if (const ClusterMachineAddress *privateAddress = prodigyFirstClusterMachineAddress(candidate.addresses.privateAddresses); privateAddress != nullptr)
      {
         candidate.ssh.address = privateAddress->address;
      }
   }

   if (candidate.ssh.port == 0)
   {
      candidate.ssh.port = 22;
   }

   if (candidate.ssh.user.size() == 0)
   {
      if (cluster.bootstrapSshUser.size() > 0)
      {
         candidate.ssh.user = cluster.bootstrapSshUser;
      }
      else
      {
         candidate.ssh.user.assign(defaultMothershipClusterSSHUser());
      }
   }

   if (candidate.ssh.privateKeyPath.size() == 0)
   {
      candidate.ssh.privateKeyPath = cluster.bootstrapSshPrivateKeyPath;
   }

   if (candidate.ssh.hostPublicKeyOpenSSH.size() == 0)
   {
      candidate.ssh.hostPublicKeyOpenSSH = cluster.bootstrapSshHostKeyPackage.publicKeyOpenSSH;
   }
}

static void printManagedCluster(const MothershipProdigyCluster& cluster)
{
   String name = cluster.name;
   String clusterUUIDHex = {};
   clusterUUIDHex.assignItoh(cluster.clusterUUID);
   String lastRefreshFailure = cluster.lastRefreshFailure;
   String providerScope = cluster.providerScope;
   String providerCredentialName = cluster.providerCredentialName;

   basics_log("  name=%s clusterUUID=%s deploymentMode=%s provider=%s datacenterFragment=%u autoscaleIntervalSeconds=%u nBrains=%u desiredEnvironment=%s environmentConfigured=%d lastRefreshMs=%lld lastRefreshFailure=%s\n",
      name.c_str(),
      clusterUUIDHex.c_str(),
      mothershipClusterDeploymentModeName(cluster.deploymentMode),
      mothershipClusterProviderName(cluster.provider),
      unsigned(cluster.datacenterFragment),
      unsigned(cluster.autoscaleIntervalSeconds),
      unsigned(cluster.nBrains),
      prodigyEnvironmentKindName(cluster.desiredEnvironment),
      int(cluster.environmentConfigured),
      (long long)cluster.lastRefreshMs,
      (lastRefreshFailure.size() ? lastRefreshFailure.c_str() : ""));
   basics_log("    architecture=%s\n", machineCpuArchitectureName(cluster.architecture));

   if (cluster.deploymentMode == MothershipClusterDeploymentMode::local)
   {
      basics_log("    includeLocalMachine=%d\n", int(cluster.includeLocalMachine));
   }

   if (cluster.provider != MothershipClusterProvider::unknown || providerScope.size() > 0)
   {
      basics_log("    providerScope=%s providerCredentialName=%s propagateProviderCredentialToProdigy=%d\n",
         providerScope.size() ? providerScope.c_str() : "",
         providerCredentialName.c_str(),
         int(cluster.propagateProviderCredentialToProdigy));

      if (cluster.provider == MothershipClusterProvider::gcp || cluster.gcp.configured())
      {
         String serviceAccountEmail = cluster.gcp.serviceAccountEmail;
         String network = cluster.gcp.network;
         String subnetwork = cluster.gcp.subnetwork;
         basics_log("    gcp.serviceAccountEmail=%s gcp.network=%s gcp.subnetwork=%s\n",
            serviceAccountEmail.c_str(),
            network.c_str(),
            subnetwork.c_str());
      }

      if (cluster.provider == MothershipClusterProvider::aws || cluster.aws.configured())
      {
         String instanceProfileName = cluster.aws.instanceProfileName;
         String instanceProfileArn = cluster.aws.instanceProfileArn;
         basics_log("    aws.instanceProfileName=%s aws.instanceProfileArn=%s\n",
            instanceProfileName.c_str(),
            instanceProfileArn.c_str());
      }

      if (cluster.provider == MothershipClusterProvider::azure || cluster.azure.configured())
      {
         String managedIdentityName = cluster.azure.managedIdentityName;
         String managedIdentityResourceID = cluster.azure.managedIdentityResourceID;
         basics_log("    azure.managedIdentityName=%s azure.managedIdentityResourceID=%s\n",
            managedIdentityName.c_str(),
            managedIdentityResourceID.c_str());
      }
   }

   for (const MothershipProdigyClusterControl& control : cluster.controls)
   {
      String path = control.path;

      basics_log("    control kind=%s path=%s\n",
         mothershipClusterControlKindName(control.kind),
         path.c_str());
   }

   if ((cluster.deploymentMode == MothershipClusterDeploymentMode::remote)
      || (cluster.deploymentMode == MothershipClusterDeploymentMode::local && cluster.machines.empty() == false))
   {
      String bootstrapSshUser = cluster.bootstrapSshUser;
      String bootstrapSshPrivateKeyPath = cluster.bootstrapSshPrivateKeyPath;
      String remoteProdigyPath = cluster.remoteProdigyPath;

      basics_log("    bootstrapSshUser=%s bootstrapSshPrivateKeyPath=%s remoteProdigyPath=%s\n",
         bootstrapSshUser.c_str(),
         bootstrapSshPrivateKeyPath.c_str(),
         remoteProdigyPath.c_str());
   }

   if (cluster.deploymentMode == MothershipClusterDeploymentMode::test && cluster.test.specified)
   {
      String workspaceRoot = cluster.test.workspaceRoot;
      basics_log("    test hostMode=%s workspaceRoot=%s machineCount=%u brainBootstrapFamily=%s enableFakeIpv4Boundary=%d interContainerMTU=%u\n",
         mothershipClusterTestHostModeName(cluster.test.host.mode),
         workspaceRoot.c_str(),
         unsigned(cluster.test.machineCount),
         mothershipClusterTestBootstrapFamilyName(cluster.test.brainBootstrapFamily),
         int(cluster.test.enableFakeIpv4Boundary),
         unsigned(cluster.test.interContainerMTU));

      if (cluster.test.host.mode == MothershipClusterTestHostMode::ssh)
      {
         String sshAddress = cluster.test.host.ssh.address;
         String sshUser = cluster.test.host.ssh.user;
         String sshPrivateKeyPath = cluster.test.host.ssh.privateKeyPath;
         String remoteProdigyPath = cluster.remoteProdigyPath;
         basics_log("    testHost ssh.address=%s ssh.port=%u ssh.user=%s ssh.privateKeyPath=%s remoteProdigyPath=%s\n",
            sshAddress.c_str(),
            unsigned(cluster.test.host.ssh.port),
            sshUser.c_str(),
            sshPrivateKeyPath.c_str(),
            remoteProdigyPath.c_str());
      }
   }

   for (const MothershipProdigyClusterMachineSchema& managedSchema : cluster.machineSchemas)
   {
      String schema = managedSchema.schema;
      String ipxeScriptURL = managedSchema.ipxeScriptURL;
      String vmImageURI = managedSchema.vmImageURI;
      String gcpInstanceTemplate = managedSchema.gcpInstanceTemplate;
      String gcpInstanceTemplateSpot = managedSchema.gcpInstanceTemplateSpot;
      String providerMachineType = managedSchema.providerMachineType;
      String providerReservationID = managedSchema.providerReservationID;
      String region = managedSchema.region;
      String zone = managedSchema.zone;
      String cpuPlatform = managedSchema.cpu.cpuPlatform;
      basics_log("    schema=%s kind=%s lifetime=%s ipxeScriptURL=%s vmImageURI=%s gcpInstanceTemplate=%s gcpInstanceTemplateSpot=%s providerMachineType=%s providerReservationID=%s region=%s zone=%s cpuArchitecture=%s cpuPlatform=%s budget=%u\n",
         schema.c_str(),
         machineKindName(managedSchema.kind),
         machineLifetimeName(managedSchema.lifetime),
         ipxeScriptURL.c_str(),
         vmImageURI.c_str(),
         gcpInstanceTemplate.c_str(),
         gcpInstanceTemplateSpot.c_str(),
         providerMachineType.c_str(),
         providerReservationID.c_str(),
         region.c_str(),
         zone.c_str(),
         machineCpuArchitectureName(managedSchema.cpu.architecture),
         cpuPlatform.c_str(),
         unsigned(managedSchema.budget));
   }

   for (const MothershipProdigyClusterMachine& machine : cluster.machines)
   {
      String machineIdentity = {};
      renderMothershipClusterMachineIdentity(machine, machineIdentity);
      String sshAddress = machine.ssh.address;
      String sshUser = machine.ssh.user;
      String sshPrivateKeyPath = machine.ssh.privateKeyPath;
      String privateAddresses = {};
      String publicAddresses = {};
      prodigyAppendCommaSeparatedClusterMachineAddressList(machine.addresses.privateAddresses, privateAddresses);
      prodigyAppendCommaSeparatedClusterMachineAddressList(machine.addresses.publicAddresses, publicAddresses);
      if (machine.cloudPresent())
      {
         String schema = machine.cloud.schema;
         String providerMachineType = machine.cloud.providerMachineType;
         String cloudID = machine.cloud.cloudID;
         basics_log("    machine identity=%s schema=%s source=%s backing=%s kind=%s lifetime=%s isBrain=%d providerMachineType=%s cloudID=%s sshAddress=%s sshPort=%u sshUser=%s sshPrivateKeyPath=%s publicAddresses=%s privateAddresses=%s ",
            machineIdentity.c_str(),
            schema.c_str(),
            mothershipClusterMachineSourceName(machine.source),
            clusterMachineBackingName(machine.backing),
            machineKindName(machine.kind),
            machineLifetimeName(machine.lifetime),
            int(machine.isBrain),
            providerMachineType.c_str(),
            cloudID.c_str(),
            sshAddress.c_str(),
            unsigned(machine.ssh.port),
            sshUser.c_str(),
            sshPrivateKeyPath.c_str(),
            publicAddresses.c_str(),
            privateAddresses.c_str());
      }
      else
      {
         basics_log("    machine identity=%s source=%s backing=%s kind=%s lifetime=%s isBrain=%d sshAddress=%s sshPort=%u sshUser=%s sshPrivateKeyPath=%s publicAddresses=%s privateAddresses=%s ",
            machineIdentity.c_str(),
            mothershipClusterMachineSourceName(machine.source),
            clusterMachineBackingName(machine.backing),
            machineKindName(machine.kind),
            machineLifetimeName(machine.lifetime),
            int(machine.isBrain),
            sshAddress.c_str(),
            unsigned(machine.ssh.port),
            sshUser.c_str(),
            sshPrivateKeyPath.c_str(),
            publicAddresses.c_str(),
            privateAddresses.c_str());
      }
      printClusterMachineOwnership(machine.ownership);
      basics_log("\n");
   }

   if (cluster.topology.machines.empty() == false)
   {
      basics_log("    topology version=%llu machines=%u\n",
         (unsigned long long)cluster.topology.version,
         unsigned(cluster.topology.machines.size()));

      for (const ClusterMachine& machine : cluster.topology.machines)
      {
         String machineIdentity = {};
         machine.renderIdentityLabel(machineIdentity);
         String sshAddress = machine.ssh.address;
         String sshUser = machine.ssh.user;
         String sshPrivateKeyPath = machine.ssh.privateKeyPath;
         String privateAddresses = {};
         String publicAddresses = {};
         prodigyAppendCommaSeparatedClusterMachineAddressList(machine.addresses.privateAddresses, privateAddresses);
         prodigyAppendCommaSeparatedClusterMachineAddressList(machine.addresses.publicAddresses, publicAddresses);
         if (machine.cloudPresent())
         {
            String schema = machine.cloud.schema;
            String providerMachineType = machine.cloud.providerMachineType;
            String cloudID = machine.cloud.cloudID;
            basics_log("      topologyMachine identity=%s schema=%s source=%u backing=%s kind=%s lifetime=%s isBrain=%d providerMachineType=%s cloudID=%s sshAddress=%s sshPort=%u sshUser=%s sshPrivateKeyPath=%s publicAddresses=%s privateAddresses=%s creationTimeMs=%lld ",
               machineIdentity.c_str(),
               schema.c_str(),
               unsigned(machine.source),
               clusterMachineBackingName(machine.backing),
               machineKindName(machine.kind),
               machineLifetimeName(machine.lifetime),
               int(machine.isBrain),
               providerMachineType.c_str(),
               cloudID.c_str(),
               sshAddress.c_str(),
               unsigned(machine.ssh.port),
               sshUser.c_str(),
               sshPrivateKeyPath.c_str(),
               publicAddresses.c_str(),
               privateAddresses.c_str(),
               (long long)machine.creationTimeMs);
         }
         else
         {
            basics_log("      topologyMachine identity=%s source=%u backing=%s kind=%s lifetime=%s isBrain=%d sshAddress=%s sshPort=%u sshUser=%s sshPrivateKeyPath=%s publicAddresses=%s privateAddresses=%s creationTimeMs=%lld ",
               machineIdentity.c_str(),
               unsigned(machine.source),
               clusterMachineBackingName(machine.backing),
               machineKindName(machine.kind),
               machineLifetimeName(machine.lifetime),
               int(machine.isBrain),
               sshAddress.c_str(),
               unsigned(machine.ssh.port),
               sshUser.c_str(),
               sshPrivateKeyPath.c_str(),
               publicAddresses.c_str(),
               privateAddresses.c_str(),
               (long long)machine.creationTimeMs);
         }
         printClusterMachineOwnership(machine.ownership);
         basics_log(" owned=%u/%u/%u uuidSet=%d\n",
            unsigned(machine.ownedLogicalCores),
            unsigned(machine.ownedMemoryMB),
            unsigned(machine.ownedStorageMB),
            int(machine.uuid != 0));
      }
   }
}

static void printProviderCredential(const MothershipProviderCredential& credential)
{
   String name = credential.name;
   String scope = credential.scope;
   String impersonateServiceAccount = credential.impersonateServiceAccount;
   String credentialPath = credential.credentialPath;

   basics_log("  name=%s provider=%s mode=%s scope=%s allowPropagateToProdigy=%d materialPresent=%d materialBytes=%u impersonateServiceAccount=%s credentialPath=%s createdAtMs=%lld updatedAtMs=%lld\n",
      name.c_str(),
      mothershipClusterProviderName(credential.provider),
      mothershipProviderCredentialModeName(credential.mode),
      scope.c_str(),
      int(credential.allowPropagateToProdigy),
      int(credential.material.size() > 0),
      unsigned(credential.material.size()),
      impersonateServiceAccount.c_str(),
      credentialPath.c_str(),
      (long long)credential.createdAtMs,
      (long long)credential.updatedAtMs);
}

static bool resolveServiceName(String serviceName, uint64_t& service)
{
   if (auto it = MeshRegistry::serviceMappings.find(serviceName); it != MeshRegistry::serviceMappings.end())
   {
      service = it->second;
      return true;
   }

   int64_t dot = serviceName.rfindChar('.');
   if (dot <= 0 || dot >= int64_t(serviceName.size() - 1))
   {
      return false;
   }

   String suffix = serviceName.substr(uint64_t(dot + 1), serviceName.size() - uint64_t(dot + 1), Copy::no);
   if (suffix.size() <= 5 || memcmp(suffix.data(), "group", 5) != 0)
   {
      return false;
   }

   uint32_t group = 0;
   for (uint64_t i = 5; i < suffix.size(); i++)
   {
      uint8_t c = suffix.data()[i];
      if (c < '0' || c > '9')
      {
         return false;
      }

      group = (group * 10) + uint32_t(c - '0');
      if (group >= (1u << 10))
      {
         return false;
      }
   }

   String baseService = serviceName.substr(0, uint64_t(dot), Copy::yes);
   if (auto it = MeshRegistry::serviceMappings.find(baseService); it != MeshRegistry::serviceMappings.end())
   {
      if (MeshServices::isPrefix(it->second) == false)
      {
         return false;
      }

      service = MeshServices::constrainPrefixToGroup(it->second, uint16_t(group));
      return true;
   }

   return false;
}

static bool parseSymbolReference(const String& value, const char *kind, String& body)
{
   uint64_t kindSize = std::strlen(kind);
   uint64_t expectedSize = 2 + kindSize + 1;
   if (value.size() <= expectedSize)
   {
      return false;
   }

   if (value.data()[0] != '$' || value.data()[1] != '{' || value.data()[value.size() - 1] != '}')
   {
      return false;
   }

   if (std::memcmp(value.data() + 2, kind, kindSize) != 0)
   {
      return false;
   }

   if (value.data()[2 + kindSize] != ':')
   {
      return false;
   }

   body.assign(value.substr(3 + kindSize, value.size() - (3 + kindSize) - 1, Copy::no));
   return body.size() > 0;
}

static bool parseApplicationReferenceSymbol(const String& value, String& applicationName)
{
   if (parseSymbolReference(value, "application", applicationName))
   {
      return true;
   }

   return parseSymbolReference(value, "app", applicationName);
}

static bool parseServiceReferenceSymbol(const String& value, String& applicationName, String& serviceName, bool& hasGroup, uint16_t& group)
{
   String body;
   if (parseSymbolReference(value, "service", body) == false && parseSymbolReference(value, "svc", body) == false)
   {
      return false;
   }

   int64_t slash = body.findChar('/');
   if (slash <= 0 || slash >= int64_t(body.size() - 1))
   {
      return false;
   }

   applicationName.assign(body.substr(0, uint64_t(slash), Copy::no));

   String serviceSpec;
   serviceSpec.assign(body.substr(uint64_t(slash + 1), body.size() - uint64_t(slash + 1), Copy::no));
   if (serviceSpec.size() == 0)
   {
      return false;
   }

   hasGroup = false;
   group = 0;
   serviceName = serviceSpec;

   int64_t dot = serviceSpec.rfindChar('.');
   if (dot <= 0 || dot >= int64_t(serviceSpec.size() - 1))
   {
      return true;
   }

   String suffix = serviceSpec.substr(uint64_t(dot + 1), serviceSpec.size() - uint64_t(dot + 1), Copy::no);
   if (suffix.size() <= 5 || std::memcmp(suffix.data(), "group", 5) != 0)
   {
      return true;
   }

   uint32_t parsedGroup = 0;
   for (uint64_t i = 5; i < suffix.size(); i += 1)
   {
      uint8_t c = suffix.data()[i];
      if (c < '0' || c > '9')
      {
         return false;
      }

      parsedGroup = (parsedGroup * 10) + uint32_t(c - '0');
      if (parsedGroup >= (1u << 10))
      {
         return false;
      }
   }

   hasGroup = true;
   group = uint16_t(parsedGroup);
   serviceName.assign(serviceSpec.substr(0, uint64_t(dot), Copy::no));
   return serviceName.size() > 0;
}

static bool parseScalingDimensionAlias(const String& value, ScalingDimension& dimension)
{
   if (value.equal("ScalingDimension::cpu"_ctv) || value.equal("ResourceType::cpu"_ctv))
   {
      dimension = ScalingDimension::cpu;
      return true;
   }
   else if (value.equal("ScalingDimension::memory"_ctv) || value.equal("ResourceType::memory"_ctv))
   {
      dimension = ScalingDimension::memory;
      return true;
   }
   else if (value.equal("ScalingDimension::storage"_ctv) || value.equal("ResourceType::storage"_ctv))
   {
      dimension = ScalingDimension::storage;
      return true;
   }
   else if (value.equal("ScalingDimension::runtimeIngressQueueWaitComposite"_ctv) || value.equal("ResourceType::runtimeIngressQueueWaitComposite"_ctv))
   {
      dimension = ScalingDimension::runtimeIngressQueueWaitComposite;
      return true;
   }
   else if (value.equal("ScalingDimension::runtimeIngressHandlerComposite"_ctv) || value.equal("ResourceType::runtimeIngressHandlerComposite"_ctv))
   {
      dimension = ScalingDimension::runtimeIngressHandlerComposite;
      return true;
   }

   return false;
}

static bool resolveScalerMetricNameFromAlias(const String& value, String& metricName)
{
   ScalingDimension dimension = ScalingDimension::cpu;
   if (parseScalingDimensionAlias(value, dimension) == false)
   {
      return false;
   }

   const char *builtinName = ProdigyMetrics::nameForScalingDimension(dimension);
   if (builtinName == nullptr)
   {
      return false;
   }

   metricName.assign(builtinName);
   return true;
}

static constexpr uint32_t radarMinimumLogicalCores = 3;

static void printConnectFailure(void)
{
	basics_log("failed to connect to mothership: %s\n", std::strerror(errno));
}

static bool mothershipRunSSHCommand(LIBSSH2_SESSION *session, const String& command, String *failure = nullptr)
{
   String commandText = {};
   commandText.assign(command);
   LIBSSH2_CHANNEL *channel = libssh2_channel_open_session(session);
   if (channel == nullptr)
   {
      if (failure) failure->assign("failed to open ssh exec channel");
      return false;
   }

   if (libssh2_channel_exec(channel, commandText.c_str()) != 0)
   {
      if (failure) failure->snprintf<"failed to execute remote command {}"_ctv>(command);
      libssh2_channel_free(channel);
      return false;
   }

   char scratch[1024];
   while (libssh2_channel_read(channel, scratch, sizeof(scratch)) > 0) {}
   while (libssh2_channel_read_stderr(channel, scratch, sizeof(scratch)) > 0) {}

   (void)libssh2_channel_send_eof(channel);
   (void)libssh2_channel_wait_eof(channel);
   (void)libssh2_channel_close(channel);

   int exitStatus = libssh2_channel_get_exit_status(channel);
   libssh2_channel_free(channel);
   if (exitStatus != 0)
   {
      if (failure) failure->snprintf<"remote command failed: {}"_ctv>(command);
      return false;
   }

   if (failure) failure->clear();
   return true;
}

static void mothershipAppendSSHSessionLastError(LIBSSH2_SESSION *session, String& failure)
{
   if (session == nullptr)
   {
      return;
   }

   char *errmsg = nullptr;
   int len = 0;
   if (libssh2_session_last_error(session, &errmsg, &len, 0) == 0 && errmsg != nullptr && len > 0)
   {
      failure.append(reinterpret_cast<const uint8_t *>(errmsg), uint64_t(len));
   }
}

static bool mothershipWaitForSSHSessionIO(LIBSSH2_SESSION *session, int fd, int timeoutMs)
{
   if (session == nullptr || fd < 0)
   {
      return false;
   }

   struct pollfd descriptor = {};
   descriptor.fd = fd;
   descriptor.events = POLLHUP | POLLERR;

   int directions = libssh2_session_block_directions(session);
   if (directions & LIBSSH2_SESSION_BLOCK_INBOUND)
   {
      descriptor.events |= POLLIN;
   }

   if (directions & LIBSSH2_SESSION_BLOCK_OUTBOUND)
   {
      descriptor.events |= POLLOUT;
   }

   if (descriptor.events == 0)
   {
      descriptor.events = POLLHUP | POLLERR | POLLIN | POLLOUT;
   }

   int rc = ::poll(&descriptor, 1, timeoutMs);
   if (rc <= 0)
   {
      basics_log("mothership control ssh-wait rc=%d fd=%d timeoutMs=%d directions=%d events=%hd revents=%hd errno=%d(%s)\n",
         rc,
         fd,
         timeoutMs,
         directions,
         descriptor.events,
         descriptor.revents,
         errno,
         std::strerror(errno));
      return false;
   }

   if (descriptor.revents & (POLLHUP | POLLERR | POLLNVAL))
   {
      basics_log("mothership control ssh-wait-event fd=%d timeoutMs=%d directions=%d events=%hd revents=%hd\n",
         fd,
         timeoutMs,
         directions,
         descriptor.events,
         descriptor.revents);
   }

   return true;
}

static bool mothershipRunSSHCommandCaptureOutput(LIBSSH2_SESSION *session, int fd, const String& command, String& output, String *failure = nullptr, int timeoutMs = 25'000)
{
   output.clear();

   String commandText = {};
   commandText.assign(command);
   LIBSSH2_CHANNEL *channel = libssh2_channel_open_session(session);
   if (channel == nullptr)
   {
      if (failure) failure->assign("failed to open ssh exec channel");
      return false;
   }

   if (libssh2_channel_exec(channel, commandText.c_str()) != 0)
   {
      if (failure) failure->snprintf<"failed to execute remote command {}"_ctv>(command);
      libssh2_channel_free(channel);
      return false;
   }

   libssh2_session_set_blocking(session, 0);

   char scratch[2048];
   int64_t deadlineMs = Time::now<TimeResolution::ms>() + int64_t(timeoutMs);
   for (;;)
   {
      bool progressed = false;

      for (;;)
      {
         ssize_t rc = libssh2_channel_read(channel, scratch, sizeof(scratch));
         if (rc > 0)
         {
            output.append(reinterpret_cast<uint8_t *>(scratch), uint64_t(rc));
            progressed = true;
            continue;
         }

         if (rc == LIBSSH2_ERROR_EAGAIN)
         {
            break;
         }

         if (rc < 0)
         {
            if (failure)
            {
               failure->assign("failed to read remote command stdout: "_ctv);
               mothershipAppendSSHSessionLastError(session, *failure);
            }

            libssh2_session_set_blocking(session, 1);
            (void)libssh2_channel_close(channel);
            libssh2_channel_free(channel);
            return false;
         }

         break;
      }

      for (;;)
      {
         ssize_t rc = libssh2_channel_read_stderr(channel, scratch, sizeof(scratch));
         if (rc > 0)
         {
            output.append(reinterpret_cast<uint8_t *>(scratch), uint64_t(rc));
            progressed = true;
            continue;
         }

         if (rc == LIBSSH2_ERROR_EAGAIN)
         {
            break;
         }

         if (rc < 0)
         {
            if (failure)
            {
               failure->assign("failed to read remote command stderr: "_ctv);
               mothershipAppendSSHSessionLastError(session, *failure);
            }

            libssh2_session_set_blocking(session, 1);
            (void)libssh2_channel_close(channel);
            libssh2_channel_free(channel);
            return false;
         }

         break;
      }

      if (libssh2_channel_eof(channel))
      {
         break;
      }

      if (progressed)
      {
         continue;
      }

      int64_t nowMs = Time::now<TimeResolution::ms>();
      if (nowMs >= deadlineMs)
      {
         if (failure) failure->snprintf<"remote command timed out after {itoa}ms: {}"_ctv>(uint64_t(timeoutMs), command);
         libssh2_session_set_blocking(session, 1);
         (void)libssh2_channel_close(channel);
         libssh2_channel_free(channel);
         return false;
      }

      int remainingMs = int(deadlineMs - nowMs);
      if (mothershipWaitForSSHSessionIO(session, fd, remainingMs) == false)
      {
         if (failure) failure->snprintf<"remote command timed out after {itoa}ms waiting for ssh io: {}"_ctv>(uint64_t(timeoutMs), command);
         libssh2_session_set_blocking(session, 1);
         (void)libssh2_channel_close(channel);
         libssh2_channel_free(channel);
         return false;
      }
   }

   libssh2_session_set_blocking(session, 1);
   (void)libssh2_channel_send_eof(channel);
   (void)libssh2_channel_wait_eof(channel);
   (void)libssh2_channel_close(channel);

   int exitStatus = libssh2_channel_get_exit_status(channel);
   libssh2_channel_free(channel);
   if (exitStatus != 0)
   {
      if (failure) failure->snprintf<"remote command failed: {}"_ctv>(command);
      return false;
   }

   if (failure) failure->clear();
   return true;
}

static bool mothershipReadProcFile(const String& path, String& output)
{
   output.clear();

   String ownedPath = {};
   ownedPath.assign(path);
   int fd = ::open(ownedPath.c_str(), O_RDONLY | O_CLOEXEC);
   if (fd < 0)
   {
      return false;
   }

   char scratch[4096];
   for (;;)
   {
      ssize_t bytes = ::read(fd, scratch, sizeof(scratch));
      if (bytes == 0)
      {
         break;
      }

      if (bytes < 0)
      {
         if (errno == EINTR)
         {
            continue;
         }

         output.clear();
         ::close(fd);
         return false;
      }

      output.append(reinterpret_cast<uint8_t *>(scratch), uint64_t(bytes));
   }

   ::close(fd);
   return output.size() > 0;
}

static bool mothershipReadProcEnvironmentValue(uint32_t pid, const char *name, String& value)
{
   value.clear();
   if (name == nullptr || name[0] == '\0')
   {
      return false;
   }

   String path = {};
   path.snprintf<"/proc/{itoa}/environ"_ctv>(uint64_t(pid));

   String environment = {};
   if (mothershipReadProcFile(path, environment) == false)
   {
      return false;
   }

   const uint64_t nameLength = uint64_t(std::strlen(name));
   uint64_t offset = 0;
   while (offset < environment.size())
   {
      uint64_t end = offset;
      while (end < environment.size() && environment[end] != '\0')
      {
         end += 1;
      }

      if (end > offset + nameLength
         && std::memcmp(environment.data() + offset, name, nameLength) == 0
         && environment[offset + nameLength] == '=')
      {
         value.assign(environment.substr(offset + nameLength + 1, end - offset - nameLength - 1, Copy::yes));
         return value.size() > 0;
      }

      offset = end + 1;
   }

   return false;
}

static bool mothershipReadProcCommandLineValue(uint32_t pid, const char *name, String& value)
{
   value.clear();
   if (name == nullptr || name[0] == '\0')
   {
      return false;
   }

   String path = {};
   path.snprintf<"/proc/{itoa}/cmdline"_ctv>(uint64_t(pid));

   String commandLine = {};
   if (mothershipReadProcFile(path, commandLine) == false)
   {
      return false;
   }

   const uint64_t nameLength = uint64_t(std::strlen(name));
   uint64_t offset = 0;
   while (offset < commandLine.size())
   {
      uint64_t end = offset;
      while (end < commandLine.size() && commandLine[end] != '\0')
      {
         end += 1;
      }

      if (end > offset + nameLength
         && std::memcmp(commandLine.data() + offset, name, nameLength) == 0
         && commandLine[offset + nameLength] == '=')
      {
         value.assign(commandLine.substr(offset + nameLength + 1, end - offset - nameLength - 1, Copy::yes));
         return value.size() > 0;
      }

      if (end == offset + nameLength && std::memcmp(commandLine.data() + offset, name, nameLength) == 0)
      {
         offset = end + 1;
         if (offset >= commandLine.size())
         {
            return false;
         }

         uint64_t nextEnd = offset;
         while (nextEnd < commandLine.size() && commandLine[nextEnd] != '\0')
         {
            nextEnd += 1;
         }

         value.assign(commandLine.substr(offset, nextEnd - offset, Copy::yes));
         return value.size() > 0;
      }

      offset = end + 1;
   }

   return false;
}

static bool mothershipReadProcBootJSONControlSocketPath(uint32_t pid, String& controlSocketPath)
{
   controlSocketPath.clear();

   String bootJSON = {};
   if (mothershipReadProcCommandLineValue(pid, "--boot-json", bootJSON) == false)
   {
      return false;
   }

   ProdigyPersistentBootState bootState = {};
   if (parseProdigyPersistentBootStateJSON(bootJSON, bootState) == false)
   {
      return false;
   }

   if (bootState.bootstrapConfig.controlSocketPath.size() == 0)
   {
      return false;
   }

   controlSocketPath = bootState.bootstrapConfig.controlSocketPath;
   return true;
}

static bool mothershipPathIsUnixSocket(const String& path)
{
   String ownedPath = {};
   ownedPath.assign(path);
   struct stat st = {};
   if (::stat(ownedPath.c_str(), &st) != 0)
   {
      return false;
   }

   return S_ISSOCK(st.st_mode);
}

static bool mothershipIsProdigyProcess(uint32_t pid)
{
   String path = {};
   path.snprintf<"/proc/{itoa}/comm"_ctv>(uint64_t(pid));

   String processName = {};
   if (mothershipReadProcFile(path, processName) == false)
   {
      return false;
   }

   uint64_t trimmedLength = processName.size();
   while (trimmedLength > 0 && std::isspace(static_cast<unsigned char>(processName[trimmedLength - 1])))
   {
      trimmedLength -= 1;
   }

   if (trimmedLength != processName.size())
   {
      processName.assign(processName.substr(0, trimmedLength, Copy::yes));
   }

   return processName.equal("prodigy"_ctv);
}

static bool resolveLiveLocalProdigyControlSocketPath(String& controlSocketPath, String *failure = nullptr)
{
   controlSocketPath.clear();

   String expectedStateDBPath = {};
   resolveProdigyPersistentStateDBPath(expectedStateDBPath);

   DIR *proc = ::opendir("/proc");
   if (proc == nullptr)
   {
      if (failure) failure->snprintf<"failed to open /proc: {}"_ctv>(String(std::strerror(errno)));
      return false;
   }

   String singleCandidateSocketPath = {};
   uint32_t candidateCount = 0;

   while (dirent *entry = ::readdir(proc))
   {
      char *end = nullptr;
      unsigned long pidValue = std::strtoul(entry->d_name, &end, 10);
      if (end == entry->d_name || *end != '\0' || pidValue == 0 || pidValue > std::numeric_limits<uint32_t>::max())
      {
         continue;
      }

      uint32_t pid = uint32_t(pidValue);
      if (mothershipIsProdigyProcess(pid) == false)
      {
         continue;
      }

      String socketPath = {};
      if (mothershipReadProcBootJSONControlSocketPath(pid, socketPath) == false
         && mothershipReadProcEnvironmentValue(pid, "PRODIGY_MOTHERSHIP_SOCKET", socketPath) == false)
      {
         continue;
      }

      String stateDBPath = {};
      if (mothershipReadProcEnvironmentValue(pid, "PRODIGY_STATE_DB", stateDBPath) && stateDBPath.equals(expectedStateDBPath))
      {
         ::closedir(proc);
         controlSocketPath = socketPath;
         if (failure) failure->clear();
         return true;
      }

      candidateCount += 1;
      if (candidateCount == 1)
      {
         singleCandidateSocketPath = socketPath;
      }
   }

   ::closedir(proc);

   if (candidateCount == 1)
   {
      controlSocketPath = singleCandidateSocketPath;
      if (failure) failure->clear();
      return true;
   }

   if (candidateCount > 1)
   {
      if (failure)
      {
         failure->snprintf<"found {itoa} live local prodigy processes but none matched PRODIGY_STATE_DB={}"_ctv>(
            uint64_t(candidateCount),
            expectedStateDBPath);
      }

      return false;
   }

   if (failure) failure->assign("no live local prodigy process found"_ctv);
   return false;
}

static bool loadLocalProdigyControlSocketPath(String& controlSocketPath, String *failure = nullptr)
{
   if (const char *explicitSocketPath = getenv("PRODIGY_MOTHERSHIP_SOCKET"))
   {
      if (explicitSocketPath[0] == '\0')
      {
         if (failure) failure->assign("PRODIGY_MOTHERSHIP_SOCKET is empty"_ctv);
         return false;
      }

      controlSocketPath.assign(explicitSocketPath);
      if (mothershipPathIsUnixSocket(controlSocketPath))
      {
         if (failure) failure->clear();
         return true;
      }

      if (failure) failure->snprintf<"PRODIGY_MOTHERSHIP_SOCKET is not a live unix socket: {}"_ctv>(controlSocketPath);
      return false;
   }

   String liveProcessFailure = {};
   if (resolveLiveLocalProdigyControlSocketPath(controlSocketPath, &liveProcessFailure))
   {
      if (failure) failure->clear();
      return true;
   }

   ProdigyPersistentStateStore stateStore;
   ProdigyPersistentBootState bootState = {};
   String loadFailure;
   if (stateStore.loadBootState(bootState, &loadFailure) == false)
   {
      if (failure)
      {
         if (liveProcessFailure.size() > 0 && liveProcessFailure.equal("no live local prodigy process found"_ctv) == false)
         {
            failure->assign(liveProcessFailure);
            failure->append("; boot state fallback failed: "_ctv);
            if (loadFailure.equal("record not found"_ctv))
            {
               failure->append("local prodigy boot state not found"_ctv);
            }
            else
            {
               failure->append(loadFailure);
            }

            return false;
         }

         if (loadFailure.equal("record not found"_ctv))
         {
            failure->assign("local prodigy boot state not found"_ctv);
         }
         else
         {
            *failure = loadFailure;
         }
      }

      return false;
   }

   if (bootState.bootstrapConfig.controlSocketPath.size() == 0)
   {
      if (failure) failure->assign("local prodigy control socket path missing from boot state"_ctv);
      return false;
   }

   controlSocketPath = bootState.bootstrapConfig.controlSocketPath;
   if (failure) failure->clear();
   return true;
}

static bool resolveLocalProdigyExecutablePath(String& localProdigyPath, String *failure = nullptr)
{
   localProdigyPath.clear();

   String selfPath;
   if (prodigyResolveCurrentExecutablePath(selfPath))
   {
      String selfDirectory;
      prodigyDirname(selfPath, selfDirectory);

      localProdigyPath.assign(selfDirectory);
      if (localProdigyPath.size() > 0 && localProdigyPath[localProdigyPath.size() - 1] != '/')
      {
         localProdigyPath.append('/');
      }
      localProdigyPath.append("prodigy"_ctv);

      String localProdigyText = localProdigyPath;
      if (::access(localProdigyText.c_str(), X_OK) == 0)
      {
         if (failure) failure->clear();
         return true;
      }
   }

   localProdigyPath.assign("/root/prodigy/prodigy"_ctv);
   String installedBundleText = localProdigyPath;
   if (::access(installedBundleText.c_str(), X_OK) == 0)
   {
      if (failure) failure->clear();
      return true;
   }

   localProdigyPath.assign("/usr/local/bin/prodigy"_ctv);
   String fallbackText = localProdigyPath;
   if (::access(fallbackText.c_str(), X_OK) == 0)
   {
      if (failure) failure->clear();
      return true;
   }

   localProdigyPath.clear();
   if (failure) failure->assign("failed to locate local prodigy executable"_ctv);
   return false;
}

static bool mothershipReadLocalFile(const String& path, String& output, String *failure = nullptr)
{
   output.clear();

   if (path.size() == 0)
   {
      if (failure) failure->assign("path required"_ctv);
      return false;
   }

   String pathText = {};
   pathText.assign(path);
   int fd = ::open(pathText.c_str(), O_RDONLY | O_CLOEXEC);
   if (fd < 0)
   {
      if (failure) failure->snprintf<"failed to open local file {}: {}"_ctv>(path, String(std::strerror(errno)));
      return false;
   }

   char scratch[4096];
   for (;;)
   {
      ssize_t bytes = ::read(fd, scratch, sizeof(scratch));
      if (bytes == 0)
      {
         break;
      }

      if (bytes < 0)
      {
         if (errno == EINTR)
         {
            continue;
         }

         ::close(fd);
         if (failure) failure->snprintf<"failed to read local file {}: {}"_ctv>(path, String(std::strerror(errno)));
         output.clear();
         return false;
      }

      output.append(reinterpret_cast<uint8_t *>(scratch), uint64_t(bytes));
   }

   ::close(fd);
   if (failure) failure->clear();
   return true;
}

static bool resolveLocalProdigyDevNetnsHarnessPath(String& harnessPath, String *failure = nullptr)
{
   harnessPath.clear();

   if (const char *overridePath = getenv("PRODIGY_MOTHERSHIP_TEST_HARNESS"); overridePath && overridePath[0] != '\0')
   {
      harnessPath.assign(overridePath);
      if (::access(harnessPath.c_str(), R_OK) == 0)
      {
         if (failure) failure->clear();
         return true;
      }
   }

   String selfPath = {};
   if (prodigyResolveCurrentExecutablePath(selfPath))
   {
      String selfDirectory = {};
      prodigyDirname(selfPath, selfDirectory);
      String candidate = {};
      candidate.snprintf<"{}/../prodigy/dev/tests/prodigy_dev_netns_harness.sh"_ctv>(selfDirectory);
      if (::access(candidate.c_str(), R_OK) == 0)
      {
         harnessPath = candidate;
         if (failure) failure->clear();
         return true;
      }
   }

   harnessPath.assign("/root/prodigy/prodigy/dev/tests/prodigy_dev_netns_harness.sh"_ctv);
   if (::access(harnessPath.c_str(), R_OK) == 0)
   {
      if (failure) failure->clear();
      return true;
   }

   harnessPath.clear();
   if (failure) failure->assign("failed to locate prodigy dev netns harness"_ctv);
   return false;
}

static void mothershipBuildTestClusterHostMachine(const MothershipProdigyCluster& cluster, MothershipProdigyClusterMachine& machine)
{
   machine = {};
   machine.isBrain = true;
   machine.ssh = cluster.test.host.ssh;
}

static void mothershipAppendPersistentTestClusterHarnessCommand(const String& harnessPath, const String& prodigyPath, const MothershipProdigyCluster& cluster, String& command)
{
   String manifestPath = {};
   mothershipResolveTestClusterManifestPath(cluster, manifestPath);

   command.assign("bash "_ctv);
   prodigyAppendShellSingleQuoted(command, harnessPath);
   command.append(" "_ctv);
   prodigyAppendShellSingleQuoted(command, prodigyPath);
   command.append(" --runner-mode=persistent"_ctv);
   command.append(" --workspace-root="_ctv);
   prodigyAppendShellSingleQuoted(command, cluster.test.workspaceRoot);
   command.append(" --manifest-path="_ctv);
   prodigyAppendShellSingleQuoted(command, manifestPath);
   String machineCountText = {};
   machineCountText.snprintf<"{itoa}"_ctv>(uint64_t(cluster.test.machineCount));
   String brainCountText = {};
   brainCountText.snprintf<"{itoa}"_ctv>(uint64_t(cluster.nBrains));
   command.append(" --machines="_ctv);
   command.append(machineCountText);
   command.append(" --brains="_ctv);
   command.append(brainCountText);
   command.append(" --brain-bootstrap-family="_ctv);
   command.append(mothershipClusterTestBootstrapFamilyName(cluster.test.brainBootstrapFamily));
   command.append(" --enable-fake-ipv4-boundary="_ctv);
   if (cluster.test.enableFakeIpv4Boundary)
   {
      command.append("1"_ctv);
   }
   else
   {
      command.append("0"_ctv);
   }
   String interContainerMTUText = {};
   interContainerMTUText.snprintf<"{itoa}"_ctv>(uint64_t(
      cluster.test.interContainerMTU > 0
         ? cluster.test.interContainerMTU
         : prodigyRuntimeTestInterContainerMTUDefault));
   command.append(" --inter-container-mtu="_ctv);
   command.append(interContainerMTUText);
}

static void mothershipAppendPersistentTestClusterWorkspaceCleanup(const String& workspaceRoot, String& command)
{
   String sharedStorePath = {};
   sharedStorePath.assign(workspaceRoot);
   if (sharedStorePath.size() > 0 && sharedStorePath[sharedStorePath.size() - 1] != '/')
   {
      sharedStorePath.append("/"_ctv);
   }
   sharedStorePath.append("brain-shared-store"_ctv);

   command.append("if [ -d "_ctv);
   prodigyAppendShellSingleQuoted(command, sharedStorePath);
   command.append(" ]; then "_ctv);
   command.append("if command -v mountpoint >/dev/null 2>&1 && mountpoint -q "_ctv);
   prodigyAppendShellSingleQuoted(command, sharedStorePath);
   command.append("; then umount "_ctv);
   prodigyAppendShellSingleQuoted(command, sharedStorePath);
   command.append(" >/dev/null 2>&1 || umount -l "_ctv);
   prodigyAppendShellSingleQuoted(command, sharedStorePath);
   command.append(" >/dev/null 2>&1 || true; fi; fi; "_ctv);
   command.append("rm -rf "_ctv);
   prodigyAppendShellSingleQuoted(command, workspaceRoot);
   command.append(" >/dev/null 2>&1 || true; "_ctv);
}

static void mothershipBuildPersistentTestClusterStartCommand(const String& harnessPath, const String& prodigyPath, const MothershipProdigyCluster& cluster, String& command)
{
   String workspaceParent = {};
   prodigyDirname(cluster.test.workspaceRoot, workspaceParent);

   String pidPath = {};
   mothershipResolveTestClusterRunnerPIDPath(cluster, pidPath);
   String logPath = {};
   mothershipResolveTestClusterRunnerLogPath(cluster, logPath);

   String runnerCommand = {};
   mothershipAppendPersistentTestClusterHarnessCommand(harnessPath, prodigyPath, cluster, runnerCommand);

   command.clear();
   command.assign("set -euo pipefail; "_ctv);
   if (workspaceParent.size() > 0)
   {
      command.append("mkdir -p "_ctv);
      prodigyAppendShellSingleQuoted(command, workspaceParent);
      command.append("; "_ctv);
   }
   mothershipAppendPersistentTestClusterWorkspaceCleanup(cluster.test.workspaceRoot, command);
   command.append("mkdir -p "_ctv);
   prodigyAppendShellSingleQuoted(command, cluster.test.workspaceRoot);
   command.append("; setsid nohup env PRODIGY_DEV_KEEP_TMP=1 bash -lc "_ctv);
   prodigyAppendShellSingleQuoted(command, runnerCommand);
   command.append(" >"_ctv);
   prodigyAppendShellSingleQuoted(command, logPath);
   command.append(" 2>&1 < /dev/null & echo $! > "_ctv);
   prodigyAppendShellSingleQuoted(command, pidPath);
}

static void mothershipBuildPersistentTestClusterStopCommand(const MothershipProdigyCluster& cluster, String& command)
{
   String pidPath = {};
   mothershipResolveTestClusterRunnerPIDPath(cluster, pidPath);

   command.assign("set +e; "_ctv);
   command.append("if [ -f "_ctv);
   prodigyAppendShellSingleQuoted(command, pidPath);
   command.append(" ]; then "_ctv);
   command.append("pid=$(cat "_ctv);
   prodigyAppendShellSingleQuoted(command, pidPath);
   command.append(" 2>/dev/null || true); "_ctv);
   command.append("if [ -n \"$pid\" ]; then kill -TERM \"$pid\" >/dev/null 2>&1 || true; fi; "_ctv);
   command.append("for _ in $(seq 1 150); do if [ -z \"$pid\" ] || ! kill -0 \"$pid\" >/dev/null 2>&1; then break; fi; sleep 0.2; done; "_ctv);
   command.append("if [ -n \"$pid\" ] && kill -0 \"$pid\" >/dev/null 2>&1; then kill -KILL \"$pid\" >/dev/null 2>&1 || true; fi; "_ctv);
   command.append("fi; "_ctv);
   mothershipAppendPersistentTestClusterWorkspaceCleanup(cluster.test.workspaceRoot, command);
}

static bool mothershipWaitForLocalTestClusterReady(const MothershipProdigyCluster& cluster, String *failure = nullptr, int timeoutMs = 180'000)
{
   String manifestPath = {};
   mothershipResolveTestClusterManifestPath(cluster, manifestPath);
   String controlSocketPath = {};
   mothershipResolveTestClusterControlSocketPath(cluster, controlSocketPath);
   String pidPath = {};
   mothershipResolveTestClusterRunnerPIDPath(cluster, pidPath);
   String logPath = {};
   mothershipResolveTestClusterRunnerLogPath(cluster, logPath);

   int64_t deadlineMs = Time::now<TimeResolution::ms>() + timeoutMs;
   for (;;)
   {
      if (::access(manifestPath.c_str(), R_OK) == 0 && ::access(controlSocketPath.c_str(), F_OK) == 0)
      {
         if (failure) failure->clear();
         return true;
      }

      if (::access(pidPath.c_str(), R_OK) == 0)
      {
         String pidText = {};
         Filesystem::openReadAtClose(-1, pidPath, pidText);
         if (pidText.size() > 0)
         {
            pidText.addNullTerminator();
            long long runnerPID = std::atoll(pidText.c_str());
            if (runnerPID > 0 && ::kill(pid_t(runnerPID), 0) != 0 && errno == ESRCH)
            {
               if (failure)
               {
                  failure->snprintf<"local test cluster runner exited before ready workspaceRoot={} runnerPID={} runnerLogPath={} runnerLogPathExists={} manifestPathExists={} controlSocketPathExists={}"_ctv>(
                     cluster.test.workspaceRoot,
                     uint64_t(runnerPID),
                     logPath,
                     uint32_t(::access(logPath.c_str(), R_OK) == 0),
                     uint32_t(::access(manifestPath.c_str(), R_OK) == 0),
                     uint32_t(::access(controlSocketPath.c_str(), F_OK) == 0));
               }
               return false;
            }
         }
      }

      if (Time::now<TimeResolution::ms>() >= deadlineMs)
      {
         if (failure)
         {
            failure->snprintf<"timed out waiting for local test cluster manifest/socket in {} runnerPIDPath={} runnerPIDPathExists={} runnerLogPath={} runnerLogPathExists={}"_ctv>(
               cluster.test.workspaceRoot,
               pidPath,
               uint32_t(::access(pidPath.c_str(), R_OK) == 0),
               logPath,
               uint32_t(::access(logPath.c_str(), R_OK) == 0));
         }
         return false;
      }

      usleep(200'000);
   }
}

static bool mothershipSnapshotLocalTestClusterFailureWorkspace(const MothershipProdigyCluster& cluster, String& snapshotPath, String *failure = nullptr)
{
   snapshotPath.clear();

   if (cluster.test.workspaceRoot.size() == 0)
   {
      return false;
   }

   snapshotPath.assign(cluster.test.workspaceRoot);
   snapshotPath.append(".create-failure"_ctv);

   String command = {};
   command.assign("set -euo pipefail; "_ctv);
   command.append("rm -rf "_ctv);
   prodigyAppendShellSingleQuoted(command, snapshotPath);
   command.append("; if [ -d "_ctv);
   prodigyAppendShellSingleQuoted(command, cluster.test.workspaceRoot);
   command.append(" ]; then mkdir -p "_ctv);
   prodigyAppendShellSingleQuoted(command, snapshotPath);
   command.append("; cp -a "_ctv);
   prodigyAppendShellSingleQuoted(command, cluster.test.workspaceRoot);
   command.append("/. "_ctv);
   prodigyAppendShellSingleQuoted(command, snapshotPath);
   command.append("/; fi"_ctv);

   String commandFailure = {};
   if (prodigyRunLocalShellCommand(command, &commandFailure) == false)
   {
      if (failure)
      {
         failure->snprintf<"failed to snapshot local test cluster workspace {} -> {}: {}"_ctv>(
            cluster.test.workspaceRoot,
            snapshotPath,
            commandFailure);
      }
      snapshotPath.clear();
      return false;
   }

   if (::access(snapshotPath.c_str(), R_OK | X_OK) != 0)
   {
      snapshotPath.clear();
      return false;
   }

   if (failure) failure->clear();
   return true;
}

static bool mothershipUploadRemoteTestHarness(LIBSSH2_SESSION *session, const MothershipProdigyCluster& cluster, String *failure = nullptr)
{
   String localHarnessPath = {};
   if (resolveLocalProdigyDevNetnsHarnessPath(localHarnessPath, failure) == false)
   {
      return false;
   }

   String harnessContents = {};
   if (mothershipReadLocalFile(localHarnessPath, harnessContents, failure) == false)
   {
      return false;
   }

   String remoteHarnessPath = {};
   mothershipResolveTestClusterRunnerRemotePath(cluster, remoteHarnessPath);

   String workspaceParent = {};
   prodigyDirname(cluster.test.workspaceRoot, workspaceParent);

   String command = {};
   command.assign("set -euo pipefail; "_ctv);
   if (workspaceParent.size() > 0)
   {
      command.append("mkdir -p "_ctv);
      prodigyAppendShellSingleQuoted(command, workspaceParent);
      command.append("; "_ctv);
   }
   command.append("mkdir -p "_ctv);
   prodigyAppendShellSingleQuoted(command, cluster.test.workspaceRoot);
   command.append("; cat > "_ctv);
   prodigyAppendShellSingleQuoted(command, remoteHarnessPath);
   command.append(" <<'__PRODIGY_TEST_CLUSTER_RUNNER__'\n"_ctv);
   command.append(harnessContents);
   if (harnessContents.size() == 0 || harnessContents[harnessContents.size() - 1] != '\n')
   {
      command.append("\n"_ctv);
   }
   command.append("__PRODIGY_TEST_CLUSTER_RUNNER__\nchmod 700 "_ctv);
   prodigyAppendShellSingleQuoted(command, remoteHarnessPath);

   return mothershipRunSSHCommand(session, command, failure);
}

static bool mothershipWaitForRemoteTestClusterReady(const MothershipProdigyCluster& cluster, String *failure = nullptr, int timeoutMs = 120'000)
{
   String manifestPath = {};
   mothershipResolveTestClusterManifestPath(cluster, manifestPath);
   String controlSocketPath = {};
   mothershipResolveTestClusterControlSocketPath(cluster, controlSocketPath);

   String command = {};
   command.assign("test -S "_ctv);
   prodigyAppendShellSingleQuoted(command, controlSocketPath);
   command.append(" && test -s "_ctv);
   prodigyAppendShellSingleQuoted(command, manifestPath);
   command.append(" && printf READY"_ctv);

   int64_t deadlineMs = Time::now<TimeResolution::ms>() + timeoutMs;
   while (Time::now<TimeResolution::ms>() < deadlineMs)
   {
      MothershipProdigyClusterMachine remoteHost = {};
      mothershipBuildTestClusterHostMachine(cluster, remoteHost);

      LIBSSH2_SESSION *session = nullptr;
      int fd = -1;
      String connectFailure = {};
      if (mothershipConnectSSHSession(remoteHost, session, fd, &connectFailure))
      {
         String output = {};
         String waitFailure = {};
         bool ready = mothershipRunSSHCommandCaptureOutput(session, fd, command, output, &waitFailure, 5'000)
            && output.equal("READY"_ctv);
         mothershipCloseSSHSession(session, fd);
         if (ready)
         {
            if (failure) failure->clear();
            return true;
         }
      }

      usleep(200'000);
   }

   if (failure) failure->snprintf<"timed out waiting for remote test cluster manifest/socket in {}"_ctv>(cluster.test.workspaceRoot);
   return false;
}

static bool bootstrapLocalProdigy(const ProdigyPersistentBootState& bootState, String *failure = nullptr)
{
   if (failure) failure->clear();

   MachineCpuArchitecture sourceArchitecture = nametagCurrentBuildMachineArchitecture();
   if (prodigyMachineCpuArchitectureSupportedTarget(sourceArchitecture) == false)
   {
      if (failure) failure->assign("local build architecture unsupported for installed prodigy bundle selection"_ctv);
      return false;
   }

   String sourceBundle;
   String approvedBundleDigest = {};
   if (prodigyResolveInstalledApprovedBundleArtifact(sourceArchitecture, sourceBundle, approvedBundleDigest, failure) == false)
   {
      return false;
   }

   ProdigyInstallRootPaths installPaths = {};
   prodigyBuildInstallRootPaths("/root/prodigy"_ctv, installPaths);
   String controlSocketDirectory;
   prodigyDirname(bootState.bootstrapConfig.controlSocketPath, controlSocketDirectory);

   if (prodigyRunLocalShellCommand("systemctl stop prodigy || true"_ctv, failure) == false)
   {
      return false;
   }

   String mkdirCommand = "mkdir -p /var/lib/prodigy"_ctv;
   if (controlSocketDirectory.size() > 0)
   {
      mkdirCommand.append(" "_ctv);
      prodigyAppendShellSingleQuoted(mkdirCommand, controlSocketDirectory);
   }

   if (prodigyRunLocalShellCommand(mkdirCommand, failure) == false)
   {
      return false;
   }

   if (prodigyInstallBundleToRoot(sourceBundle, installPaths.installRoot, failure) == false)
   {
      return false;
   }

   String systemdUnit;
   renderProdigySystemdUnit(installPaths.binaryPath, installPaths.libraryDirectory, controlSocketDirectory, systemdUnit);
   Filesystem::eraseFile("/etc/systemd/system/prodigy.service.tmp"_ctv);
   if (Filesystem::openWriteAtClose(-1, "/etc/systemd/system/prodigy.service.tmp"_ctv, systemdUnit) < 0)
   {
      if (failure) failure->assign("failed to write local prodigy systemd unit"_ctv);
      return false;
   }

   if (Filesystem::renameFile("/etc/systemd/system/prodigy.service.tmp"_ctv, "/etc/systemd/system/prodigy.service"_ctv) != 0)
   {
      if (failure) failure->assign("failed to install local prodigy systemd unit"_ctv);
      return false;
   }

   String bootJSON;
   renderProdigyPersistentBootStateJSON(bootState, bootJSON);

   String persistCommand;
   persistCommand.assign("LD_LIBRARY_PATH="_ctv);
   prodigyAppendShellSingleQuoted(persistCommand, installPaths.libraryDirectory);
   persistCommand.append(" "_ctv);
   prodigyAppendShellSingleQuoted(persistCommand, installPaths.binaryPath);
   persistCommand.append(" --persist-only --reset-brain-snapshot --boot-json="_ctv);
   prodigyAppendShellSingleQuoted(persistCommand, bootJSON);
   if (prodigyRunLocalShellCommand(persistCommand, failure) == false)
   {
      return false;
   }

   if (prodigyRunLocalShellCommand("systemctl daemon-reload && systemctl enable prodigy && systemctl restart prodigy"_ctv, failure) == false)
   {
      return false;
   }

   return true;
}

class MothershipSocket {
public:

	enum class TransportMode : uint8_t
	{
		none = 0,
		stageTcp = 1,
		localUnix = 2,
		remoteSshUnix = 3
	};

	String rBuffer;
	String wBuffer;

	private:

		// Remote managed addMachines can spend tens of seconds between progress frames
		// while bootstrap/install runs on newly created brains. Keep the ssh-unix proxy
		// stream open long enough to receive the final completion frame.
		static constexpr int defaultSshTransportIOTimeoutMs = 120'000;

		TransportMode transportMode = TransportMode::none;
		String targetLabel;
		String lastConnectFailure;
		String lastIOFailure;
		String tcpAddress;
		uint16_t tcpPort = 0;
		Vector<String> controlPaths;
		Vector<MothershipProdigyClusterMachine> remoteMachines;
      Vault::SSHKeyPackage clusterBootstrapSshKeyPackage;
      String clusterBootstrapSshPrivateKeyPath;
		String matchedFrameBuffer;
		int transportFD = -1;
		LIBSSH2_SESSION *sshSession = nullptr;
		LIBSSH2_CHANNEL *sshChannel = nullptr;
		int sshFD = -1;
      pid_t sshTunnelPID = -1;
      String sshTunnelSocketPath;
      String sshTunnelKnownHostsPath;
      int sshTransportIOTimeoutMs = defaultSshTransportIOTimeoutMs;

		const char *transportModeName(void) const
		{
			switch (transportMode)
			{
				case TransportMode::none: return "none";
				case TransportMode::stageTcp: return "stageTcp";
				case TransportMode::localUnix: return "localUnix";
				case TransportMode::remoteSshUnix: return "remoteSshUnix";
			}

			return "unknown";
		}

		void clearTarget(void)
		{
			transportMode = TransportMode::none;
			targetLabel.clear();
			lastConnectFailure.clear();
			lastIOFailure.clear();
			tcpAddress.clear();
			tcpPort = 0;
         sshTransportIOTimeoutMs = defaultSshTransportIOTimeoutMs;
			controlPaths.clear();
			remoteMachines.clear();
         clusterBootstrapSshKeyPackage.clear();
         clusterBootstrapSshPrivateKeyPath.clear();
         sshTunnelKnownHostsPath.clear();
			matchedFrameBuffer.clear();
		}

		void disconnectSSH(void)
		{
         LIBSSH2_CHANNEL *channel = sshChannel;
         LIBSSH2_SESSION *session = sshSession;
         int fd = sshFD;
         pid_t tunnelPID = sshTunnelPID;
         String tunnelSocketPath = {};
         tunnelSocketPath.assign(sshTunnelSocketPath);
         String tunnelKnownHostsPath = {};
         tunnelKnownHostsPath.assign(sshTunnelKnownHostsPath);

	         sshChannel = nullptr;
	         sshSession = nullptr;
         sshFD = -1;
         sshTunnelPID = -1;
         sshTunnelSocketPath.clear();
         sshTunnelKnownHostsPath.clear();

         if (session != nullptr)
         {
            libssh2_session_set_blocking(session, 0);
         }

         // The ssh-unix proxy is request-scoped. Waiting for a graceful tunnel
         // shutdown can burn seconds after the response is already in hand, and
         // the child may inherit ignored SIGTERM dispositions from the parent.
         if (channel != nullptr)
         {
            (void)libssh2_channel_send_eof(channel);
            (void)libssh2_channel_close(channel);
         }

         if (session != nullptr)
         {
            (void)libssh2_session_disconnect(session, "Normal Shutdown");
         }

         if (fd >= 0)
         {
            (void)::shutdown(fd, SHUT_RDWR);
            ::close(fd);
         }

         if (channel != nullptr)
         {
            libssh2_channel_free(channel);
         }

         if (session != nullptr)
         {
            libssh2_session_free(session);
         }

         if (tunnelPID > 0)
         {
            (void)::kill(tunnelPID, SIGKILL);
            (void)::waitpid(tunnelPID, nullptr, 0);
         }

         if (tunnelSocketPath.size() > 0)
         {
            (void)::unlink(tunnelSocketPath.c_str());
         }

         if (tunnelKnownHostsPath.size() > 0)
         {
            (void)::unlink(tunnelKnownHostsPath.c_str());
         }
      }

	void disconnectLocal(void)
	{
		if (transportFD >= 0)
		{
			::close(transportFD);
			transportFD = -1;
		}
	}

		bool connectStageTcp(void)
		{
			int fd = -1;
			if (mothershipOpenConnectedSocket(tcpAddress, tcpPort, fd) == false)
			{
				lastConnectFailure.snprintf<"failed to connect tcp {}:{}"_ctv>(tcpAddress, unsigned(tcpPort));
				printConnectFailure();
				return false;
			}

			lastConnectFailure.clear();
			transportFD = fd;
			return true;
		}

		bool connectLocalUnixSocket(const String& path)
		{
			String socketPath = path;
			int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
			if (fd < 0)
			{
				lastConnectFailure.snprintf<"failed to create unix socket for {}: {}"_ctv>(path, String(std::strerror(errno)));
				return false;
			}

		struct sockaddr_un address = {};
		address.sun_family = AF_UNIX;
		std::snprintf(address.sun_path, sizeof(address.sun_path), "%s", socketPath.c_str());
		socklen_t addressLen = socklen_t(sizeof(address.sun_family) + std::strlen(address.sun_path));

			if (::connect(fd, reinterpret_cast<struct sockaddr *>(&address), addressLen) != 0)
			{
				lastConnectFailure.snprintf<"failed to connect local unix socket {}: {}"_ctv>(path, String(std::strerror(errno)));
				::close(fd);
				return false;
			}

			lastConnectFailure.clear();
			transportFD = fd;
			basics_log("mothership control connect mode=%s target=%s path=%.*s fd=%d\n",
				transportModeName(),
				targetLabel.c_str(),
				int(path.size()),
				reinterpret_cast<const char *>(path.data()),
				fd);
			return true;
		}

		bool connectRemoteMachineUnixSocket(const MothershipProdigyClusterMachine& machine, const String& path, String *failure = nullptr)
		{
			String sshUser = {};
			sshUser.assign(machine.ssh.user);
			String sshPrivateKeyPath = {};
			sshPrivateKeyPath.assign(machine.ssh.privateKeyPath);
			String socketPath = {};
			socketPath.assign(path);
			basics_log("mothership control ssh-unix-start target=%s ssh=%.*s:%u user=%s path=%s\n",
				targetLabel.c_str(),
				int(machine.ssh.address.size()),
				reinterpret_cast<const char *>(machine.ssh.address.data()),
				unsigned(machine.ssh.port),
				sshUser.c_str(),
				socketPath.c_str());

         disconnectSSH();

         uint64_t nonce = Time::now<TimeResolution::us>();
         String localTunnelPath = {};
         localTunnelPath.snprintf<"/tmp/prodigy-mothership-ssh-{itoa}-{itoa}.sock"_ctv>(uint64_t(::getpid()), nonce);
         (void)::unlink(localTunnelPath.c_str());
         String knownHostsPath = {};
         String knownHostLine = {};
         if (renderOpenSSHKnownHostLine(machine.ssh.address, machine.ssh.port, machine.ssh.hostPublicKeyOpenSSH, knownHostLine, failure) == false)
         {
            return false;
         }
         knownHostsPath.snprintf<"/tmp/prodigy-mothership-known-hosts-{itoa}-{itoa}"_ctv>(uint64_t(::getpid()), nonce);
         if (prodigyWriteLocalFile(knownHostsPath, knownHostLine, 0600, failure) == false)
         {
            return false;
         }

         pid_t pid = ::fork();
         if (pid < 0)
         {
            (void)::unlink(knownHostsPath.c_str());
            if (failure) failure->assign("failed to fork ssh tunnel"_ctv);
            return false;
         }

         if (pid == 0)
         {
            int devNullFD = ::open("/dev/null", O_RDWR);
            if (devNullFD >= 0)
            {
               (void)::dup2(devNullFD, STDIN_FILENO);
               (void)::dup2(devNullFD, STDOUT_FILENO);
               (void)::dup2(devNullFD, STDERR_FILENO);
               if (devNullFD > STDERR_FILENO)
               {
                  ::close(devNullFD);
               }
            }

            String sshTarget = {};
            sshTarget.snprintf<"{}@{}"_ctv>(sshUser, machine.ssh.address);
            String sshPortText = {};
            sshPortText.assignItoa(machine.ssh.port);
            String knownHostsOption = {};
            knownHostsOption.snprintf<"UserKnownHostsFile={}"_ctv>(knownHostsPath);

            const char *argv[] = {
               "ssh",
               "-o", "BatchMode=yes",
               "-o", "ExitOnForwardFailure=yes",
               "-o", "StreamLocalBindUnlink=yes",
               "-o", "StrictHostKeyChecking=yes",
               "-o", nullptr,
               "-i", sshPrivateKeyPath.c_str(),
               "-p", sshPortText.c_str(),
               "-nNT",
               "-L", nullptr,
               sshTarget.c_str(),
               nullptr
            };

            String forwardSpec = {};
            forwardSpec.snprintf<"{}:{}"_ctv>(localTunnelPath, path);
            argv[10] = knownHostsOption.c_str();
            argv[17] = forwardSpec.c_str();
            ::execvp("ssh", const_cast<char * const *>(argv));
            _exit(111);
         }

         int64_t deadlineMs = Time::now<TimeResolution::ms>() + sshTransportIOTimeoutMs;
         for (;;)
         {
            if (mothershipPathIsUnixSocket(localTunnelPath))
            {
               sshTunnelPID = pid;
               sshTunnelSocketPath.assign(localTunnelPath);
               sshTunnelKnownHostsPath.assign(knownHostsPath);
               if (connectLocalUnixSocket(localTunnelPath))
               {
                  lastConnectFailure.clear();
                  lastIOFailure.clear();
                  basics_log("mothership control connect mode=remoteSshUnix target=%s ssh=%.*s:%u path=%.*s tunnel=%s tunnelPid=%d fd=%d\n",
                     targetLabel.c_str(),
                     int(machine.ssh.address.size()),
                     reinterpret_cast<const char *>(machine.ssh.address.data()),
                     unsigned(machine.ssh.port),
                     int(path.size()),
                     reinterpret_cast<const char *>(path.data()),
                     localTunnelPath.c_str(),
                     int(pid),
                     transportFD);
                  return true;
               }
            }

            int status = 0;
            pid_t waited = ::waitpid(pid, &status, WNOHANG);
            if (waited == pid)
            {
               (void)::unlink(localTunnelPath.c_str());
               (void)::unlink(knownHostsPath.c_str());
               if (failure)
               {
                  failure->snprintf<"ssh tunnel exited before unix socket became ready for {} via ssh {}:{} status={itoa}"_ctv>(
                     path,
                     machine.ssh.address,
                     unsigned(machine.ssh.port),
                     uint64_t(status));
               }
               return false;
            }

            if (Time::now<TimeResolution::ms>() >= deadlineMs)
            {
               (void)::kill(pid, SIGKILL);
               (void)::waitpid(pid, nullptr, 0);
               (void)::unlink(localTunnelPath.c_str());
               (void)::unlink(knownHostsPath.c_str());
               if (failure)
               {
                  failure->snprintf<"timed out waiting for ssh tunnel {} via ssh {}:{}"_ctv>(path, machine.ssh.address, unsigned(machine.ssh.port));
               }
               return false;
            }

            ::usleep(25 * 1000);
         }
		}

	bool connectCluster(void)
	{
		if (controlPaths.size() == 0)
		{
			basics_log("cluster %s has no unix control sockets\n", targetLabel.c_str());
			return false;
		}

		if (transportMode == TransportMode::localUnix)
		{
			for (const String& path : controlPaths)
			{
				basics_log("mothership control connect-attempt mode=%s target=%s path=%.*s\n",
					transportModeName(),
					targetLabel.c_str(),
					int(path.size()),
					reinterpret_cast<const char *>(path.data()));
				if (connectLocalUnixSocket(path))
				{
					return true;
				}
			}

			basics_log("failed to connect to local cluster %s via unix socket\n", targetLabel.c_str());
			return false;
		}

		if (remoteMachines.size() == 0)
		{
			basics_log("cluster %s has no candidate SSH machines\n", targetLabel.c_str());
			return false;
		}

			for (const String& path : controlPaths)
			{
				for (const MothershipProdigyClusterMachine& machine : remoteMachines)
				{
					String attemptFailure = {};
					basics_log("mothership control connect-attempt mode=%s target=%s ssh=%.*s:%u path=%.*s\n",
						transportModeName(),
						targetLabel.c_str(),
						int(machine.ssh.address.size()),
						reinterpret_cast<const char *>(machine.ssh.address.data()),
						unsigned(machine.ssh.port),
						int(path.size()),
						reinterpret_cast<const char *>(path.data()));
					disconnectSSH();
					if (connectRemoteMachineUnixSocket(machine, path, &attemptFailure))
					{
						return true;
					}

					basics_log("mothership control connect-failed mode=%s target=%s ssh=%.*s:%u path=%.*s failure=%s\n",
						transportModeName(),
						targetLabel.c_str(),
						int(machine.ssh.address.size()),
						reinterpret_cast<const char *>(machine.ssh.address.data()),
						unsigned(machine.ssh.port),
						int(path.size()),
						reinterpret_cast<const char *>(path.data()),
						attemptFailure.c_str());
					lastConnectFailure = attemptFailure;
				}
				}

				return false;
			}
			ssize_t recvTransport(uint8_t *buffer, size_t len)
			{
			if (transportMode == TransportMode::remoteSshUnix && sshChannel != nullptr)
			{
				int64_t deadlineMs = Time::now<TimeResolution::ms>() + sshTransportIOTimeoutMs;
            int64_t waitStartMs = Time::now<TimeResolution::ms>();
            int64_t nextWaitLogMs = waitStartMs + 1000;
            uint32_t waitLoops = 0;

			for (;;)
			{
					ssize_t rc = libssh2_channel_read(sshChannel, reinterpret_cast<char *>(buffer), len);
					if (rc > 0)
					{
						uint8_t sample[16] = {0};
						size_t sampleCount = (size_t(rc) < sizeof(sample) ? size_t(rc) : sizeof(sample));
						if (sampleCount > 0)
						{
							memcpy(sample, buffer, sampleCount);
						}
						basics_log("mothership control recv-transport mode=%s target=%s bytes=%zd\n",
							transportModeName(),
							targetLabel.c_str(),
							rc);
						basics_log("mothership control recv-transport-head mode=%s target=%s bytes=%zd sampleBytes=%zu sample=%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
							transportModeName(),
							targetLabel.c_str(),
							rc,
							sampleCount,
							unsigned(sample[0]),
							unsigned(sample[1]),
							unsigned(sample[2]),
							unsigned(sample[3]),
							unsigned(sample[4]),
							unsigned(sample[5]),
							unsigned(sample[6]),
							unsigned(sample[7]),
							unsigned(sample[8]),
							unsigned(sample[9]),
							unsigned(sample[10]),
							unsigned(sample[11]),
							unsigned(sample[12]),
							unsigned(sample[13]),
							unsigned(sample[14]),
							unsigned(sample[15]));
						return rc;
					}

					if (rc == 0 || libssh2_channel_eof(sshChannel))
					{
						basics_log("mothership control recv-transport-eof mode=%s target=%s\n",
							transportModeName(),
							targetLabel.c_str());
						return 0;
					}

					if (rc != LIBSSH2_ERROR_EAGAIN)
					{
						errno = EIO;
						basics_log("mothership control recv-transport-error mode=%s target=%s rc=%zd errno=%d\n",
							transportModeName(),
							targetLabel.c_str(),
							rc,
							errno);
						return -1;
					}

				++waitLoops;
				int64_t nowMs = Time::now<TimeResolution::ms>();
					if (nowMs >= deadlineMs)
					{
						errno = ETIMEDOUT;
						basics_log("mothership control recv-transport-timeout mode=%s target=%s len=%zu\n",
							transportModeName(),
							targetLabel.c_str(),
							len);
						return -1;
					}

               if (nowMs >= nextWaitLogMs)
               {
                  int directions = libssh2_session_block_directions(sshSession);
                  basics_log("mothership control recv-transport-wait mode=%s target=%s elapsedMs=%lld waitLoops=%u directions=%d len=%zu\n",
                     transportModeName(),
                     targetLabel.c_str(),
                     (long long)(nowMs - waitStartMs),
                     unsigned(waitLoops),
                     directions,
                     len);
                  nextWaitLogMs = nowMs + 1000;
               }

				int remainingMs = int(deadlineMs - nowMs);
					if (mothershipWaitForSSHSessionIO(sshSession, sshFD, remainingMs) == false)
					{
						errno = ETIMEDOUT;
						basics_log("mothership control recv-transport-wait-timeout mode=%s target=%s remainingMs=%d len=%zu\n",
							transportModeName(),
							targetLabel.c_str(),
							remainingMs,
							len);
						return -1;
					}
				}
			}

		return ::recv(transportFD, buffer, len, 0);
	}

		bool sendTransport(const uint8_t *buffer, size_t len)
		{
			if (transportMode == TransportMode::remoteSshUnix && sshChannel != nullptr)
			{
				int64_t deadlineMs = Time::now<TimeResolution::ms>() + sshTransportIOTimeoutMs;
			size_t sent = 0;
			while (sent < len)
			{
				ssize_t rc = libssh2_channel_write(sshChannel, reinterpret_cast<const char *>(buffer + sent), len - sent);
				if (rc > 0)
				{
					sent += size_t(rc);
					continue;
				}

					if (rc != LIBSSH2_ERROR_EAGAIN)
					{
						basics_log("mothership control send-transport-error mode=%s target=%s rc=%zd sent=%zu total=%zu\n",
							transportModeName(),
							targetLabel.c_str(),
							rc,
							sent,
							len);
						return false;
					}

				int64_t nowMs = Time::now<TimeResolution::ms>();
					if (nowMs >= deadlineMs)
					{
						errno = ETIMEDOUT;
						basics_log("mothership control send-transport-timeout mode=%s target=%s sent=%zu total=%zu\n",
							transportModeName(),
							targetLabel.c_str(),
							sent,
							len);
						return false;
					}

				int remainingMs = int(deadlineMs - nowMs);
					if (mothershipWaitForSSHSessionIO(sshSession, sshFD, remainingMs) == false)
					{
						errno = ETIMEDOUT;
						basics_log("mothership control send-transport-wait-timeout mode=%s target=%s sent=%zu total=%zu remainingMs=%d\n",
							transportModeName(),
							targetLabel.c_str(),
							sent,
							len,
							remainingMs);
						return false;
					}
				}

					basics_log("mothership control send-transport mode=%s target=%s bytes=%zu\n",
						transportModeName(),
						targetLabel.c_str(),
						len);
					return true;
				}

		size_t sent = 0;
		while (sent < len)
		{
			ssize_t rc = ::send(transportFD, buffer + sent, len - sent, 0);
			if (rc <= 0)
			{
				return false;
			}

			sent += size_t(rc);
		}

		return true;
	}

	public:

      void setRemoteIOTimeoutMs(int timeoutMs)
      {
         sshTransportIOTimeoutMs = std::max(timeoutMs, 1);
      }

		const String& connectFailureDetail(void) const
		{
			return lastConnectFailure;
		}

		const String& ioFailureDetail(void) const
		{
			return lastIOFailure;
		}

#ifdef PRODIGY_MOTHERSHIP_TEST_ACCESS
      const Vector<MothershipProdigyClusterMachine>& unitTestRemoteMachines(void) const
      {
         return remoteMachines;
      }
#endif

	bool setLocal(String *failure = nullptr)
	{
		clearTarget();
		transportMode = TransportMode::localUnix;
		targetLabel.assign("local"_ctv);

      String controlSocketPath;
      if (loadLocalProdigyControlSocketPath(controlSocketPath, failure) == false)
      {
         return false;
      }

	      controlPaths.push_back(controlSocketPath);
      if (failure) failure->clear();
      return true;
	}

	bool handleStageArg(const char *arg, String *failure = nullptr)
	{
      if (std::strcmp(arg, "local") == 0)
		{
			return setLocal(failure);
		}

		return false;
	}

	bool configureCluster(const MothershipProdigyCluster& cluster, String *failure = nullptr)
	{
		clearTarget();
		targetLabel = cluster.name;
      clusterBootstrapSshKeyPackage = cluster.bootstrapSshKeyPackage;
      clusterBootstrapSshPrivateKeyPath = cluster.bootstrapSshPrivateKeyPath;

		for (const MothershipProdigyClusterControl& control : cluster.controls)
		{
			if (control.kind == MothershipClusterControlKind::unixSocket)
			{
				controlPaths.push_back(control.path);
			}
		}

		if (controlPaths.size() == 0)
		{
			if (failure) failure->assign("cluster has no unixSocket controls"_ctv);
			return false;
		}

		if (mothershipClusterIncludesLocalMachine(cluster)
         || (cluster.deploymentMode == MothershipClusterDeploymentMode::test && cluster.test.host.mode == MothershipClusterTestHostMode::local))
		{
			transportMode = TransportMode::localUnix;
			if (failure) failure->clear();
			return true;
		}

		transportMode = TransportMode::remoteSshUnix;

      if (cluster.deploymentMode == MothershipClusterDeploymentMode::test)
      {
         MothershipProdigyClusterMachine candidate = {};
         candidate.isBrain = true;
         candidate.ssh = cluster.test.host.ssh;
         remoteMachines.push_back(candidate);
         if (failure) failure->clear();
         return true;
      }

      auto appendCandidate = [&] (const MothershipProdigyClusterMachine& machine) -> void {

         if (machine.ssh.address.size() == 0 || machine.ssh.privateKeyPath.size() == 0)
         {
            return;
         }

         remoteMachines.push_back(machine);
      };

      if (cluster.topology.machines.empty() == false)
      {
         for (const ClusterMachine& machine : cluster.topology.machines)
         {
            if (machine.isBrain == false)
            {
               continue;
            }

            MothershipProdigyClusterMachine candidate = {};
            candidate.ssh = machine.ssh;
            candidate.addresses = machine.addresses;
            candidate.isBrain = true;
            mothershipHydrateTopologyRemoteCandidateSSH(cluster, candidate);
            appendCandidate(candidate);
         }
      }

      if (remoteMachines.size() == 0)
      {
		   for (const MothershipProdigyClusterMachine& machine : cluster.machines)
		   {
			   if (machine.isBrain)
			   {
				   appendCandidate(machine);
			   }
		   }
      }

		if (remoteMachines.size() == 0 && cluster.topology.machines.empty() == false)
      {
         for (const ClusterMachine& machine : cluster.topology.machines)
         {
            MothershipProdigyClusterMachine candidate = {};
            candidate.ssh = machine.ssh;
            candidate.addresses = machine.addresses;
            mothershipHydrateTopologyRemoteCandidateSSH(cluster, candidate);
            appendCandidate(candidate);
         }
      }

		if (remoteMachines.size() == 0)
		{
			for (const MothershipProdigyClusterMachine& machine : cluster.machines)
			{
				appendCandidate(machine);
			}
		}

		if (failure) failure->clear();
		return true;
	}

		bool collectRemoteProdigyDiagnostics(String& diagnostics)
		{
      diagnostics.clear();

      if (transportMode != TransportMode::remoteSshUnix || remoteMachines.size() == 0)
      {
         return false;
      }

      String command = {};
      command.append("timeout "_ctv);
      String timeoutSeconds = {};
      timeoutSeconds.assignItoa(prodigyRemoteBootstrapSocketDiagnosticsTimeoutSeconds);
      command.append(timeoutSeconds);
      command.append(
         "s sh -lc 'printf \"%s\\n\" \"=== systemctl ===\"; systemctl status prodigy --no-pager -l || true; "
         "printf \"\\n%s\\n\" \"=== journalctl ===\"; journalctl -u prodigy -n 120 --no-pager || true; "
         "printf \"\\n%s\\n\" \"=== boot state ===\"; PROD_EXE=$(readlink /proc/$(pidof prodigy)/exe 2>/dev/null || command -v prodigy || true); if [ -n \"$PROD_EXE\" ]; then PROD_DIR=$(dirname \"$PROD_EXE\"); LD_LIBRARY_PATH=\"$PROD_DIR/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}\" \"$PROD_EXE\" --print-boot-state || true; else echo \"prodigy binary not found\"; fi; "
         "printf \"\\n%s\\n\" \"=== bootstrap artifacts ===\"; command -v zstd || true; ls -ld /root/prodigy* /etc/systemd/system/prodigy* || true; "
         "printf \"\\n%s\\n\" \"=== socket ===\"; ls -ld /run/prodigy /run/prodigy/control.sock || true; "
         "printf \"\\n%s\\n\" \"=== unix listeners ===\"; ss -xlpn | grep prodigy || true; "
         "printf \"\\n%s\\n\" \"=== tcp listeners ===\"; ss -ltnp | grep prodigy || true; "
         "printf \"\\n%s\\n\" \"=== environment ===\"; PROD_PID=$(pidof prodigy 2>/dev/null || true); if [ -n \"$PROD_PID\" ]; then tr \"\\0\" \"\\n\" < /proc/$PROD_PID/environ | grep \"^PRODIGY_\" || true; fi; "
         "printf \"\\n%s\\n\" \"=== ps ===\"; ps -ef | grep \"[p]rodigy\" || true'"_ctv);

      for (const MothershipProdigyClusterMachine& machine : remoteMachines)
      {
         LIBSSH2_SESSION *session = nullptr;
         int fd = -1;
         String failure = {};
         if (mothershipConnectSSHSession(machine, session, fd, &failure, &clusterBootstrapSshKeyPackage, &clusterBootstrapSshPrivateKeyPath) == false)
         {
            continue;
         }

         String output = {};
	         bool ok = mothershipRunSSHCommandCaptureOutput(session, fd, command, output, &failure);
	         mothershipCloseSSHSession(session, fd);

         if (ok && output.size() > 0)
         {
            diagnostics.snprintf<"remote diagnostics from {}:\n{}"_ctv>(machine.ssh.address, output);
            return true;
         }

         if (failure.size() > 0)
         {
            diagnostics.snprintf<"failed to collect remote diagnostics from {}: {}"_ctv>(machine.ssh.address, failure);
            return true;
         }
      }

      return false;
   }

	int connect(void)
	{
		disconnect();
		rBuffer.clear();
		wBuffer.clear();
		matchedFrameBuffer.clear();

		switch (transportMode)
		{
			case TransportMode::stageTcp:
			{
				return connectStageTcp() ? 0 : -1;
			}
			case TransportMode::localUnix:
			case TransportMode::remoteSshUnix:
			{
				return connectCluster() ? 0 : -1;
			}
			case TransportMode::none:
			{
				basics_log("no mothership control target configured\n");
				return -1;
			}
		}

		return -1;
	}

	Message* recv(void)
	{
		rBuffer.clear();

		ssize_t result = recvTransport(reinterpret_cast<uint8_t *>(rBuffer.pTail()), rBuffer.remainingCapacity());
		if (result > 0)
		{
			rBuffer.advance(result);
		}

		if (result <= 0)
		{
			if (result < 0)
			{
				lastIOFailure.snprintf<"recv from mothership failed with result: {itoa} ({})"_ctv>(int64_t(result), String(std::strerror(errno)));
				basics_log("mothership control recv-failed mode=%s target=%s result=%zd errno=%d(%s)\n",
					transportModeName(),
					targetLabel.c_str(),
					result,
					errno,
					std::strerror(errno));
			}
			else
			{
				lastIOFailure.assign("recv from mothership failed with result: 0"_ctv);
				basics_log("mothership control recv-failed mode=%s target=%s result=%zd\n",
					transportModeName(),
					targetLabel.c_str(),
					result);
			}
			return nullptr;
		}

		lastIOFailure.clear();
		basics_log("mothership control recv mode=%s target=%s bytes=%zd\n",
			transportModeName(),
			targetLabel.c_str(),
			result);
		return reinterpret_cast<Message *>(rBuffer.data());
	}

	bool recvAppend(void)
	{
		if (rBuffer.remainingCapacity() == 0 && rBuffer.growCapacityByExponentialDecay() == false)
		{
			lastIOFailure.assign("recv from mothership failed: unable to grow receive buffer"_ctv);
			basics_log("mothership control recv-buffer-grow-failed mode=%s target=%s size=%zu capacity=%llu\n",
				transportModeName(),
				targetLabel.c_str(),
				size_t(rBuffer.size()),
				(unsigned long long)rBuffer.tentativeCapacity());
			return false;
		}

		ssize_t result = recvTransport(reinterpret_cast<uint8_t *>(rBuffer.pTail()), rBuffer.remainingCapacity());
		if (result > 0)
		{
			rBuffer.advance(result);
		}

		if (result <= 0)
		{
			if (result < 0)
			{
				lastIOFailure.snprintf<"recv from mothership failed with result: {itoa} ({})"_ctv>(int64_t(result), String(std::strerror(errno)));
				basics_log("mothership control recv-failed mode=%s target=%s result=%zd errno=%d(%s)\n",
					transportModeName(),
					targetLabel.c_str(),
					result,
					errno,
					std::strerror(errno));
			}
			else
			{
				lastIOFailure.assign("recv from mothership failed with result: 0"_ctv);
				basics_log("mothership control recv-failed mode=%s target=%s result=%zd\n",
					transportModeName(),
					targetLabel.c_str(),
					result);
			}
			return false;
		}

		lastIOFailure.clear();
		basics_log("mothership control recv mode=%s target=%s bytes=%zd buffered=%zu\n",
			transportModeName(),
			targetLabel.c_str(),
			result,
			size_t(rBuffer.size()));
		return true;
	}

	bool send(void)
	{
		uint16_t topic = 0;
		uint32_t messageSize = 0;
		uint8_t messagePadding = 0;
		uint8_t messageHeaderSize = 0;
		uint8_t sample[16] = {0};
		size_t sampleCount = 0;
		if (wBuffer.size() >= sizeof(Message))
		{
			const Message *message = reinterpret_cast<const Message *>(wBuffer.data());
			topic = message->topic;
			messageSize = message->size;
			messagePadding = message->padding;
			messageHeaderSize = message->headerSize;
			sampleCount = (wBuffer.size() < sizeof(sample) ? size_t(wBuffer.size()) : sizeof(sample));
			if (sampleCount > 0)
			{
				memcpy(sample, wBuffer.data(), sampleCount);
			}
		}
		basics_log("mothership control send mode=%s target=%s topic=%s(%u) bytes=%zu\n",
			transportModeName(),
			targetLabel.c_str(),
			prodigyMothershipTopicName(MothershipTopic(topic)),
			unsigned(topic),
			size_t(wBuffer.size()));
		if (topic == uint16_t(MothershipTopic::measureApplication) || topic == uint16_t(MothershipTopic::spinApplication))
		{
			basics_log(
				"mothership control send-head mode=%s target=%s topic=%s(%u) bytes=%zu messageSize=%u padding=%u header=%u sampleBytes=%zu sample=%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
				transportModeName(),
				targetLabel.c_str(),
				prodigyMothershipTopicName(MothershipTopic(topic)),
				unsigned(topic),
				size_t(wBuffer.size()),
				unsigned(messageSize),
				unsigned(messagePadding),
				unsigned(messageHeaderSize),
				sampleCount,
				unsigned(sample[0]),
				unsigned(sample[1]),
				unsigned(sample[2]),
				unsigned(sample[3]),
				unsigned(sample[4]),
				unsigned(sample[5]),
				unsigned(sample[6]),
				unsigned(sample[7]),
				unsigned(sample[8]),
				unsigned(sample[9]),
				unsigned(sample[10]),
				unsigned(sample[11]),
				unsigned(sample[12]),
				unsigned(sample[13]),
				unsigned(sample[14]),
				unsigned(sample[15]));
		}
		bool result = sendTransport(reinterpret_cast<const uint8_t *>(wBuffer.data()), wBuffer.size());
		wBuffer.clear();

		if (result == false)
		{
			if (errno != 0)
			{
				lastIOFailure.snprintf<"send to mothership failed: {}"_ctv>(String(std::strerror(errno)));
			}
			else
			{
				lastIOFailure.assign("send to mothership failed"_ctv);
			}
			basics_log("mothership control send-failed mode=%s target=%s topic=%s(%u) errno=%d(%s)\n",
				transportModeName(),
				targetLabel.c_str(),
				prodigyMothershipTopicName(MothershipTopic(topic)),
				unsigned(topic),
				errno,
				std::strerror(errno));
			return false;
		}

		lastIOFailure.clear();
		return true;
	}

	Message* sendRecv(void)
	{
		bool result = send();

		if (result == false) return nullptr;

		return recv();
	}

	Message* recvExpectedTopic(MothershipTopic expectedTopic, uint32_t maxReceives = 64)
	{
		constexpr uint64_t wireHeaderBytes = sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint8_t) + sizeof(uint8_t);

		for (uint32_t receiveAttempt = 0; receiveAttempt < maxReceives; ++receiveAttempt)
		{
			uint64_t cursorOffset = 0;
			bool awaitingMoreBytes = false;

			while (cursorOffset + wireHeaderBytes <= rBuffer.size())
			{
				uint8_t *cursor = rBuffer.data() + cursorOffset;
				uint32_t messageSize = 0;
				uint16_t messageTopic = 0;
				memcpy(&messageSize, cursor, sizeof(messageSize));
				memcpy(&messageTopic, cursor + sizeof(messageSize), sizeof(messageTopic));
				if (messageSize < wireHeaderBytes)
				{
					basics_log("invalid framed message from mothership (size too small)\n");
					lastIOFailure.assign("recv from mothership failed: framed message size smaller than header"_ctv);
					return nullptr;
				}

				if (messageSize > ProdigyWire::maxControlFrameBytes)
				{
					lastIOFailure.snprintf<"recv from mothership failed: framed message exceeds control-frame limit ({itoa} > {itoa})"_ctv>(
						uint64_t(messageSize),
						uint64_t(ProdigyWire::maxControlFrameBytes));
					basics_log("mothership control recv-oversized-frame mode=%s target=%s messageSize=%u limit=%u attempt=%u\n",
						transportModeName(),
						targetLabel.c_str(),
						unsigned(messageSize),
						unsigned(ProdigyWire::maxControlFrameBytes),
						receiveAttempt + 1);
					return nullptr;
				}

				uint64_t bufferedBytes = rBuffer.size() - cursorOffset;
				if (messageSize > bufferedBytes)
				{
					if (messageSize > rBuffer.tentativeCapacity() && rBuffer.reserve(messageSize) == false)
					{
						lastIOFailure.assign("recv from mothership failed: unable to reserve framed message buffer"_ctv);
						basics_log("mothership control recv-buffer-reserve-failed mode=%s target=%s messageSize=%u capacity=%llu\n",
							transportModeName(),
							targetLabel.c_str(),
							unsigned(messageSize),
							(unsigned long long)rBuffer.tentativeCapacity());
						return nullptr;
					}

					awaitingMoreBytes = true;
					break;
				}

				if (MothershipTopic(messageTopic) == expectedTopic)
				{
					matchedFrameBuffer.clear();
					matchedFrameBuffer.append(cursor, messageSize);
					uint64_t consumedBytes = cursorOffset + messageSize;
					uint64_t remaining = rBuffer.size() - consumedBytes;
					if (remaining > 0)
					{
						memmove(rBuffer.data(), rBuffer.data() + consumedBytes, remaining);
					}
					rBuffer.resize(remaining);
					basics_log("mothership control recv-topic mode=%s target=%s topic=%s(%u) expected=%s(%u) size=%u attempt=%u\n",
					transportModeName(),
					targetLabel.c_str(),
					prodigyMothershipTopicName(MothershipTopic(messageTopic)),
					unsigned(messageTopic),
					prodigyMothershipTopicName(expectedTopic),
					unsigned(expectedTopic),
					unsigned(messageSize),
					receiveAttempt + 1);
					return reinterpret_cast<Message *>(matchedFrameBuffer.data());
				}

				basics_log("mothership control recv-topic mode=%s target=%s topic=%s(%u) expected=%s(%u) size=%u attempt=%u ignored=1\n",
					transportModeName(),
					targetLabel.c_str(),
					prodigyMothershipTopicName(MothershipTopic(messageTopic)),
					unsigned(messageTopic),
					prodigyMothershipTopicName(expectedTopic),
					unsigned(expectedTopic),
					unsigned(messageSize),
					receiveAttempt + 1);

				cursorOffset += messageSize;
			}

			if (cursorOffset > 0)
			{
				uint64_t remaining = rBuffer.size() - cursorOffset;
				memmove(rBuffer.data(), rBuffer.data() + cursorOffset, remaining);
				rBuffer.resize(remaining);
			}

				if (awaitingMoreBytes || rBuffer.size() < wireHeaderBytes)
				{
					uint32_t peekSize = 0;
					uint16_t peekTopic = 0;
					uint8_t peekPadding = 0;
					uint8_t peekHeaderSize = 0;
					uint8_t sample[16] = {0};
					if (rBuffer.size() >= sizeof(uint32_t))
					{
						memcpy(&peekSize, rBuffer.data(), sizeof(uint32_t));
					}
					if (rBuffer.size() >= sizeof(uint32_t) + sizeof(uint16_t))
					{
						memcpy(&peekTopic, rBuffer.data() + sizeof(uint32_t), sizeof(uint16_t));
					}
					if (rBuffer.size() >= sizeof(uint32_t) + sizeof(uint16_t) + 1)
					{
						memcpy(&peekPadding, rBuffer.data() + sizeof(uint32_t) + sizeof(uint16_t), 1);
					}
					if (rBuffer.size() >= sizeof(uint32_t) + sizeof(uint16_t) + 2)
					{
						memcpy(&peekHeaderSize, rBuffer.data() + sizeof(uint32_t) + sizeof(uint16_t) + 1, 1);
					}
					size_t sampleCount = (rBuffer.size() < sizeof(sample) ? size_t(rBuffer.size()) : sizeof(sample));
					if (sampleCount > 0)
					{
						memcpy(sample, rBuffer.data(), sampleCount);
					}
					basics_log("mothership control recv-partial mode=%s target=%s buffered=%zu attempt=%u\n",
						transportModeName(),
						targetLabel.c_str(),
						size_t(rBuffer.size()),
						receiveAttempt + 1);
					basics_log("mothership control recv-partial-head mode=%s target=%s buffered=%zu peekSize=%u peekTopic=%u peekPadding=%u peekHeader=%u sampleBytes=%zu sample=%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
						transportModeName(),
						targetLabel.c_str(),
						size_t(rBuffer.size()),
						unsigned(peekSize),
						unsigned(peekTopic),
						unsigned(peekPadding),
						unsigned(peekHeaderSize),
						sampleCount,
						unsigned(sample[0]),
						unsigned(sample[1]),
						unsigned(sample[2]),
						unsigned(sample[3]),
						unsigned(sample[4]),
						unsigned(sample[5]),
						unsigned(sample[6]),
						unsigned(sample[7]),
						unsigned(sample[8]),
						unsigned(sample[9]),
						unsigned(sample[10]),
						unsigned(sample[11]),
						unsigned(sample[12]),
						unsigned(sample[13]),
						unsigned(sample[14]),
						unsigned(sample[15]));
				}

			if (recvAppend() == false) return nullptr;
			continue;

			if (cursorOffset != rBuffer.size())
			{
				basics_log("invalid framed message from mothership (trailing bytes)\n");
				return nullptr;
			}
		}

		basics_log("timed out waiting for response topic %u\n", uint32_t(expectedTopic));
		return nullptr;
	}

	bool ensureConnected(void)
	{
		if (transportMode == TransportMode::none)
		{
			return false;
		}

		if (transportMode == TransportMode::remoteSshUnix)
		{
			if (sshSession == nullptr || sshChannel == nullptr || sshFD < 0 || libssh2_channel_eof(sshChannel))
			{
				return connect() == 0;
			}
		}
		else if (transportFD < 0)
		{
			return connect() == 0;
		}

		int fd = (transportMode == TransportMode::remoteSshUnix) ? sshFD : transportFD;
		struct sockaddr_storage peer = {};
		socklen_t peerLength = sizeof(peer);
		if (::getpeername(fd, reinterpret_cast<struct sockaddr *>(&peer), &peerLength) == 0)
		{
			return true;
		}

		if (errno != ENOTCONN)
		{
			return false;
		}

		return connect() == 0;
	}

	bool requestApplicationID(ApplicationIDReserveRequest& request, ApplicationIDReserveResponse& response)
	{
		const bool debugDeploy = (std::getenv("PRODIGY_MOTHERSHIP_DEBUG_DEPLOY") != nullptr);

		if (ensureConnected() == false)
		{
			if (debugDeploy)
			{
				basics_log("DEPLOY_DEBUG requestApplicationID ensureConnected_failed\n");
				std::fflush(stdout);
			}
			return false;
		}

		if (debugDeploy)
		{
			basics_log("DEPLOY_DEBUG requestApplicationID app_name_len=%llu create=%u\n",
				static_cast<unsigned long long>(request.applicationName.size()),
				uint32_t(request.createIfMissing));
			(void)std::fwrite(request.applicationName.data(), 1, request.applicationName.size(), stdout);
			basics_log("\n");
			std::fflush(stdout);
		}

		uint32_t headerOffset = Message::appendHeader(wBuffer, MothershipTopic::reserveApplicationID);
		Message::serializeAndAppendObject(wBuffer, request);
		Message::finish(wBuffer, headerOffset);

		if (send() == false)
		{
			return false;
		}

		Message *responseMessage = recvExpectedTopic(MothershipTopic::reserveApplicationID);
		if (responseMessage == nullptr)
		{
			if (debugDeploy)
			{
				basics_log("DEPLOY_DEBUG requestApplicationID recv_failed\n");
				std::fflush(stdout);
			}
			return false;
		}

		String serializedResponse;
		uint8_t *args = responseMessage->args;
		if (debugDeploy)
		{
			basics_log("DEPLOY_DEBUG requestApplicationID response_size=%u\n", responseMessage->size);
			std::fflush(stdout);
		}
		Message::extractToStringView(args, serializedResponse);
		bool ok = BitseryEngine::deserializeSafe(serializedResponse, response);
		if (debugDeploy)
		{
			basics_log("DEPLOY_DEBUG requestApplicationID decoded=%u success=%u failure_len=%llu\n",
				uint32_t(ok),
				uint32_t(response.success),
				static_cast<unsigned long long>(response.failure.size()));
			if (response.failure.size())
			{
				(void)std::fwrite(response.failure.data(), 1, response.failure.size(), stdout);
				basics_log("\n");
			}
			std::fflush(stdout);
		}
		return ok;
	}

	bool requestServiceID(ApplicationServiceReserveRequest& request, ApplicationServiceReserveResponse& response)
	{
		const bool debugDeploy = (std::getenv("PRODIGY_MOTHERSHIP_DEBUG_DEPLOY") != nullptr);

		if (ensureConnected() == false)
		{
			if (debugDeploy)
			{
				basics_log("DEPLOY_DEBUG requestServiceID ensureConnected_failed\n");
				std::fflush(stdout);
			}
			return false;
		}

		if (debugDeploy)
		{
			basics_log("DEPLOY_DEBUG requestServiceID app_id=%u app_name_len=%llu service_name_len=%llu kind=%u create=%u\n",
				uint32_t(request.applicationID),
				static_cast<unsigned long long>(request.applicationName.size()),
				static_cast<unsigned long long>(request.serviceName.size()),
				uint32_t(request.kind),
				uint32_t(request.createIfMissing));
			std::fflush(stdout);
		}

		uint32_t headerOffset = Message::appendHeader(wBuffer, MothershipTopic::reserveServiceID);
		Message::serializeAndAppendObject(wBuffer, request);
		Message::finish(wBuffer, headerOffset);

		if (send() == false)
		{
			return false;
		}

		Message *responseMessage = recvExpectedTopic(MothershipTopic::reserveServiceID);
		if (responseMessage == nullptr)
		{
			if (debugDeploy)
			{
				basics_log("DEPLOY_DEBUG requestServiceID recv_failed\n");
				std::fflush(stdout);
			}
			return false;
		}

		String serializedResponse;
		uint8_t *args = responseMessage->args;
		if (debugDeploy)
		{
			basics_log("DEPLOY_DEBUG requestServiceID response_size=%u\n", responseMessage->size);
			std::fflush(stdout);
		}
		Message::extractToStringView(args, serializedResponse);
		return BitseryEngine::deserializeSafe(serializedResponse, response);
	}

	bool resolveApplicationIDReference(const String& reference, uint16_t& applicationID, bool createIfMissing = false)
	{
		String applicationName;
		if (parseApplicationReferenceSymbol(reference, applicationName) == false)
		{
			return false;
		}

		ApplicationIDReserveRequest request;
		request.applicationName = applicationName;
		request.createIfMissing = createIfMissing;

		ApplicationIDReserveResponse response;
		if (requestApplicationID(request, response) == false)
		{
			return false;
		}

		if (response.success == false || response.applicationID == 0)
		{
			return false;
		}

		applicationID = response.applicationID;
		return true;
	}

	bool resolveServiceReference(const String& reference, uint64_t& service)
	{
		const bool debugDeploy = (std::getenv("PRODIGY_MOTHERSHIP_DEBUG_DEPLOY") != nullptr);

		if (resolveServiceName(reference, service))
		{
			if (debugDeploy)
			{
				basics_log("DEPLOY_DEBUG resolveServiceReference builtin=%llu\n", static_cast<unsigned long long>(service));
				std::fflush(stdout);
			}
			return true;
		}

		String applicationName;
		String serviceName;
		bool hasGroup = false;
		uint16_t group = 0;
		if (parseServiceReferenceSymbol(reference, applicationName, serviceName, hasGroup, group) == false)
		{
			if (debugDeploy)
			{
				basics_log("DEPLOY_DEBUG resolveServiceReference parse_failed len=%llu\n", static_cast<unsigned long long>(reference.size()));
				std::fflush(stdout);
			}
			return false;
		}

		if (debugDeploy)
		{
			basics_log("DEPLOY_DEBUG resolveServiceReference parsed app_len=%llu service_len=%llu has_group=%u group=%u\n",
				static_cast<unsigned long long>(applicationName.size()),
				static_cast<unsigned long long>(serviceName.size()),
				uint32_t(hasGroup),
				uint32_t(group));
			(void)std::fwrite(applicationName.data(), 1, applicationName.size(), stdout);
			basics_log(" / ");
			(void)std::fwrite(serviceName.data(), 1, serviceName.size(), stdout);
			basics_log("\n");
			std::fflush(stdout);
		}

		ApplicationIDReserveRequest appRequest;
		appRequest.applicationName = applicationName;
		appRequest.createIfMissing = false;

		ApplicationIDReserveResponse appResponse;
		if (requestApplicationID(appRequest, appResponse) == false || appResponse.success == false || appResponse.applicationID == 0)
		{
			if (debugDeploy)
			{
				basics_log("DEPLOY_DEBUG resolveServiceReference app_lookup_failed success=%u app_id=%u\n",
					uint32_t(appResponse.success),
					uint32_t(appResponse.applicationID));
				std::fflush(stdout);
			}
			return false;
		}

		if (debugDeploy)
		{
			basics_log("DEPLOY_DEBUG resolveServiceReference app_lookup_ok app_id=%u\n", uint32_t(appResponse.applicationID));
			std::fflush(stdout);
		}

		ApplicationServiceReserveRequest serviceRequest;
		serviceRequest.applicationID = appResponse.applicationID;
		serviceRequest.applicationName = applicationName;
		serviceRequest.serviceName = serviceName;
		serviceRequest.createIfMissing = false;

		ApplicationServiceReserveResponse serviceResponse;
		if (requestServiceID(serviceRequest, serviceResponse) == false || serviceResponse.success == false || serviceResponse.service == 0)
		{
			if (debugDeploy)
			{
				basics_log("DEPLOY_DEBUG resolveServiceReference service_lookup_failed success=%u service=%llu\n",
					uint32_t(serviceResponse.success),
					static_cast<unsigned long long>(serviceResponse.service));
				std::fflush(stdout);
			}
			return false;
		}

		service = serviceResponse.service;
		if (debugDeploy)
		{
			basics_log("DEPLOY_DEBUG resolveServiceReference service_lookup_ok service=%llu kind=%u slot=%u\n",
				static_cast<unsigned long long>(service),
				uint32_t(serviceResponse.kind),
				uint32_t(serviceResponse.serviceSlot));
			std::fflush(stdout);
		}
		if (hasGroup)
		{
			if (MeshServices::isPrefix(service) == false)
			{
				return false;
			}

			service = MeshServices::constrainPrefixToGroup(service, group);
		}

		return true;
	}

	MothershipSocket()
	{
		rBuffer.reserve(64_KB);
		wBuffer.reserve(64_KB);
	}

	~MothershipSocket()
	{
		disconnect();
	}

	void disconnect(void)
	{
		disconnectLocal();
		disconnectSSH();
	}

	void close(void)
	{
		disconnect();
	}
};

class Mothership {
private:

	MothershipSocket socket;

   static MothershipClusterRegistry openClusterRegistry(void)
   {
      return MothershipClusterRegistry();
   }

   static MothershipProviderCredentialRegistry openProviderCredentialRegistry(void)
   {
      return MothershipProviderCredentialRegistry();
   }

   static void printMachineProvisioningProgress(const char *prefix, const Vector<MachineProvisioningProgress>& progress)
   {
      for (const MachineProvisioningProgress& machine : progress)
      {
         const char *schema = machine.cloud.schema.size() ? reinterpret_cast<const char *>(machine.cloud.schema.data()) : "";
         const char *providerMachineType = machine.cloud.providerMachineType.size() ? reinterpret_cast<const char *>(machine.cloud.providerMachineType.data()) : "";
         const char *providerName = machine.providerName.size() ? reinterpret_cast<const char *>(machine.providerName.data()) : "";
         const char *cloudID = machine.cloud.cloudID.size() ? reinterpret_cast<const char *>(machine.cloud.cloudID.data()) : "";
         const char *status = machine.status.size() ? reinterpret_cast<const char *>(machine.status.data()) : "";
         String publicAddresses = {};
         String privateAddresses = {};
         prodigyAppendCommaSeparatedClusterMachineAddressList(machine.addresses.publicAddresses, publicAddresses);
         prodigyAppendCommaSeparatedClusterMachineAddressList(machine.addresses.privateAddresses, privateAddresses);
         basics_log(
            "%s schema=%.*s providerMachineType=%.*s providerName=%.*s cloudID=%.*s status=%.*s ready=%u publicAddresses=%.*s privateAddresses=%.*s sshAddress=%.*s sshPort=%u sshUser=%.*s sshPrivateKeyPath=%.*s\n",
            prefix,
            int(machine.cloud.schema.size()), schema,
            int(machine.cloud.providerMachineType.size()), providerMachineType,
            int(machine.providerName.size()), providerName,
            int(machine.cloud.cloudID.size()), cloudID,
            int(machine.status.size()), status,
            machine.ready ? 1u : 0u,
            int(publicAddresses.size()), reinterpret_cast<const char *>(publicAddresses.data()),
            int(privateAddresses.size()), reinterpret_cast<const char *>(privateAddresses.data()),
            int(machine.ssh.address.size()), reinterpret_cast<const char *>(machine.ssh.address.data()),
            unsigned(machine.ssh.port),
            int(machine.ssh.user.size()), reinterpret_cast<const char *>(machine.ssh.user.data()),
            int(machine.ssh.privateKeyPath.size()), reinterpret_cast<const char *>(machine.ssh.privateKeyPath.data())
         );
      }
   }

   static void printBrainReachabilityResults(const char *prefix, const String& targetAddress, const Vector<BrainReachabilityProbeResult>& results)
   {
      for (const BrainReachabilityProbeResult& result : results)
      {
         const char *brainLabel = result.brainLabel.size() ? reinterpret_cast<const char *>(result.brainLabel.data()) : "";
         const char *failure = result.failure.size() ? reinterpret_cast<const char *>(result.failure.data()) : "";
         const char *target = targetAddress.size() ? reinterpret_cast<const char *>(targetAddress.data()) : "";

         basics_log(
            "%s target=%.*s brain=%.*s reachable=%u latencyMs=%u failure=%.*s\n",
            prefix,
            int(targetAddress.size()), target,
            int(result.brainLabel.size()), brainLabel,
            result.reachable ? 1u : 0u,
            result.latencyMs,
            int(result.failure.size()), failure
         );
      }
   }

#if PRODIGY_ENABLE_CREATE_TIMING_ATTRIBUTION
   static void printTimingAttributionLine(const char *prefix, const char *stage, const ProdigyTimingAttribution& attribution)
   {
      uint64_t totalNs = prodigyTimingAttributionTotalNs(attribution);
      if (totalNs == 0)
      {
         return;
      }

      double providerWaitPct = (double(attribution.providerWaitNs) * 100.0) / double(totalNs);
      double runtimeOwnedPct = (double(attribution.runtimeOwnedNs) * 100.0) / double(totalNs);
      if (stage != nullptr && stage[0] != '\0')
      {
         basics_log(
            "%s stage=%s totalNs=%llu providerWaitNs=%llu runtimeOwnedNs=%llu providerWaitPct=%.3f runtimeOwnedPct=%.3f\n",
            prefix,
            stage,
            (unsigned long long)totalNs,
            (unsigned long long)attribution.providerWaitNs,
            (unsigned long long)attribution.runtimeOwnedNs,
            providerWaitPct,
            runtimeOwnedPct);
         return;
      }

      basics_log(
         "%s totalNs=%llu providerWaitNs=%llu runtimeOwnedNs=%llu providerWaitPct=%.3f runtimeOwnedPct=%.3f\n",
         prefix,
         (unsigned long long)totalNs,
         (unsigned long long)attribution.providerWaitNs,
         (unsigned long long)attribution.runtimeOwnedNs,
         providerWaitPct,
         runtimeOwnedPct);
   }

   static void printCreateClusterTimingSummary(const MothershipClusterCreateTimingSummary& summary)
   {
      printTimingAttributionLine("createCluster timing", "prepareProviderBootstrapArtifacts", summary.prepareProviderBootstrapArtifacts);
      printTimingAttributionLine("createCluster timing", "createSeedMachine", summary.createSeedMachine);
      printTimingAttributionLine("createCluster timing", "bootstrapRemoteSeed", summary.bootstrapRemoteSeed);
      printTimingAttributionLine("createCluster timing", "configureSeedCluster", summary.configureSeedCluster);
      printTimingAttributionLine("createCluster timing", "fetchSeedTopology", summary.fetchSeedTopology);
      printTimingAttributionLine("createCluster timing", "applyAddMachines", summary.applyAddMachines);
      printTimingAttributionLine("createCluster timing", "upsertMachineSchemas", summary.upsertMachineSchemas);
      printTimingAttributionLine("createCluster timing", nullptr, summary.total);
   }
#endif

	bool configureControlTarget(const char *arg, String *failureOut = nullptr)
	{
      String failure;
		if (socket.handleStageArg(arg, &failure))
		{
         if (failureOut)
         {
            failureOut->clear();
         }
			return true;
		}

      if (std::strcmp(arg, "local") == 0)
      {
         if (failure.size() == 0)
         {
            failure.assign("failed to resolve local control target"_ctv);
         }

         if (failureOut)
         {
            *failureOut = failure;
         }

         basics_log("failed to configure local control target: %s\n", failure.c_str());
         return false;
      }

		String clusterName;
		clusterName.setInvariant(arg);

		MothershipProdigyCluster cluster = {};
		MothershipClusterRegistry clusterRegistry = openClusterRegistry();
		if (clusterRegistry.getClusterByIdentity(clusterName, cluster, &failure) == false)
		{
         if (failureOut)
         {
            *failureOut = failure;
         }

			basics_log("unknown control target %s: %s\n", arg, failure.c_str());
			return false;
		}

		if (socket.configureCluster(cluster, &failure) == false)
		{
         if (failureOut)
         {
            *failureOut = failure;
         }

			basics_log("cluster %s has invalid control configuration: %s\n", arg, failure.c_str());
			return false;
		}

      if (failureOut)
      {
         failureOut->clear();
      }

		return true;
	}

   static bool resolveProdigyBundleTargetArchitecture(const char *arg, MachineCpuArchitecture& architecture, String *failure = nullptr)
   {
      architecture = MachineCpuArchitecture::unknown;
      if (failure) failure->clear();

      if (arg == nullptr || arg[0] == '\0')
      {
         if (failure) failure->assign("control target required"_ctv);
         return false;
      }

      if (std::strcmp(arg, "local") == 0)
      {
         architecture = nametagCurrentBuildMachineArchitecture();
         if (prodigyMachineCpuArchitectureSupportedTarget(architecture) == false)
         {
            if (failure) failure->assign("local build architecture unsupported for prodigy bundle selection"_ctv);
            return false;
         }

         return true;
      }

      MothershipClusterRegistry clusterRegistry = openClusterRegistry();
      MothershipProdigyCluster cluster = {};
      String clusterIdentity = {};
      clusterIdentity.assign(arg);
      if (clusterRegistry.getClusterByIdentity(clusterIdentity, cluster, failure) == false)
      {
         return false;
      }

      if (prodigyMachineCpuArchitectureSupportedTarget(cluster.architecture) == false)
      {
         if (failure) failure->snprintf<"cluster architecture must be x86_64, aarch64, or riscv64 for bundle selection: {}"_ctv>(clusterIdentity);
         return false;
      }

      architecture = cluster.architecture;
      return true;
   }

   bool validateClusterProviderCredentialReference(const MothershipProdigyCluster& cluster, String& failure, MothershipProviderCredential *credentialOut = nullptr)
   {
      if (cluster.deploymentMode == MothershipClusterDeploymentMode::local
         || cluster.deploymentMode == MothershipClusterDeploymentMode::test)
      {
         failure.clear();
         return true;
      }

      if (cluster.providerCredentialName.size() == 0)
      {
         failure.assign("remote clusters require providerCredentialName"_ctv);
         return false;
      }

      MothershipProviderCredential credential = {};
      MothershipProviderCredentialRegistry providerCredentialRegistry = openProviderCredentialRegistry();
      if (providerCredentialRegistry.getCredential(cluster.providerCredentialName, credential, &failure) == false)
      {
         if (failure.equal("record not found"_ctv))
         {
            failure.assign("cluster providerCredentialName is not registered"_ctv);
         }

         return false;
      }

      if (credential.provider != cluster.provider)
      {
         failure.assign("cluster providerCredentialName provider does not match cluster provider"_ctv);
         return false;
      }

      if (cluster.propagateProviderCredentialToProdigy && credential.allowPropagateToProdigy == false)
      {
         failure.assign("cluster providerCredentialName does not allow Prodigy propagation"_ctv);
         return false;
      }

      if (credentialOut != nullptr)
      {
         *credentialOut = credential;
      }

      failure.clear();
      return true;
   }

   bool inferClusterMachineSchemaCpuCapabilities(MothershipProdigyCluster& cluster, const MothershipProviderCredential *credential, String& failure)
   {
      failure.clear();

      if (cluster.deploymentMode != MothershipClusterDeploymentMode::remote || cluster.machineSchemas.empty())
      {
         return true;
      }

      ProdigyRuntimeEnvironmentConfig provisioningEnvironment = {};
      if (mothershipBuildClusterProvisioningRuntimeEnvironment(cluster, credential, provisioningEnvironment, &failure) == false)
      {
         return false;
      }

      std::unique_ptr<BrainIaaS> provider = prodigyCreateProviderBrainIaaS(provisioningEnvironment);
      if (provider == nullptr)
      {
         failure.assign("cluster provider does not support schema cpu capability inference"_ctv);
         return false;
      }

      provider->configureRuntimeEnvironment(provisioningEnvironment);
      for (MothershipProdigyClusterMachineSchema& schema : cluster.machineSchemas)
      {
         MachineConfig config = {};
         mothershipBuildMachineConfigFromSchema(schema, config);

         MachineSchemaCpuCapability capability = {};
         String schemaFailure = {};
         if (provider->inferMachineSchemaCpuCapability(config, capability, schemaFailure) == false)
         {
            failure.snprintf<"cluster machineSchema '{}' cpu capability inference failed: {}"_ctv>(
               schema.schema,
               schemaFailure.size() ? schemaFailure : String("unknown failure"_ctv));
            return false;
         }

         schema.cpu = capability;
         if (cluster.architecture != MachineCpuArchitecture::unknown
            && capability.architecture != MachineCpuArchitecture::unknown
            && capability.architecture != cluster.architecture)
         {
            failure.snprintf<"cluster machineSchema '{}' architecture '{}' does not match cluster architecture '{}'"_ctv>(
               schema.schema,
               String(machineCpuArchitectureName(capability.architecture)),
               String(machineCpuArchitectureName(cluster.architecture)));
            return false;
         }
      }

      return true;
   }

   bool destroyCloudClusterMachines(const MothershipProdigyCluster& cluster, const Vector<ClusterMachine>& createdMachines, uint32_t& destroyedCloudMachines, String& failure)
   {
      failure.clear();
      destroyedCloudMachines = 0;

      if (cluster.deploymentMode == MothershipClusterDeploymentMode::local
         || cluster.deploymentMode == MothershipClusterDeploymentMode::test)
      {
         return true;
      }

      MothershipProviderCredential credential = {};
      if (validateClusterProviderCredentialReference(cluster, failure, &credential) == false)
      {
         return false;
      }

      ProdigyRuntimeEnvironmentConfig runtimeEnvironment = {};
      if (mothershipBuildClusterProvisioningRuntimeEnvironment(cluster, &credential, runtimeEnvironment, &failure) == false)
      {
         return false;
      }

      std::unique_ptr<BrainIaaS> provider = prodigyCreateProviderBrainIaaS(runtimeEnvironment);
      if (provider == nullptr)
      {
         failure.assign("failed to construct runtime provider for cluster destroy"_ctv);
         return false;
      }

      provider->configureRuntimeEnvironment(runtimeEnvironment);

      for (const ClusterMachine& createdMachine : createdMachines)
      {
         Machine machine = prodigyBuildMachineSnapshotFromClusterMachine(createdMachine);
         provider->destroyMachine(&machine);
      }

      destroyedCloudMachines = uint32_t(createdMachines.size());
      return true;
   }

   bool stopAndWipeLocalProdigyInstance(String& failure)
   {
      failure.clear();

      String stateDBPath = {};
      resolveProdigyPersistentStateDBPath(stateDBPath);

      String command = {};
      mothershipBuildProdigyStateWipeCommand(stateDBPath, command);
      return prodigyRunLocalShellCommand(command, &failure);
   }

   bool stopAndWipeRemoteProdigyInstance(const MothershipProdigyCluster& cluster, const MothershipProdigyClusterMachine& machine, String& failure)
   {
      failure.clear();

      LIBSSH2_SESSION *session = nullptr;
      int fd = -1;
      if (mothershipConnectSSHSession(machine, session, fd, &failure, &cluster.bootstrapSshKeyPackage, &cluster.bootstrapSshPrivateKeyPath) == false)
      {
         return false;
      }

      String command = {};
      if (cluster.deploymentMode == MothershipClusterDeploymentMode::remote)
      {
         mothershipBuildRemoteProdigyUninstallCommand(cluster, command);
      }
      else
      {
         mothershipBuildProdigyStateWipeCommand(defaultProdigyPersistentStateDBPath(), command);
      }
      bool ok = mothershipRunSSHCommand(session, command, &failure);
      mothershipCloseSSHSession(session, fd);
      return ok;
   }

   class RemoveClusterHooks final : public MothershipClusterRemoveHooks
   {
   public:

      explicit RemoveClusterHooks(Mothership *mothership) : mothership(mothership) {}

      bool stopTestCluster(const MothershipProdigyCluster& cluster, String *failure = nullptr) override
      {
         String localFailure = {};
         bool ok = mothership->stopTestClusterRunner(cluster, localFailure);
         if (failure != nullptr)
         {
            *failure = localFailure;
         }
         return ok;
      }

      bool stopAndWipeLocalMachine(const MothershipProdigyCluster& cluster, String *failure = nullptr) override
      {
         (void)cluster;
         String localFailure = {};
         bool ok = mothership->stopAndWipeLocalProdigyInstance(localFailure);
         if (failure != nullptr)
         {
            *failure = localFailure;
         }
         return ok;
      }

      bool stopAndWipeAdoptedMachine(const MothershipProdigyCluster& cluster, const MothershipProdigyClusterMachine& machine, String *failure = nullptr) override
      {
         String localFailure = {};
         bool ok = mothership->stopAndWipeRemoteProdigyInstance(cluster, machine, localFailure);
         if (failure != nullptr)
         {
            *failure = localFailure;
         }
         return ok;
      }

      bool destroyCreatedCloudMachines(const MothershipProdigyCluster& cluster, const Vector<ClusterMachine>& machines, uint32_t& destroyed, String *failure = nullptr) override
      {
         String localFailure = {};
         bool ok = mothership->destroyCloudClusterMachines(cluster, machines, destroyed, localFailure);
         if (failure != nullptr)
         {
            *failure = localFailure;
         }
         return ok;
      }

   private:

      Mothership *mothership = nullptr;
   };

   bool providerCredentialReferencedByClusters(const String& name, String& failure, String *referencingClusterName = nullptr)
   {
      Vector<MothershipProdigyCluster> clusters;
      MothershipClusterRegistry clusterRegistry = openClusterRegistry();
      if (clusterRegistry.listClusters(clusters, &failure) == false)
      {
         return false;
      }

      for (const MothershipProdigyCluster& cluster : clusters)
      {
         if (cluster.providerCredentialName.equals(name))
         {
            if (referencingClusterName != nullptr)
            {
               *referencingClusterName = cluster.name;
            }

            failure.clear();
            return true;
         }
      }

      if (referencingClusterName != nullptr)
      {
         referencingClusterName->clear();
      }

      failure.clear();
      return false;
   }

   bool startTestClusterRunner(const MothershipProdigyCluster& cluster, String& failure)
   {
      failure.clear();

      if (mothershipClusterUsesTestRunner(cluster) == false)
      {
         failure.assign("cluster is not a test cluster"_ctv);
         return false;
      }

      if (cluster.test.host.mode == MothershipClusterTestHostMode::local)
      {
         String harnessPath = {};
         if (resolveLocalProdigyDevNetnsHarnessPath(harnessPath, &failure) == false)
         {
            return false;
         }

         String localProdigyPath = {};
         if (resolveLocalProdigyExecutablePath(localProdigyPath, &failure) == false)
         {
            return false;
         }

         String startCommand = {};
         mothershipBuildPersistentTestClusterStartCommand(harnessPath, localProdigyPath, cluster, startCommand);
         if (prodigyRunLocalShellCommand(startCommand, &failure) == false)
         {
            return false;
         }

         if (mothershipWaitForLocalTestClusterReady(cluster, &failure) == false)
         {
            String snapshotPath = {};
            String snapshotFailure = {};
            if (mothershipSnapshotLocalTestClusterFailureWorkspace(cluster, snapshotPath, &snapshotFailure))
            {
               failure.append(" preservedWorkspace="_ctv);
               failure.append(snapshotPath);
            }
            else if (snapshotFailure.size() > 0)
            {
               failure.append(" snapshotFailure="_ctv);
               failure.append(snapshotFailure);
            }

            String cleanupFailure = {};
            (void)stopTestClusterRunner(cluster, cleanupFailure);
            return false;
         }

         return true;
      }

      MothershipProdigyClusterMachine remoteHost = {};
      mothershipBuildTestClusterHostMachine(cluster, remoteHost);

      LIBSSH2_SESSION *session = nullptr;
      int fd = -1;
      if (mothershipConnectSSHSession(remoteHost, session, fd, &failure) == false)
      {
         return false;
      }

      bool ok = false;
      do
      {
         if (mothershipUploadRemoteTestHarness(session, cluster, &failure) == false)
         {
            break;
         }

         String remoteHarnessPath = {};
         mothershipResolveTestClusterRunnerRemotePath(cluster, remoteHarnessPath);

         String startCommand = {};
         mothershipBuildPersistentTestClusterStartCommand(remoteHarnessPath, cluster.remoteProdigyPath, cluster, startCommand);
         if (mothershipRunSSHCommand(session, startCommand, &failure) == false)
         {
            break;
         }

         ok = true;
      }
      while (false);

      mothershipCloseSSHSession(session, fd);
      if (ok == false)
      {
         return false;
      }

      if (mothershipWaitForRemoteTestClusterReady(cluster, &failure) == false)
      {
         String cleanupFailure = {};
         (void)stopTestClusterRunner(cluster, cleanupFailure);
         return false;
      }

      return true;
   }

   bool stopTestClusterRunner(const MothershipProdigyCluster& cluster, String& failure)
   {
      failure.clear();

      if (mothershipClusterUsesTestRunner(cluster) == false)
      {
         return true;
      }

      String stopCommand = {};
      mothershipBuildPersistentTestClusterStopCommand(cluster, stopCommand);

      if (cluster.test.host.mode == MothershipClusterTestHostMode::local)
      {
         return prodigyRunLocalShellCommand(stopCommand, &failure);
      }

      MothershipProdigyClusterMachine remoteHost = {};
      mothershipBuildTestClusterHostMachine(cluster, remoteHost);

      LIBSSH2_SESSION *session = nullptr;
      int fd = -1;
      if (mothershipConnectSSHSession(remoteHost, session, fd, &failure) == false)
      {
         return false;
      }

      bool ok = mothershipRunSSHCommand(session, stopCommand, &failure);
      mothershipCloseSSHSession(session, fd);
      return ok;
   }

   static bool resolveClusterUnixControlPath(const MothershipProdigyCluster& cluster, String& controlSocketPath, String *failure = nullptr)
   {
      controlSocketPath.clear();
      if (failure) failure->clear();

      for (const MothershipProdigyClusterControl& control : cluster.controls)
      {
         if (control.kind == MothershipClusterControlKind::unixSocket && control.path.size() > 0)
         {
            controlSocketPath = control.path;
            return true;
         }
      }

      if (failure) failure->assign("cluster has no unixSocket control path"_ctv);
      return false;
   }

   static void assignClusterMachinePreferredLiteralAddresses(ClusterMachine& machine)
   {
      Vector<ClusterMachinePeerAddress> candidates = {};
      prodigyCollectClusterMachinePeerAddresses(machine, candidates);
      prodigyAssignClusterMachineAddressesFromPeerCandidates(machine.addresses, candidates);
   }

   bool buildLocalClusterMachineProbe(const MothershipProdigyCluster& cluster, ClusterMachine& localMachine, String *failure = nullptr)
   {
      localMachine = {};
      if (failure) failure->clear();

      Vector<ClusterMachinePeerAddress> localCandidates = {};
      prodigyCollectLocalPeerAddressCandidates(""_ctv, {}, localCandidates);
      if (localCandidates.empty())
      {
         if (failure) failure->assign("failed to resolve local peer addresses"_ctv);
         return false;
      }

      localMachine.source = ClusterMachineSource::adopted;
      localMachine.backing = ClusterMachineBacking::owned;
      localMachine.kind = MachineConfig::MachineKind::bareMetal;
      localMachine.lifetime = MachineLifetime::owned;
      localMachine.isBrain = true;
      prodigyAssignClusterMachineAddressesFromPeerCandidates(localMachine.addresses, localCandidates);
      localMachine.ownership.mode = ClusterMachineOwnershipMode::wholeMachine;

      ProdigyPersistentStateStore persistentStateStore;
      ProdigyPersistentLocalBrainState localState = {};
      String stateFailure = {};
      if (persistentStateStore.loadLocalBrainState(localState, &stateFailure))
      {
         localMachine.uuid = localState.uuid;
      }
      else if (stateFailure.size() > 0 && stateFailure.equal("record not found"_ctv) == false)
      {
         if (failure)
         {
            *failure = stateFailure;
         }
         return false;
      }

      ClusterTopology normalizedTopology = {};
      normalizedTopology.machines.push_back(localMachine);
      prodigyNormalizeClusterTopologyPeerAddresses(normalizedTopology);
      localMachine = normalizedTopology.machines[0];
      assignClusterMachinePreferredLiteralAddresses(localMachine);
      return true;
   }

   bool findLocalClusterMachineInTopology(const MothershipProdigyCluster& cluster, const ClusterTopology& topology, ClusterMachine& localMachine, String *failure = nullptr)
   {
      localMachine = {};

      ClusterMachine probe = {};
      if (buildLocalClusterMachineProbe(cluster, probe, failure) == false)
      {
         return false;
      }

      for (const ClusterMachine& existingMachine : topology.machines)
      {
         if (existingMachine.sameIdentityAs(probe))
         {
            localMachine = existingMachine;
            if (failure) failure->clear();
            return true;
         }
      }

      localMachine = probe;
      if (failure) failure->clear();
      return false;
   }

   bool bootstrapLocalClusterMachine(const MothershipProdigyCluster& cluster, const ClusterTopology& currentTopology, ClusterMachine& localMachine, String& failure)
   {
      failure.clear();

      String controlSocketPath = {};
      if (resolveClusterUnixControlPath(cluster, controlSocketPath, &failure) == false)
      {
         return false;
      }

      ProdigyRuntimeEnvironmentConfig runtimeEnvironment = {};
      if (mothershipBuildClusterRuntimeEnvironment(cluster, nullptr, runtimeEnvironment, &failure) == false)
      {
         return false;
      }

      ClusterTopology bootTopology = currentTopology;
      bool localAlreadyPresent = false;
      for (const ClusterMachine& machine : bootTopology.machines)
      {
         if (machine.sameIdentityAs(localMachine))
         {
            localAlreadyPresent = true;
            break;
         }
      }

      if (localAlreadyPresent == false)
      {
         bootTopology.machines.push_back(localMachine);
      }
      prodigyNormalizeClusterTopologyPeerAddresses(bootTopology);

      for (const ClusterMachine& machine : bootTopology.machines)
      {
         if (machine.sameIdentityAs(localMachine))
         {
            localMachine = machine;
            break;
         }
      }

      ProdigyPersistentBootState bootState = {};
      bootState.initialTopology = bootTopology;
      bootState.runtimeEnvironment = runtimeEnvironment;
      bootState.bootstrapConfig.nodeRole = ProdigyBootstrapNodeRole::brain;
      bootState.bootstrapConfig.controlSocketPath = controlSocketPath;
      bootState.bootstrapSshUser = cluster.bootstrapSshUser;
      bootState.bootstrapSshKeyPackage = cluster.bootstrapSshKeyPackage;
      bootState.bootstrapSshHostKeyPackage = cluster.bootstrapSshHostKeyPackage;
      bootState.bootstrapSshPrivateKeyPath = cluster.bootstrapSshPrivateKeyPath;
      prodigyRenderClusterTopologyBootstrapPeers(localMachine, bootTopology, bootState.bootstrapConfig.bootstrapPeers);
      if (bootState.bootstrapConfig.bootstrapPeers.empty())
      {
         failure.assign("local cluster join requires at least one existing remote brain peer"_ctv);
         return false;
      }

      return bootstrapLocalProdigy(bootState, &failure);
   }

   bool stopLocalProdigyInstance(String& failure)
   {
      failure.clear();
      return prodigyRunLocalShellCommand("systemctl stop prodigy || true"_ctv, &failure);
   }

   bool reconcileClusterToDesiredSpec(
      const MothershipProdigyCluster& controlCluster,
      MothershipProdigyCluster& desiredCluster,
      AddMachines& request,
      AddMachines& finalState,
      bool& changed,
      String& failure)
   {
      failure.clear();
      changed = false;
      request = {};
      finalState = {};

      if (socket.configureCluster(controlCluster, &failure) == false)
      {
         return false;
      }

      AddMachines currentState = {};
      if (requestAddMachines(AddMachines{}, currentState, failure) == false)
      {
         return false;
      }

      if (currentState.hasTopology == false)
      {
         failure.assign("cluster did not return topology"_ctv);
         return false;
      }

      if (desiredCluster.deploymentMode == MothershipClusterDeploymentMode::test)
      {
         ClusterCreateHooks hooks(this);
         if (mothershipRestartTestClusterToDesiredShape(controlCluster, desiredCluster, currentState.topology, hooks, changed, &failure) == false)
         {
            return false;
         }

         if (changed == false)
         {
            finalState = currentState;
            changed = !(desiredCluster.topology == currentState.topology);
            desiredCluster.topology = currentState.topology;
         }
         else
         {
            finalState = {};
            finalState.hasTopology = true;
            finalState.topology = desiredCluster.topology;
         }
         return true;
      }

      if (mothershipBuildClusterAddMachinesRequest(desiredCluster, currentState.topology, request, &failure) == false)
      {
         return false;
      }

      ClusterMachine localMachine = {};
      bool localMachineKnown = false;
      if (desiredCluster.deploymentMode == MothershipClusterDeploymentMode::local
         && (desiredCluster.includeLocalMachine || mothershipClusterIncludesLocalMachine(controlCluster)))
      {
         localMachineKnown = findLocalClusterMachineInTopology(desiredCluster, currentState.topology, localMachine, &failure);
         if (failure.size() > 0)
         {
            return false;
         }
      }

      if (mothershipBuildDesiredClusterReconcileRequest(
            controlCluster,
            desiredCluster,
            currentState.topology,
            request,
            changed,
            &failure,
            ((desiredCluster.deploymentMode == MothershipClusterDeploymentMode::local
               && (desiredCluster.includeLocalMachine || mothershipClusterIncludesLocalMachine(controlCluster)))
               ? &localMachine
               : nullptr),
            localMachineKnown) == false)
      {
         return false;
      }

      finalState = currentState;
      if (changed == false)
      {
         desiredCluster.topology = currentState.topology;
         return true;
      }

      bool bootstrappedLocalMachine = false;
      if (request.readyMachines.empty() == false)
      {
         ClusterMachine localReadyMachine = request.readyMachines[0];
         if (bootstrapLocalClusterMachine(desiredCluster, currentState.topology, localReadyMachine, failure) == false)
         {
            return false;
         }

         request.readyMachines[0] = localReadyMachine;
         bootstrappedLocalMachine = true;
      }

      if (requestAddMachines(request, finalState, failure) == false)
      {
         if (bootstrappedLocalMachine)
         {
            String cleanupFailure = {};
            if (stopLocalProdigyInstance(cleanupFailure) == false && cleanupFailure.size() > 0)
            {
               failure.append(" | cleanup failure: "_ctv);
               failure.append(cleanupFailure);
            }
         }

         return false;
      }

      if (finalState.hasTopology == false)
      {
         failure.assign("cluster addMachines response missing topology"_ctv);
         if (bootstrappedLocalMachine)
         {
            String cleanupFailure = {};
            if (stopLocalProdigyInstance(cleanupFailure) == false && cleanupFailure.size() > 0)
            {
               failure.append(" | cleanup failure: "_ctv);
               failure.append(cleanupFailure);
            }
         }

         return false;
      }

      if (request.removedMachines.empty() == false && mothershipClusterIncludesLocalMachine(controlCluster) && desiredCluster.includeLocalMachine == false)
      {
         String stopFailure = {};
         if (stopLocalProdigyInstance(stopFailure) == false && stopFailure.size() > 0)
         {
            basics_log("cluster mutation local stop warning=%s\n", stopFailure.c_str());
         }
      }

      desiredCluster.topology = finalState.topology;
      return true;
   }

   bool requestAddMachines(const AddMachines& request, AddMachines& response, String& failure)
   {
	      response = {};
	      basics_log("mothership control request-addMachines adopted=%u ready=%u removed=%u\n",
	         uint32_t(request.adoptedMachines.size()),
            uint32_t(request.readyMachines.size()),
            uint32_t(request.removedMachines.size()));

	      if (socket.connect() != 0)
	      {
	         if (socket.connectFailureDetail().size() > 0)
	         {
	            failure = socket.connectFailureDetail();
	         }
	         else
	         {
	            failure.assign("failed to connect to cluster control socket"_ctv);
	         }
	         return false;
	      }

      String serializedRequest = {};
      AddMachines requestCopy = request;
      BitseryEngine::serialize(serializedRequest, requestCopy);
      Message::construct(socket.wBuffer, MothershipTopic::addMachines, serializedRequest);

      if (socket.send() == false)
      {
         socket.close();
         failure.assign("failed to send addMachines request"_ctv);
         return false;
      }

	      bool ok = mothershipAwaitAddMachinesResponse(
	         [&] (String& serializedResponse, String& receiveFailure) -> bool {
	            Message *responseMessage = socket.recvExpectedTopic(MothershipTopic::addMachines, 512);
	            if (responseMessage == nullptr)
	            {
	               if (socket.ioFailureDetail().size() > 0)
	               {
	                  receiveFailure = socket.ioFailureDetail();
	               }
	               else
	               {
	                  receiveFailure.assign("timed out waiting for addMachines response"_ctv);
	               }
	               return false;
	            }

            uint8_t *responseArgs = responseMessage->args;
            Message::extractToStringView(responseArgs, serializedResponse);
            return true;
         },
         [&] (const Vector<MachineProvisioningProgress>& progress) -> void {
            printMachineProvisioningProgress("addMachines progress", progress);
         },
         response,
         failure
      );

	      socket.close();

	      if (ok == false)
	      {
	         basics_log("mothership control request-addMachines failed failure=%s\n", failure.c_str());
	         if (response.reachabilityResults.empty() == false)
	         {
	            printBrainReachabilityResults("addMachines reachability", response.reachabilityProbeAddress, response.reachabilityResults);
	         }

         return false;
      }

      if (response.reachabilityResults.empty() == false)
      {
         printBrainReachabilityResults("addMachines reachability", response.reachabilityProbeAddress, response.reachabilityResults);
      }

      basics_log("mothership control request-addMachines success hasTopology=%d topologyMachines=%u progress=%u\n",
         int(response.hasTopology),
         (response.hasTopology ? uint32_t(response.topology.machines.size()) : 0u),
         uint32_t(response.provisioningProgress.size()));
#if PRODIGY_ENABLE_CREATE_TIMING_ATTRIBUTION
      if (response.hasTimingAttribution)
      {
         printTimingAttributionLine("mothership control request-addMachines timing", nullptr, response.timingAttribution);
      }
#endif
      return true;
   }

   template <typename Payload>
   bool requestTopicRoundTrip(MothershipTopic topic, const Payload& request, Payload& response, String& failure)
   {
      response = {};
      String topicName = {};
      topicName.assign(prodigyMothershipTopicName(topic));

      if (socket.connect() != 0)
      {
         if (socket.connectFailureDetail().size() > 0)
         {
            failure = socket.connectFailureDetail();
         }
         else
         {
            failure.snprintf<"failed to connect to cluster control socket for {}"_ctv>(topicName);
         }
         return false;
      }

      String serializedRequest = {};
      Payload requestCopy = request;
      BitseryEngine::serialize(serializedRequest, requestCopy);
      Message::construct(socket.wBuffer, topic, serializedRequest);

      if (socket.send() == false)
      {
         socket.close();
         failure.snprintf<"failed to send {} request"_ctv>(topicName);
         return false;
      }

      Message *responseMessage = socket.recvExpectedTopic(topic);
      if (responseMessage == nullptr)
      {
         if (socket.ioFailureDetail().size() > 0)
         {
            failure = socket.ioFailureDetail();
         }
         else
         {
            failure.snprintf<"timed out waiting for {} response"_ctv>(topicName);
         }

         socket.close();
         return false;
      }

      uint8_t *responseArgs = responseMessage->args;
      String serializedResponse = {};
      Message::extractToStringView(responseArgs, serializedResponse);
      if (BitseryEngine::deserializeSafe(serializedResponse, response) == false)
      {
         socket.close();
         failure.snprintf<"invalid {} response payload"_ctv>(topicName);
         return false;
      }

      socket.close();
      if (response.success == false)
      {
         if (response.failure.size() > 0)
         {
            failure = response.failure;
         }
         else
         {
            failure.snprintf<"{} request failed"_ctv>(topicName);
         }

         mothershipMarkFailureNonRetryable(failure);
         return false;
      }

      failure.clear();
      return true;
   }

   bool requestUpsertMachineSchemas(const UpsertMachineSchemas& request, UpsertMachineSchemas& response, String& failure)
   {
      bool ok = requestTopicRoundTrip(MothershipTopic::upsertMachineSchemas, request, response, failure);
#if PRODIGY_ENABLE_CREATE_TIMING_ATTRIBUTION
      if (ok && response.hasTimingAttribution)
      {
         printTimingAttributionLine("mothership control request-upsertMachineSchemas timing", nullptr, response.timingAttribution);
      }
#endif
      return ok;
   }

   bool requestDeltaMachineBudget(const DeltaMachineBudget& request, DeltaMachineBudget& response, String& failure)
   {
      return requestTopicRoundTrip(MothershipTopic::deltaMachineBudget, request, response, failure);
   }

   bool requestDeleteMachineSchema(const DeleteMachineSchema& request, DeleteMachineSchema& response, String& failure)
   {
      return requestTopicRoundTrip(MothershipTopic::deleteMachineSchema, request, response, failure);
   }

   void persistClusterRefreshFailure(MothershipProdigyCluster& cluster, const String& failure)
   {
      cluster.lastRefreshMs = Time::now<TimeResolution::ms>();
      cluster.lastRefreshFailure = failure;

      String persistFailure;
      MothershipClusterRegistry clusterRegistry = openClusterRegistry();
      if (clusterRegistry.upsertCluster(cluster, nullptr, &persistFailure) == false)
      {
         basics_log("failed to persist cluster refresh failure for %s: %s\n", cluster.name.c_str(), persistFailure.c_str());
      }
   }

   void persistClusterRefreshSuccess(MothershipProdigyCluster& cluster)
   {
      cluster.lastRefreshMs = Time::now<TimeResolution::ms>();
      cluster.lastRefreshFailure.clear();

      String persistFailure;
      MothershipClusterRegistry clusterRegistry = openClusterRegistry();
      if (clusterRegistry.upsertCluster(cluster, &cluster, &persistFailure) == false)
      {
         basics_log("failed to persist cluster refresh success for %s: %s\n", cluster.name.c_str(), persistFailure.c_str());
         exit(EXIT_FAILURE);
      }
   }

   void persistClusterTopology(MothershipProdigyCluster& cluster, const ClusterTopology& topology)
   {
      cluster.topology = topology;
      cluster.lastRefreshMs = Time::now<TimeResolution::ms>();
      cluster.lastRefreshFailure.clear();

      String persistFailure;
      MothershipClusterRegistry clusterRegistry = openClusterRegistry();
      if (clusterRegistry.upsertCluster(cluster, &cluster, &persistFailure) == false)
      {
         basics_log("failed to persist cluster topology for %s: %s\n", cluster.name.c_str(), persistFailure.c_str());
         exit(EXIT_FAILURE);
      }
   }

   static uint64_t clusterControlRetryBudgetMs(const MothershipProdigyCluster& cluster)
   {
      for (const ClusterMachine& machine : cluster.topology.machines)
      {
         if (machine.isBrain && machine.source == ClusterMachineSource::created)
         {
            return Time::minsToMs(10);
         }
      }

      return Time::minsToMs(2);
   }

   class ClusterCreateHooks final : public MothershipClusterCreateHooks
   {
   private:

      Mothership *owner = nullptr;

      class SeedProvisioningProgressPrinter final : public BrainIaaSMachineProvisioningProgressSink
      {
      private:

         String prefix;

      public:

         explicit SeedProvisioningProgressPrinter(const String& clusterName)
         {
            prefix.snprintf<"createCluster progress cluster={} seed"_ctv>(clusterName);
         }

         void reportMachineProvisioningProgress(const Vector<MachineProvisioningProgress>& progress) override
         {
            Mothership::printMachineProvisioningProgress(prefix.c_str(), progress);
         }
      };

	      bool waitForClusterRequest(const MothershipProdigyCluster& cluster, auto&& action, String *failure = nullptr)
	      {
	         if (failure) failure->clear();

	         int64_t deadlineMs = Time::now<TimeResolution::ms>() + int64_t(clusterControlRetryBudgetMs(cluster));
	         String lastFailure;
	         uint32_t attempt = 0;

	         for (;;)
	         {
	            attempt += 1;
	            basics_log("mothership control request-attempt cluster=%.*s attempt=%u deadlineMs=%lld\n",
	               int(cluster.name.size()),
	               reinterpret_cast<const char *>(cluster.name.data()),
	               attempt,
	               (long long)deadlineMs);
               int64_t nowMs = Time::now<TimeResolution::ms>();
               int ioTimeoutMs = int(std::max<int64_t>(deadlineMs - nowMs, 1));
               bool configured = owner->socket.configureCluster(cluster, &lastFailure);
               if (configured)
               {
                  owner->socket.setRemoteIOTimeoutMs(ioTimeoutMs);
               }
	            if (configured && action(lastFailure))
	            {
	               owner->socket.close();
	               basics_log("mothership control request-success cluster=%.*s attempt=%u\n",
	                  int(cluster.name.size()),
	                  reinterpret_cast<const char *>(cluster.name.data()),
	                  attempt);
	               if (failure) failure->clear();
	               return true;
	            }

	            basics_log("mothership control request-retry cluster=%.*s attempt=%u failure=%s\n",
	               int(cluster.name.size()),
	               reinterpret_cast<const char *>(cluster.name.data()),
	               attempt,
	               lastFailure.c_str());
	            if (mothershipFailureIsNonRetryable(lastFailure))
	            {
	               mothershipStripNonRetryableFailurePrefix(lastFailure);
	               if (failure) *failure = lastFailure;
	               owner->socket.close();
	               return false;
	            }
	            owner->socket.close();
            if (Time::now<TimeResolution::ms>() >= deadlineMs)
            {
               if (failure)
               {
                  String diagnostics = {};
                  if (owner->socket.collectRemoteProdigyDiagnostics(diagnostics) && diagnostics.size() > 0)
                  {
                     if (lastFailure.size() > 0)
                     {
                        failure->snprintf<"{}\n{}"_ctv>(lastFailure, diagnostics);
                     }
                     else
                     {
                        *failure = diagnostics;
                     }
                  }
                  else
                  {
                     *failure = lastFailure;
                  }
               }

               return false;
            }

            usleep(500'000);
         }
      }

      bool ensureCloudMachinesTaggedLocally(const MothershipProdigyCluster& cluster, const Vector<ClusterMachine>& machines, String *failure = nullptr)
      {
         if (failure) failure->clear();

         bool hasCloudMachines = false;
         for (const ClusterMachine& machine : machines)
         {
            if (machine.backing == ClusterMachineBacking::cloud)
            {
               hasCloudMachines = true;
               break;
            }
         }

         if (hasCloudMachines == false)
         {
            return true;
         }

         MothershipProviderCredential credential = {};
         MothershipProviderCredential *credentialPtr = nullptr;
         String tagFailure = {};
         if (owner->validateClusterProviderCredentialReference(cluster, tagFailure, &credential) == false)
         {
            if (failure) failure->assign(tagFailure);
            return false;
         }

         if (cluster.providerCredentialName.size() > 0)
         {
            credentialPtr = &credential;
         }

         ProdigyRuntimeEnvironmentConfig tagRuntimeEnvironment = {};
         if (mothershipBuildClusterProvisioningRuntimeEnvironment(cluster, credentialPtr, tagRuntimeEnvironment, &tagFailure) == false)
         {
            if (failure) failure->assign(tagFailure);
            return false;
         }

         std::unique_ptr<BrainIaaS> provider = prodigyCreateProviderBrainIaaS(tagRuntimeEnvironment);
         if (provider == nullptr)
         {
            if (failure) failure->assign("failed to construct runtime provider for cloud machine tagging"_ctv);
            return false;
         }

         provider->configureRuntimeEnvironment(tagRuntimeEnvironment);
         provider->configureBootstrapSSHAccess(cluster.bootstrapSshUser, cluster.bootstrapSshKeyPackage, cluster.bootstrapSshHostKeyPackage, cluster.bootstrapSshPrivateKeyPath);
         for (const ClusterMachine& machine : machines)
         {
            if (prodigyEnsureCloudMachineTagged(*provider, cluster.clusterUUID, machine, &tagFailure) == false)
            {
               if (failure) failure->assign(tagFailure);
               return false;
            }
         }

         return true;
      }

   public:

      explicit ClusterCreateHooks(Mothership *mothership) : owner(mothership) {}

      bool startTestCluster(const MothershipProdigyCluster& cluster, String *failure = nullptr) override
      {
         String localFailure = {};
         bool ok = owner->startTestClusterRunner(cluster, localFailure);
         if (failure)
         {
            *failure = localFailure;
         }
         return ok;
      }

      bool stopTestCluster(const MothershipProdigyCluster& cluster, String *failure = nullptr) override
      {
         String localFailure = {};
         bool ok = owner->stopTestClusterRunner(cluster, localFailure);
         if (failure)
         {
            *failure = localFailure;
         }
         return ok;
      }

      bool prepareProviderBootstrapArtifacts(const MothershipProdigyCluster& cluster, ProdigyTimingAttribution *timingAttribution = nullptr, String *failure = nullptr) override
      {
#if PRODIGY_ENABLE_CREATE_TIMING_ATTRIBUTION
         uint64_t stageStartNs = Time::now<TimeResolution::ns>();
         uint64_t providerWaitNs = 0;
#endif
         auto finalizeTiming = [&] () -> void {

#if PRODIGY_ENABLE_CREATE_TIMING_ATTRIBUTION
            if (timingAttribution != nullptr)
            {
               prodigyFinalizeTimingAttribution(Time::now<TimeResolution::ns>() - stageStartNs, providerWaitNs, *timingAttribution);
            }
#else
            (void)timingAttribution;
#endif
         };

         if (cluster.deploymentMode != MothershipClusterDeploymentMode::remote
            || (cluster.provider != MothershipClusterProvider::gcp
               && cluster.provider != MothershipClusterProvider::azure))
         {
            if (failure) failure->clear();
            finalizeTiming();
            return true;
         }

         const MothershipProdigyClusterMachineSchema *standardSchema = nullptr;
         const MothershipProdigyClusterMachineSchema *spotSchema = nullptr;
         for (const MothershipProdigyClusterMachineSchema& schema : cluster.machineSchemas)
         {
            if (schema.budget == 0)
            {
               continue;
            }

            if (schema.lifetime == MachineLifetime::spot)
            {
               if (spotSchema == nullptr)
               {
                  spotSchema = &schema;
               }
            }
            else if (standardSchema == nullptr)
            {
               standardSchema = &schema;
            }
         }

         if (standardSchema == nullptr && spotSchema == nullptr)
         {
            if (failure) failure->clear();
            finalizeTiming();
            return true;
         }

         MothershipProviderCredential credential = {};
         String localFailure = {};
         if (owner->validateClusterProviderCredentialReference(cluster, localFailure, &credential) == false)
         {
            if (failure) failure->assign(localFailure);
            finalizeTiming();
            return false;
         }

         ProdigyRuntimeEnvironmentConfig runtimeEnvironment = {};
         if (mothershipBuildClusterProvisioningRuntimeEnvironment(cluster, &credential, runtimeEnvironment, &localFailure) == false)
         {
            if (failure) failure->assign(localFailure);
            finalizeTiming();
            return false;
         }

         std::unique_ptr<BrainIaaS> provider = prodigyCreateProviderBrainIaaS(runtimeEnvironment);
         if (provider == nullptr)
         {
            if (failure) failure->assign("failed to construct runtime provider for gcp template preparation"_ctv);
            finalizeTiming();
            return false;
         }

         provider->configureRuntimeEnvironment(runtimeEnvironment);
         if (cluster.provider == MothershipClusterProvider::gcp)
         {
            GcpBrainIaaS *gcp = dynamic_cast<GcpBrainIaaS *>(provider.get());
            if (gcp == nullptr)
            {
               if (failure) failure->assign("failed to construct gcp provider for template preparation"_ctv);
               finalizeTiming();
               return false;
            }

            auto ensureTemplate = [&] (const MothershipProdigyClusterMachineSchema& schema, bool spot) -> bool {
               MachineConfig config = {};
               mothershipBuildMachineConfigFromSchema(schema, config);
               const String& templateName = spot ? schema.gcpInstanceTemplateSpot : schema.gcpInstanceTemplate;
#if PRODIGY_ENABLE_CREATE_TIMING_ATTRIBUTION
               uint64_t providerWaitStartNs = Time::now<TimeResolution::ns>();
#endif
               bool ok = gcp->ensureManagedInstanceTemplate(
                  templateName,
                  cluster.gcp.serviceAccountEmail,
                  cluster.gcp.network,
                  cluster.gcp.subnetwork,
                  config,
                  spot,
                  localFailure);
#if PRODIGY_ENABLE_CREATE_TIMING_ATTRIBUTION
               providerWaitNs += (Time::now<TimeResolution::ns>() - providerWaitStartNs);
#endif
               return ok;
            };

            if (standardSchema != nullptr && ensureTemplate(*standardSchema, false) == false)
            {
               if (failure) failure->assign(localFailure);
               finalizeTiming();
               return false;
            }

            if (spotSchema != nullptr && ensureTemplate(*spotSchema, true) == false)
            {
               if (failure) failure->assign(localFailure);
               finalizeTiming();
               return false;
            }
         }
         else if (cluster.provider == MothershipClusterProvider::azure)
         {
            AzureBrainIaaS *azure = dynamic_cast<AzureBrainIaaS *>(provider.get());
            if (azure == nullptr)
            {
               if (failure) failure->assign("failed to construct azure provider for managed identity preparation"_ctv);
               finalizeTiming();
               return false;
            }

#if PRODIGY_ENABLE_CREATE_TIMING_ATTRIBUTION
            uint64_t providerWaitStartNs = Time::now<TimeResolution::ns>();
#endif
            if (azure->ensureManagedClusterIdentity(localFailure) == false)
            {
#if PRODIGY_ENABLE_CREATE_TIMING_ATTRIBUTION
               providerWaitNs += (Time::now<TimeResolution::ns>() - providerWaitStartNs);
#endif
               if (failure) failure->assign(localFailure);
               finalizeTiming();
               return false;
            }
#if PRODIGY_ENABLE_CREATE_TIMING_ATTRIBUTION
            providerWaitNs += (Time::now<TimeResolution::ns>() - providerWaitStartNs);
#endif
         }

         if (failure) failure->clear();
         finalizeTiming();
         return true;
      }

      bool bootstrapLocalSeed(const ProdigyPersistentBootState& bootState, String *failure = nullptr) override
      {
         return bootstrapLocalProdigy(bootState, failure);
      }

      bool createSeedMachine(const MothershipProdigyCluster& cluster, const CreateMachinesInstruction& instruction, ClusterMachine& seedMachine, ProdigyTimingAttribution *timingAttribution = nullptr, String *failure = nullptr) override
      {
         seedMachine = {};
         if (failure) failure->clear();

         MothershipProviderCredential credential = {};
         String localFailure;
         if (owner->validateClusterProviderCredentialReference(cluster, localFailure, &credential) == false)
         {
            if (failure) failure->assign(localFailure);
            return false;
         }

         ProdigyRuntimeEnvironmentConfig runtimeEnvironment = {};
         if (mothershipBuildClusterProvisioningRuntimeEnvironment(cluster, &credential, runtimeEnvironment, &localFailure) == false)
         {
            if (failure) failure->assign(localFailure);
            return false;
         }

         std::unique_ptr<BrainIaaS> provider = prodigyCreateProviderBrainIaaS(runtimeEnvironment);
         if (provider == nullptr)
         {
            if (failure) failure->assign("failed to construct runtime provider for cluster seed provisioning"_ctv);
            return false;
         }

         provider->configureRuntimeEnvironment(runtimeEnvironment);
         SeedProvisioningProgressPrinter progressPrinter(cluster.name);

         if (mothershipProvisionCreatedSeedMachine(cluster, instruction, *provider, seedMachine, &progressPrinter, timingAttribution, &localFailure) == false)
         {
            if (failure) failure->assign(localFailure);
            return false;
         }

         if (failure) failure->clear();
         return true;
      }

      bool destroyCreatedSeedMachine(const MothershipProdigyCluster& cluster, const ClusterMachine& seedMachine, String *failure = nullptr) override
      {
         if (failure) failure->clear();

         if (seedMachine.source != ClusterMachineSource::created
            || seedMachine.backing != ClusterMachineBacking::cloud
            || seedMachine.cloud.cloudID.size() == 0)
         {
            return true;
         }

         MothershipProviderCredential credential = {};
         String localFailure;
         if (owner->validateClusterProviderCredentialReference(cluster, localFailure, &credential) == false)
         {
            if (failure) failure->assign(localFailure);
            return false;
         }

         ProdigyRuntimeEnvironmentConfig runtimeEnvironment = {};
         if (mothershipBuildClusterProvisioningRuntimeEnvironment(cluster, &credential, runtimeEnvironment, &localFailure) == false)
         {
            if (failure) failure->assign(localFailure);
            return false;
         }

         std::unique_ptr<BrainIaaS> provider = prodigyCreateProviderBrainIaaS(runtimeEnvironment);
         if (provider == nullptr)
         {
            if (failure) failure->assign("failed to construct runtime provider for cluster seed destroy"_ctv);
            return false;
         }

         provider->configureRuntimeEnvironment(runtimeEnvironment);
         provider->configureBootstrapSSHAccess(cluster.bootstrapSshUser, cluster.bootstrapSshKeyPackage, cluster.bootstrapSshHostKeyPackage, cluster.bootstrapSshPrivateKeyPath);

         String clusterUUIDTagValue = {};
         prodigyRenderClusterUUIDTagValue(cluster.clusterUUID, clusterUUIDTagValue);

         uint32_t destroyedClusterMachines = 0;
         String destroyClusterFailure = {};
         if (provider->destroyClusterMachines(clusterUUIDTagValue, destroyedClusterMachines, destroyClusterFailure))
         {
            if (failure) failure->clear();
            return true;
         }

         mothershipDestroyCreatedClusterMachine(*provider, seedMachine);
         if (destroyClusterFailure.size() > 0)
         {
            if (failure) failure->assign(destroyClusterFailure);
            return false;
         }

         if (failure) failure->clear();
         return true;
      }

      bool bootstrapRemoteSeed(const MothershipProdigyCluster& cluster, const ClusterMachine& seedMachine, const AddMachines& request, const ClusterTopology& topology, const ProdigyRuntimeEnvironmentConfig& runtimeEnvironment, ProdigyTimingAttribution *timingAttribution = nullptr, String *failure = nullptr) override
      {
#if PRODIGY_ENABLE_CREATE_TIMING_ATTRIBUTION
         uint64_t stageStartNs = Time::now<TimeResolution::ns>();
         uint64_t providerWaitNs = 0;
#endif
         auto finalizeTiming = [&] () -> void {

#if PRODIGY_ENABLE_CREATE_TIMING_ATTRIBUTION
            if (timingAttribution != nullptr)
            {
               prodigyFinalizeTimingAttribution(Time::now<TimeResolution::ns>() - stageStartNs, providerWaitNs, *timingAttribution);
            }
#else
            (void)timingAttribution;
#endif
         };

         if (seedMachine.backing == ClusterMachineBacking::cloud)
         {
            MothershipProviderCredential credential = {};
            MothershipProviderCredential *credentialPtr = nullptr;
            String tagFailure = {};
            if (owner->validateClusterProviderCredentialReference(cluster, tagFailure, &credential) == false)
            {
               if (failure) failure->assign(tagFailure);
               finalizeTiming();
               return false;
            }

            if (cluster.providerCredentialName.size() > 0)
            {
               credentialPtr = &credential;
            }

            ProdigyRuntimeEnvironmentConfig tagRuntimeEnvironment = {};
            if (mothershipBuildClusterProvisioningRuntimeEnvironment(cluster, credentialPtr, tagRuntimeEnvironment, &tagFailure) == false)
            {
               if (failure) failure->assign(tagFailure);
               finalizeTiming();
               return false;
            }

            std::unique_ptr<BrainIaaS> provider = prodigyCreateProviderBrainIaaS(tagRuntimeEnvironment);
            if (provider == nullptr)
            {
               if (failure) failure->assign("failed to construct runtime provider for seed tagging"_ctv);
               finalizeTiming();
               return false;
            }

            provider->configureRuntimeEnvironment(tagRuntimeEnvironment);
            provider->configureBootstrapSSHAccess(cluster.bootstrapSshUser, cluster.bootstrapSshKeyPackage, cluster.bootstrapSshHostKeyPackage, cluster.bootstrapSshPrivateKeyPath);
#if PRODIGY_ENABLE_CREATE_TIMING_ATTRIBUTION
            uint64_t providerWaitStartNs = Time::now<TimeResolution::ns>();
#endif
            if (prodigyEnsureCloudMachineTagged(*provider, cluster.clusterUUID, seedMachine, &tagFailure) == false)
            {
#if PRODIGY_ENABLE_CREATE_TIMING_ATTRIBUTION
               providerWaitNs += (Time::now<TimeResolution::ns>() - providerWaitStartNs);
#endif
               if (failure) failure->assign(tagFailure);
               finalizeTiming();
               return false;
            }
#if PRODIGY_ENABLE_CREATE_TIMING_ATTRIBUTION
            providerWaitNs += (Time::now<TimeResolution::ns>() - providerWaitStartNs);
#endif
         }

         ProdigyRemoteBootstrapPlan plan = {};
         if (prodigyBuildRemoteBootstrapPlan(seedMachine, request, topology, runtimeEnvironment, plan, failure) == false)
         {
            finalizeTiming();
            return false;
         }

         bool ok = prodigyExecuteRemoteBootstrapPlan(plan, failure);
         finalizeTiming();
         return ok;
      }

	      bool configureSeedCluster(const MothershipProdigyCluster& cluster, const BrainConfig& config, String *failure = nullptr) override
	      {
	         String serialized;
	         BrainConfig configCopy = config;
         BitseryEngine::serialize(serialized, configCopy);
         basics_log("mothership control request-configure cluster=%.*s bytes=%zu clusterUUID=%llu datacenter=%u nMachineConfigs=%u nSubnets=%u\n",
            int(cluster.name.size()),
            reinterpret_cast<const char *>(cluster.name.data()),
            size_t(serialized.size()),
            (unsigned long long)config.clusterUUID,
            unsigned(config.datacenterFragment),
            uint32_t(config.configBySlug.size()),
            uint32_t(config.distributableExternalSubnets.size()));

	         return waitForClusterRequest(cluster, [&] (String& requestFailure) -> bool {

	            if (owner->socket.connect() != 0)
	            {
	               if (owner->socket.connectFailureDetail().size() > 0)
	               {
	                  requestFailure = owner->socket.connectFailureDetail();
	               }
	               else
	               {
	                  requestFailure.assign("failed to connect to cluster control socket"_ctv);
	               }
	               return false;
	            }

            Message::construct(owner->socket.wBuffer, MothershipTopic::configure, serialized);
	            if (owner->socket.send() == false)
	            {
	               requestFailure.assign("failed to send configure request"_ctv);
	               return false;
	            }

	            Message *response = owner->socket.recvExpectedTopic(MothershipTopic::configure);
	            if (response == nullptr)
	            {
	               if (owner->socket.ioFailureDetail().size() > 0)
	               {
	                  requestFailure = owner->socket.ioFailureDetail();
	               }
	               else
	               {
	                  requestFailure.assign("timed out waiting for configure acknowledgement"_ctv);
	               }
	               return false;
	            }

	            basics_log("mothership control request-configure success cluster=%.*s responseBytes=%u\n",
	               int(cluster.name.size()),
	               reinterpret_cast<const char *>(cluster.name.data()),
	               unsigned(response->size));

	            return true;
         }, failure);
      }

      bool fetchSeedTopology(const MothershipProdigyCluster& cluster, ClusterTopology& topology, String *failure = nullptr) override
      {
         AddMachines response = {};
         basics_log("mothership control request-fetchTopology cluster=%.*s\n",
            int(cluster.name.size()),
            reinterpret_cast<const char *>(cluster.name.data()));
         if (waitForClusterRequest(cluster, [&] (String& requestFailure) -> bool {
               return owner->requestAddMachines(AddMachines{}, response, requestFailure);
            }, failure) == false)
         {
            return false;
         }

         if (response.hasTopology == false)
         {
            if (failure) failure->assign("cluster did not return topology"_ctv);
            return false;
         }

         topology = response.topology;
         basics_log("mothership control request-fetchTopology success cluster=%.*s topologyMachines=%u\n",
            int(cluster.name.size()),
            reinterpret_cast<const char *>(cluster.name.data()),
            uint32_t(topology.machines.size()));
         if (failure) failure->clear();
         return true;
      }

      bool applyAddMachines(const MothershipProdigyCluster& cluster, const AddMachines& request, ClusterTopology& topology, ProdigyTimingAttribution *timingAttribution = nullptr, String *failure = nullptr) override
      {
#if PRODIGY_ENABLE_CREATE_TIMING_ATTRIBUTION
         uint64_t stageStartNs = Time::now<TimeResolution::ns>();
         uint64_t providerWaitNs = 0;
#endif
         AddMachines taggedRequest = request;
#if PRODIGY_ENABLE_CREATE_TIMING_ATTRIBUTION
         uint64_t providerWaitStartNs = Time::now<TimeResolution::ns>();
#endif
         if (ensureCloudMachinesTaggedLocally(cluster, taggedRequest.adoptedMachines, failure) == false)
         {
#if PRODIGY_ENABLE_CREATE_TIMING_ATTRIBUTION
            providerWaitNs += (Time::now<TimeResolution::ns>() - providerWaitStartNs);
            if (timingAttribution != nullptr)
            {
               prodigyFinalizeTimingAttribution(Time::now<TimeResolution::ns>() - stageStartNs, providerWaitNs, *timingAttribution);
            }
#else
            (void)timingAttribution;
#endif
            return false;
         }
#if PRODIGY_ENABLE_CREATE_TIMING_ATTRIBUTION
         providerWaitNs += (Time::now<TimeResolution::ns>() - providerWaitStartNs);
#endif

         AddMachines response = {};
         basics_log("mothership control request-applyAddMachines cluster=%.*s adopted=%u ready=%u removed=%u\n",
            int(cluster.name.size()),
            reinterpret_cast<const char *>(cluster.name.data()),
            uint32_t(taggedRequest.adoptedMachines.size()),
            uint32_t(taggedRequest.readyMachines.size()),
            uint32_t(taggedRequest.removedMachines.size()));
         if (waitForClusterRequest(cluster, [&] (String& requestFailure) -> bool {
               return owner->requestAddMachines(taggedRequest, response, requestFailure);
            }, failure) == false)
         {
#if PRODIGY_ENABLE_CREATE_TIMING_ATTRIBUTION
            if (timingAttribution != nullptr)
            {
               prodigyFinalizeTimingAttribution(Time::now<TimeResolution::ns>() - stageStartNs, providerWaitNs, *timingAttribution);
            }
#endif
            return false;
         }

         if (response.hasTopology == false)
         {
            if (failure) failure->assign("cluster addMachines response missing topology"_ctv);
            return false;
         }

         topology = response.topology;
         basics_log("mothership control request-applyAddMachines success cluster=%.*s topologyMachines=%u\n",
            int(cluster.name.size()),
            reinterpret_cast<const char *>(cluster.name.data()),
            uint32_t(topology.machines.size()));
#if PRODIGY_ENABLE_CREATE_TIMING_ATTRIBUTION
         if (response.hasTimingAttribution)
         {
            providerWaitNs += response.timingAttribution.providerWaitNs;
         }
         if (timingAttribution != nullptr)
         {
            prodigyFinalizeTimingAttribution(Time::now<TimeResolution::ns>() - stageStartNs, providerWaitNs, *timingAttribution);
         }
#else
         (void)timingAttribution;
#endif
         if (failure) failure->clear();
         return true;
      }

      bool upsertMachineSchemas(const MothershipProdigyCluster& cluster, const Vector<ProdigyManagedMachineSchemaPatch>& patches, ClusterTopology& topology, ProdigyTimingAttribution *timingAttribution = nullptr, String *failure = nullptr) override
      {
#if PRODIGY_ENABLE_CREATE_TIMING_ATTRIBUTION
         uint64_t stageStartNs = Time::now<TimeResolution::ns>();
#endif
         UpsertMachineSchemas request = {};
         request.patches = patches;

         UpsertMachineSchemas response = {};
         basics_log("mothership control request-upsertMachineSchemas cluster=%.*s patches=%u\n",
            int(cluster.name.size()),
            reinterpret_cast<const char *>(cluster.name.data()),
            uint32_t(patches.size()));
         if (waitForClusterRequest(cluster, [&] (String& requestFailure) -> bool {
               return owner->requestUpsertMachineSchemas(request, response, requestFailure);
            }, failure) == false)
         {
#if PRODIGY_ENABLE_CREATE_TIMING_ATTRIBUTION
            if (timingAttribution != nullptr)
            {
               prodigyFinalizeTimingAttribution(Time::now<TimeResolution::ns>() - stageStartNs, 0, *timingAttribution);
            }
#else
            (void)timingAttribution;
#endif
            return false;
         }

         if (response.hasTopology == false)
         {
            if (failure) failure->assign("cluster upsertMachineSchemas response missing topology"_ctv);
            return false;
         }

         topology = response.topology;
         basics_log("mothership control request-upsertMachineSchemas success cluster=%.*s topologyMachines=%u\n",
            int(cluster.name.size()),
            reinterpret_cast<const char *>(cluster.name.data()),
            uint32_t(topology.machines.size()));
#if PRODIGY_ENABLE_CREATE_TIMING_ATTRIBUTION
         uint64_t providerWaitNs = 0;
         if (response.hasTimingAttribution)
         {
            providerWaitNs = response.timingAttribution.providerWaitNs;
         }
         if (timingAttribution != nullptr)
         {
            prodigyFinalizeTimingAttribution(Time::now<TimeResolution::ns>() - stageStartNs, providerWaitNs, *timingAttribution);
         }
#else
         (void)timingAttribution;
#endif
         if (failure) failure->clear();
         return true;
      }
   };

   bool tryLoadStoredClusterTarget(const char *arg, MothershipProdigyCluster& cluster, String *failure = nullptr)
   {
      cluster = {};
      if (failure)
      {
         failure->clear();
      }

      if (arg == nullptr || std::strcmp(arg, "local") == 0)
      {
         return false;
      }

      String clusterIdentity = {};
      clusterIdentity.assign(arg);
      if (clusterIdentity.size() == 0)
      {
         return false;
      }

      MothershipClusterRegistry clusterRegistry = openClusterRegistry();
      if (clusterRegistry.getClusterByIdentity(clusterIdentity, cluster, failure) == false)
      {
         return false;
      }

      if (failure)
      {
         failure->clear();
      }

      return true;
   }

   void runClusterReport(int argc, char *argv[])
   {
      if (argc < 1)
      {
         basics_log("too few arguments. ex: clusterReport [target: local|clusterName|clusterUUID]\n");
         exit(EXIT_FAILURE);
      }

      MothershipProdigyCluster storedCluster = {};
      bool hasStoredClusterTarget = tryLoadStoredClusterTarget(argv[0], storedCluster);

      String targetFailure = {};
      if (configureControlTarget(argv[0], &targetFailure) == false)
      {
         if (hasStoredClusterTarget)
         {
            if (targetFailure.size() == 0)
            {
               targetFailure.assign("failed to configure cluster control target"_ctv);
            }

            persistClusterRefreshFailure(storedCluster, targetFailure);
         }

         exit(EXIT_FAILURE);
      }

      auto failClusterReport = [&] (String failure) -> void {
         socket.close();

         if (hasStoredClusterTarget)
         {
            String persistedFailure = failure;
            if (persistedFailure.size() == 0)
            {
               persistedFailure.assign("clusterReport failed"_ctv);
            }

            persistClusterRefreshFailure(storedCluster, persistedFailure);
         }

         if (failure.size() > 0)
         {
            String printedFailure = failure;
            basics_log("clusterReport failed: %s\n", printedFailure.c_str());
         }

         exit(EXIT_FAILURE);
      };

      if (socket.connect() != 0)
      {
         String failure = socket.connectFailureDetail();
         if (failure.size() == 0)
         {
            failure.assign("failed to connect to cluster control socket"_ctv);
         }

         failClusterReport(failure);
      }

      Message::construct(socket.wBuffer, MothershipTopic::pullClusterReport);
      if (socket.send() == false)
      {
         String failure = socket.ioFailureDetail();
         if (failure.size() == 0)
         {
            failure.assign("failed to send cluster report request"_ctv);
         }

         failClusterReport(failure);
      }

      Message *response = socket.recvExpectedTopic(MothershipTopic::pullClusterReport, 1024);
      if (response == nullptr)
      {
         String failure = socket.ioFailureDetail();
         if (failure.size() == 0)
         {
            failure.assign("timed out waiting for cluster report"_ctv);
         }

         failClusterReport(failure);
      }

      if (MothershipTopic(response->topic) != MothershipTopic::pullClusterReport)
      {
         String failure = {};
         failure.snprintf<"unexpected response topic {}"_ctv>(uint32_t(response->topic));
         failClusterReport(failure);
      }

      uint8_t *args = response->args;

      String serializedReport = {};
      Message::extractToStringView(args, serializedReport);

      ClusterStatusReport report = {};
      if (BitseryEngine::deserializeSafe(serializedReport, report) == false)
      {
         failClusterReport("invalid report payload"_ctv);
      }

      if (hasStoredClusterTarget)
      {
         if (report.hasTopology)
         {
            persistClusterTopology(storedCluster, report.topology);
         }
         else
         {
            persistClusterRefreshSuccess(storedCluster);
         }
      }

      String stringified = {};
      report.stringify(stringified);

      socket.close();

      if (stringified.size() > 0)
      {
         std::fwrite(stringified.c_str(), 1, stringified.size(), stdout);
      }
      exit(EXIT_SUCCESS);
   }

   bool loadClusterForScopedMutation(const char *operationName, const String& clusterIdentity, MothershipProdigyCluster& controlCluster, String& failure)
   {
      failure.clear();
      controlCluster = {};
      String operation = {};
      operation.assign(operationName);

      if (clusterIdentity.size() == 0)
      {
         failure.snprintf<"{}.identity required"_ctv>(operation);
         return false;
      }

      MothershipClusterRegistry clusterRegistry = openClusterRegistry();
      if (clusterRegistry.getClusterByIdentity(clusterIdentity, controlCluster, &failure) == false)
      {
         return false;
      }

      return true;
   }

   bool applyAndPersistScopedClusterMutation(
      const MothershipProdigyCluster& controlCluster,
      MothershipProdigyCluster& desiredCluster,
      AddMachines& request,
      bool& changed,
      String& failure)
   {
      failure.clear();
      request = {};
      changed = false;

      if (desiredCluster.deploymentMode == MothershipClusterDeploymentMode::test)
      {
         // Test-cluster controls are synthesized from workspaceRoot by validation.
         // Stored test cluster records already carry that synthesized unix socket, so
         // clear it before revalidating an update to avoid treating managed controls
         // as user-specified input.
         desiredCluster.controls.clear();
      }

      MothershipProdigyCluster normalizedDesiredCluster = {};
      {
         MothershipClusterRegistry clusterRegistry = openClusterRegistry();
         if (clusterRegistry.validateClusterForUpsert(desiredCluster, normalizedDesiredCluster, &failure) == false)
         {
            return false;
         }
      }

      AddMachines finalState = {};
      if (reconcileClusterToDesiredSpec(controlCluster, normalizedDesiredCluster, request, finalState, changed, failure) == false)
      {
         MothershipProdigyCluster failedCluster = controlCluster;
         persistClusterRefreshFailure(failedCluster, failure);
         return false;
      }

      normalizedDesiredCluster.lastRefreshMs = Time::now<TimeResolution::ms>();
      normalizedDesiredCluster.lastRefreshFailure.clear();

      {
         MothershipClusterRegistry clusterRegistry = openClusterRegistry();
         if (clusterRegistry.upsertCluster(normalizedDesiredCluster, &normalizedDesiredCluster, &failure) == false)
         {
            return false;
         }
      }

      desiredCluster = normalizedDesiredCluster;
      return true;
   }

   void runSetLocalClusterMembership(int argc, char *argv[])
   {
      if (argc < 2)
      {
         basics_log("too few arguments. ex: setLocalClusterMembership [name|clusterUUID] [json]\n");
         exit(EXIT_FAILURE);
      }

      String clusterIdentity = {};
      clusterIdentity.assign(argv[0]);

      String failure = {};
      MothershipProdigyCluster controlCluster = {};
      if (loadClusterForScopedMutation("setLocalClusterMembership", clusterIdentity, controlCluster, failure) == false)
      {
         basics_log("setLocalClusterMembership success=0 identity=%s failure=%s\n", clusterIdentity.c_str(), failure.c_str());
         exit(EXIT_FAILURE);
      }

      if (controlCluster.deploymentMode != MothershipClusterDeploymentMode::local)
      {
         basics_log("setLocalClusterMembership success=0 identity=%s failure=setLocalClusterMembership requires deploymentMode=local\n", clusterIdentity.c_str());
         exit(EXIT_FAILURE);
      }

      String json = {};
      json.append(argv[1]);
      json.need(simdjson::SIMDJSON_PADDING);

      simdjson::dom::parser parser;
      simdjson::dom::element doc;
      if (parser.parse(json.data(), json.size()).get(doc))
      {
         basics_log("invalid json for setLocalClusterMembership\n");
         exit(EXIT_FAILURE);
      }

      if (doc.type() != simdjson::dom::element_type::OBJECT)
      {
         basics_log("setLocalClusterMembership requires object json\n");
         exit(EXIT_FAILURE);
      }

      MothershipProdigyCluster desiredCluster = controlCluster;
      bool sawIncludeLocalMachine = false;
      bool sawMachines = false;
      for (auto field : doc.get_object())
      {
         String key = {};
         key.setInvariant(field.key.data(), field.key.size());

         if (key.equal("includeLocalMachine"_ctv))
         {
            if (field.value.type() != simdjson::dom::element_type::BOOL)
            {
               basics_log("setLocalClusterMembership.includeLocalMachine requires bool\n");
               exit(EXIT_FAILURE);
            }

            bool value = false;
            if (field.value.get(value) != simdjson::SUCCESS)
            {
               basics_log("setLocalClusterMembership.includeLocalMachine invalid\n");
               exit(EXIT_FAILURE);
            }

            desiredCluster.includeLocalMachine = value;
            sawIncludeLocalMachine = true;
         }
         else if (key.equal("machines"_ctv))
         {
            if (parseMothershipClusterMachinesJSON(field.value, desiredCluster.machines, "setLocalClusterMembership.machines") == false)
            {
               exit(EXIT_FAILURE);
            }

            sawMachines = true;
         }
         else
         {
            basics_log("setLocalClusterMembership invalid field\n");
            exit(EXIT_FAILURE);
         }
      }

      if (sawIncludeLocalMachine == false)
      {
         basics_log("setLocalClusterMembership.includeLocalMachine required\n");
         exit(EXIT_FAILURE);
      }

      if (sawMachines == false)
      {
         basics_log("setLocalClusterMembership.machines required\n");
         exit(EXIT_FAILURE);
      }

      AddMachines request = {};
      bool changed = false;
      if (applyAndPersistScopedClusterMutation(controlCluster, desiredCluster, request, changed, failure) == false)
      {
         basics_log("setLocalClusterMembership success=0 name=%s failure=%s\n", controlCluster.name.c_str(), failure.c_str());
         exit(EXIT_FAILURE);
      }

      basics_log("setLocalClusterMembership success=1 name=%s changed=%d adoptedAdded=%u readyAdded=%u removed=%u topologyVersion=%llu topologyMachines=%u\n",
         desiredCluster.name.c_str(),
         int(changed),
         unsigned(request.adoptedMachines.size()),
         unsigned(request.readyMachines.size()),
         unsigned(request.removedMachines.size()),
         (unsigned long long)desiredCluster.topology.version,
         unsigned(desiredCluster.topology.machines.size()));
      printManagedCluster(desiredCluster);
   }

   void runSetTestClusterMachineCount(int argc, char *argv[])
   {
      if (argc < 2)
      {
         basics_log("too few arguments. ex: setTestClusterMachineCount [name|clusterUUID] [json]\n");
         exit(EXIT_FAILURE);
      }

      String clusterIdentity = {};
      clusterIdentity.assign(argv[0]);

      String failure = {};
      MothershipProdigyCluster controlCluster = {};
      if (loadClusterForScopedMutation("setTestClusterMachineCount", clusterIdentity, controlCluster, failure) == false)
      {
         basics_log("setTestClusterMachineCount success=0 identity=%s failure=%s\n", clusterIdentity.c_str(), failure.c_str());
         exit(EXIT_FAILURE);
      }

      if (controlCluster.deploymentMode != MothershipClusterDeploymentMode::test)
      {
         basics_log("setTestClusterMachineCount success=0 identity=%s failure=setTestClusterMachineCount requires deploymentMode=test\n", clusterIdentity.c_str());
         exit(EXIT_FAILURE);
      }

      String json = {};
      json.append(argv[1]);
      json.need(simdjson::SIMDJSON_PADDING);

      simdjson::dom::parser parser;
      simdjson::dom::element doc;
      if (parser.parse(json.data(), json.size()).get(doc))
      {
         basics_log("invalid json for setTestClusterMachineCount\n");
         exit(EXIT_FAILURE);
      }

      if (doc.type() != simdjson::dom::element_type::OBJECT)
      {
         basics_log("setTestClusterMachineCount requires object json\n");
         exit(EXIT_FAILURE);
      }

      MothershipProdigyCluster desiredCluster = controlCluster;
      bool sawMachineCount = false;
      for (auto field : doc.get_object())
      {
         String key = {};
         key.setInvariant(field.key.data(), field.key.size());
         if (key.equal("machineCount"_ctv) == false)
         {
            basics_log("setTestClusterMachineCount invalid field\n");
            exit(EXIT_FAILURE);
         }

         uint64_t machineCount = 0;
         if (field.value.get(machineCount) != simdjson::SUCCESS || machineCount > UINT32_MAX)
         {
            basics_log("setTestClusterMachineCount.machineCount invalid\n");
            exit(EXIT_FAILURE);
         }

         desiredCluster.test.machineCount = uint32_t(machineCount);
         sawMachineCount = true;
      }

      if (sawMachineCount == false)
      {
         basics_log("setTestClusterMachineCount.machineCount required\n");
         exit(EXIT_FAILURE);
      }

      AddMachines request = {};
      bool changed = false;
      if (applyAndPersistScopedClusterMutation(controlCluster, desiredCluster, request, changed, failure) == false)
      {
         basics_log("setTestClusterMachineCount success=0 name=%s failure=%s\n", controlCluster.name.c_str(), failure.c_str());
         exit(EXIT_FAILURE);
      }

      basics_log("setTestClusterMachineCount success=1 name=%s changed=%d machineCount=%u topologyVersion=%llu topologyMachines=%u\n",
         desiredCluster.name.c_str(),
         int(changed),
         unsigned(desiredCluster.test.machineCount),
         (unsigned long long)desiredCluster.topology.version,
         unsigned(desiredCluster.topology.machines.size()));
      printManagedCluster(desiredCluster);
   }

   bool loadRemoteClusterMutationTarget(const char *operationName, const char *identityArg, MothershipProdigyCluster& controlCluster, String& failure)
   {
      failure.clear();
      controlCluster = {};
      String operation = {};
      operation.assign(operationName);

      String identity = {};
      if (identityArg != nullptr)
      {
         identity.assign(identityArg);
      }

      if (identity.size() == 0)
      {
         failure.snprintf<"{}.identity required"_ctv>(operation);
         return false;
      }

      MothershipClusterRegistry clusterRegistry = openClusterRegistry();
      if (clusterRegistry.getClusterByIdentity(identity, controlCluster, &failure) == false)
      {
         return false;
      }

      if (controlCluster.deploymentMode != MothershipClusterDeploymentMode::remote)
      {
         failure.snprintf<"{} only supports remote clusters"_ctv>(operation);
         return false;
      }

      return true;
   }

   void runUpsertMachineSchemas(int argc, char *argv[])
   {
      if (argc < 2)
      {
         basics_log("too few arguments. ex: upsertMachineSchemas [name|clusterUUID] [json object|array]\n");
         exit(EXIT_FAILURE);
      }

      String failure = {};
      MothershipProdigyCluster controlCluster = {};
      if (loadRemoteClusterMutationTarget("upsertMachineSchemas", argv[0], controlCluster, failure) == false)
      {
         basics_log("upsertMachineSchemas success=0 identity=%s failure=%s\n", argv[0], failure.c_str());
         exit(EXIT_FAILURE);
      }

      String json = {};
      json.append(argv[1]);
      json.need(simdjson::SIMDJSON_PADDING);

      simdjson::dom::parser parser;
      simdjson::dom::element doc;
      if (parser.parse(json.data(), json.size()).get(doc))
      {
         basics_log("invalid json for upsertMachineSchemas\n");
         exit(EXIT_FAILURE);
      }

      Vector<MothershipProdigyClusterMachineSchemaPatch> patches = {};
      if (doc.type() == simdjson::dom::element_type::OBJECT)
      {
         MothershipProdigyClusterMachineSchemaPatch patch = {};
         if (parseClusterMachineSchemaPatchJSON(doc, patch, "upsertMachineSchemas") == false)
         {
            exit(EXIT_FAILURE);
         }
         patches.push_back(patch);
      }
      else if (doc.type() == simdjson::dom::element_type::ARRAY)
      {
         for (auto item : doc.get_array())
         {
            MothershipProdigyClusterMachineSchemaPatch patch = {};
            if (parseClusterMachineSchemaPatchJSON(item, patch, "upsertMachineSchemas[]") == false)
            {
               exit(EXIT_FAILURE);
            }
            patches.push_back(patch);
         }
      }
      else
      {
         basics_log("upsertMachineSchemas requires object or array json\n");
         exit(EXIT_FAILURE);
      }

      if (patches.empty())
      {
         basics_log("upsertMachineSchemas requires at least one schema patch\n");
         exit(EXIT_FAILURE);
      }

      MothershipProdigyCluster desiredCluster = controlCluster;
      uint32_t createdCount = 0;
      for (const MothershipProdigyClusterMachineSchemaPatch& patch : patches)
      {
         bool created = false;
         if (mothershipUpsertClusterMachineSchema(desiredCluster.machineSchemas, patch, &created, &failure) == false)
         {
            basics_log("upsertMachineSchemas success=0 name=%s failure=%s\n", controlCluster.name.c_str(), failure.c_str());
            exit(EXIT_FAILURE);
         }

         if (created)
         {
            createdCount += 1;
         }
      }

      MothershipProviderCredential referencedCredential = {};
      if (validateClusterProviderCredentialReference(desiredCluster, failure, &referencedCredential) == false
         || inferClusterMachineSchemaCpuCapabilities(desiredCluster, &referencedCredential, failure) == false)
      {
         basics_log("upsertMachineSchemas success=0 name=%s failure=%s\n", controlCluster.name.c_str(), failure.c_str());
         exit(EXIT_FAILURE);
      }

      bool changed = mothershipEqualClusterMachineSchemas(controlCluster.machineSchemas, desiredCluster.machineSchemas) == false;

      Vector<ProdigyManagedMachineSchemaPatch> requestPatches = {};
      requestPatches.reserve(patches.size());
      for (const MothershipProdigyClusterMachineSchemaPatch& patch : patches)
      {
         ProdigyManagedMachineSchemaPatch requestPatch = {};
         convertClusterMachineSchemaPatch(patch, requestPatch);
         for (const MothershipProdigyClusterMachineSchema& desiredSchema : desiredCluster.machineSchemas)
         {
            if (desiredSchema.schema == requestPatch.schema)
            {
               requestPatch.hasCpu = true;
               requestPatch.cpu = desiredSchema.cpu;
               break;
            }
         }
         requestPatches.push_back(std::move(requestPatch));
      }

      if (socket.configureCluster(controlCluster, &failure) == false)
      {
         basics_log("upsertMachineSchemas success=0 name=%s failure=%s\n", controlCluster.name.c_str(), failure.c_str());
         exit(EXIT_FAILURE);
      }

      UpsertMachineSchemas request = {};
      request.patches = requestPatches;
      UpsertMachineSchemas response = {};
      if (requestUpsertMachineSchemas(request, response, failure) == false)
      {
         MothershipProdigyCluster refreshCluster = controlCluster;
         persistClusterRefreshFailure(refreshCluster, failure);
         basics_log("upsertMachineSchemas success=0 name=%s failure=%s\n", controlCluster.name.c_str(), failure.c_str());
         exit(EXIT_FAILURE);
      }

      desiredCluster.topology = response.topology;
      desiredCluster.lastRefreshMs = Time::now<TimeResolution::ms>();
      desiredCluster.lastRefreshFailure.clear();

      {
         MothershipClusterRegistry clusterRegistry = openClusterRegistry();
         if (clusterRegistry.upsertCluster(desiredCluster, &desiredCluster, &failure) == false)
         {
            basics_log("upsertMachineSchemas success=0 name=%s failure=%s\n", controlCluster.name.c_str(), failure.c_str());
            exit(EXIT_FAILURE);
         }
      }

      basics_log("upsertMachineSchemas success=1 name=%s upserted=%u created=%u changed=%d topologyVersion=%llu topologyMachines=%u\n",
         desiredCluster.name.c_str(),
         unsigned(patches.size()),
         unsigned(createdCount),
         int(changed),
         (unsigned long long)desiredCluster.topology.version,
         unsigned(desiredCluster.topology.machines.size()));
      printManagedCluster(desiredCluster);
   }

   void runDeltaMachineBudget(int argc, char *argv[])
   {
      if (argc < 2)
      {
         basics_log("too few arguments. ex: deltaMachineBudget [name|clusterUUID] [{\"schema\":\"...\",\"delta\":-1}]\n");
         exit(EXIT_FAILURE);
      }

      String failure = {};
      MothershipProdigyCluster controlCluster = {};
      if (loadRemoteClusterMutationTarget("deltaMachineBudget", argv[0], controlCluster, failure) == false)
      {
         basics_log("deltaMachineBudget success=0 identity=%s failure=%s\n", argv[0], failure.c_str());
         exit(EXIT_FAILURE);
      }

      String json = {};
      json.append(argv[1]);
      json.need(simdjson::SIMDJSON_PADDING);

      simdjson::dom::parser parser;
      simdjson::dom::element doc;
      if (parser.parse(json.data(), json.size()).get(doc))
      {
         basics_log("invalid json for deltaMachineBudget\n");
         exit(EXIT_FAILURE);
      }

      if (doc.type() != simdjson::dom::element_type::OBJECT)
      {
         basics_log("deltaMachineBudget requires object json\n");
         exit(EXIT_FAILURE);
      }

      String schema = {};
      int64_t delta = 0;
      bool sawSchema = false;
      bool sawDelta = false;
      for (auto field : doc.get_object())
      {
         String key = {};
         key.setInvariant(field.key.data(), field.key.size());

         if (key.equal("schema"_ctv))
         {
            if (field.value.type() != simdjson::dom::element_type::STRING)
            {
               basics_log("deltaMachineBudget.schema requires string\n");
               exit(EXIT_FAILURE);
            }

            schema.assign(field.value.get_c_str());
            sawSchema = true;
         }
         else if (key.equal("delta"_ctv))
         {
            if (field.value.type() != simdjson::dom::element_type::INT64 || field.value.get(delta) != simdjson::SUCCESS)
            {
               basics_log("deltaMachineBudget.delta invalid\n");
               exit(EXIT_FAILURE);
            }

            sawDelta = true;
         }
         else
         {
            basics_log("deltaMachineBudget invalid field\n");
            exit(EXIT_FAILURE);
         }
      }

      if (sawSchema == false || sawDelta == false)
      {
         basics_log("deltaMachineBudget requires schema and delta\n");
         exit(EXIT_FAILURE);
      }

      MothershipProdigyCluster desiredCluster = controlCluster;
      uint32_t finalBudget = 0;
      if (mothershipDeltaClusterMachineBudget(desiredCluster.machineSchemas, schema, delta, &finalBudget, &failure) == false)
      {
         basics_log("deltaMachineBudget success=0 name=%s failure=%s\n", controlCluster.name.c_str(), failure.c_str());
         exit(EXIT_FAILURE);
      }

      MothershipProviderCredential referencedCredential = {};
      if (validateClusterProviderCredentialReference(desiredCluster, failure, &referencedCredential) == false
         || inferClusterMachineSchemaCpuCapabilities(desiredCluster, &referencedCredential, failure) == false)
      {
         basics_log("deltaMachineBudget success=0 name=%s failure=%s\n", controlCluster.name.c_str(), failure.c_str());
         exit(EXIT_FAILURE);
      }

      bool changed = mothershipEqualClusterMachineSchemas(controlCluster.machineSchemas, desiredCluster.machineSchemas) == false;

      if (socket.configureCluster(controlCluster, &failure) == false)
      {
         basics_log("deltaMachineBudget success=0 name=%s failure=%s\n", controlCluster.name.c_str(), failure.c_str());
         exit(EXIT_FAILURE);
      }

      DeltaMachineBudget request = {};
      request.schema = schema;
      request.delta = delta;

      DeltaMachineBudget response = {};
      if (requestDeltaMachineBudget(request, response, failure) == false)
      {
         MothershipProdigyCluster refreshCluster = controlCluster;
         persistClusterRefreshFailure(refreshCluster, failure);
         basics_log("deltaMachineBudget success=0 name=%s failure=%s\n", controlCluster.name.c_str(), failure.c_str());
         exit(EXIT_FAILURE);
      }

      desiredCluster.topology = response.topology;
      desiredCluster.lastRefreshMs = Time::now<TimeResolution::ms>();
      desiredCluster.lastRefreshFailure.clear();

      {
         MothershipClusterRegistry clusterRegistry = openClusterRegistry();
         if (clusterRegistry.upsertCluster(desiredCluster, &desiredCluster, &failure) == false)
         {
            basics_log("deltaMachineBudget success=0 name=%s failure=%s\n", controlCluster.name.c_str(), failure.c_str());
            exit(EXIT_FAILURE);
         }
      }

      basics_log("deltaMachineBudget success=1 name=%s schema=%s budget=%u changed=%d topologyVersion=%llu topologyMachines=%u\n",
         desiredCluster.name.c_str(),
         schema.c_str(),
         unsigned(finalBudget),
         int(changed),
         (unsigned long long)desiredCluster.topology.version,
         unsigned(desiredCluster.topology.machines.size()));
      printManagedCluster(desiredCluster);
   }

   void runDeleteMachineSchema(int argc, char *argv[])
   {
      if (argc < 2)
      {
         basics_log("too few arguments. ex: deleteMachineSchema [name|clusterUUID] [schema]\n");
         exit(EXIT_FAILURE);
      }

      String failure = {};
      MothershipProdigyCluster controlCluster = {};
      if (loadRemoteClusterMutationTarget("deleteMachineSchema", argv[0], controlCluster, failure) == false)
      {
         basics_log("deleteMachineSchema success=0 identity=%s failure=%s\n", argv[0], failure.c_str());
         exit(EXIT_FAILURE);
      }

      String schema = {};
      schema.assign(argv[1]);
      if (schema.size() == 0)
      {
         basics_log("deleteMachineSchema.schema required\n");
         exit(EXIT_FAILURE);
      }

      MothershipProdigyCluster desiredCluster = controlCluster;
      bool removed = false;
      if (mothershipDeleteClusterMachineSchema(desiredCluster.machineSchemas, schema, &removed, &failure) == false)
      {
         basics_log("deleteMachineSchema success=0 name=%s failure=%s\n", controlCluster.name.c_str(), failure.c_str());
         exit(EXIT_FAILURE);
      }

      MothershipProviderCredential referencedCredential = {};
      if (validateClusterProviderCredentialReference(desiredCluster, failure, &referencedCredential) == false
         || inferClusterMachineSchemaCpuCapabilities(desiredCluster, &referencedCredential, failure) == false)
      {
         basics_log("deleteMachineSchema success=0 name=%s failure=%s\n", controlCluster.name.c_str(), failure.c_str());
         exit(EXIT_FAILURE);
      }

      bool changed = mothershipEqualClusterMachineSchemas(controlCluster.machineSchemas, desiredCluster.machineSchemas) == false;

      if (socket.configureCluster(controlCluster, &failure) == false)
      {
         basics_log("deleteMachineSchema success=0 name=%s failure=%s\n", controlCluster.name.c_str(), failure.c_str());
         exit(EXIT_FAILURE);
      }

      DeleteMachineSchema request = {};
      request.schema = schema;

      DeleteMachineSchema response = {};
      if (requestDeleteMachineSchema(request, response, failure) == false)
      {
         MothershipProdigyCluster refreshCluster = controlCluster;
         persistClusterRefreshFailure(refreshCluster, failure);
         basics_log("deleteMachineSchema success=0 name=%s failure=%s\n", controlCluster.name.c_str(), failure.c_str());
         exit(EXIT_FAILURE);
      }

      desiredCluster.topology = response.topology;
      desiredCluster.lastRefreshMs = Time::now<TimeResolution::ms>();
      desiredCluster.lastRefreshFailure.clear();

      {
         MothershipClusterRegistry clusterRegistry = openClusterRegistry();
         if (clusterRegistry.upsertCluster(desiredCluster, &desiredCluster, &failure) == false)
         {
            basics_log("deleteMachineSchema success=0 name=%s failure=%s\n", controlCluster.name.c_str(), failure.c_str());
            exit(EXIT_FAILURE);
         }
      }

      basics_log("deleteMachineSchema success=1 name=%s schema=%s removed=%d changed=%d topologyVersion=%llu topologyMachines=%u\n",
         desiredCluster.name.c_str(),
         schema.c_str(),
         int(removed),
         int(changed),
         (unsigned long long)desiredCluster.topology.version,
         unsigned(desiredCluster.topology.machines.size()));
      printManagedCluster(desiredCluster);
   }

	void runDeploy(int argc, char *argv[])
	{
		const bool debugDeploy = (std::getenv("PRODIGY_MOTHERSHIP_DEBUG_DEPLOY") != nullptr);
		auto debugLog = [debugDeploy] (const char *stage) -> void {
			if (debugDeploy)
			{
				basics_log("DEPLOY_DEBUG stage=%s\n", stage);
				std::fflush(stdout);
			}
		};

		if (argc < 3)
		{
			basics_log("too few arguments provided to deploy. ex: deploy [target: local|clusterName|clusterUUID] [deployment plan json] [path to container blob]\n");
			exit(EXIT_FAILURE);
		}

		bool returnAfterInitialSpinOkay = (std::strcmp(argv[0], "dev") == 0);
		if (returnAfterInitialSpinOkay == false
			&& std::strcmp(argv[0], "local") == 0
			&& std::getenv("PRODIGY_MOTHERSHIP_TEST_HARNESS") != nullptr)
		{
			// Local unix control requests coming from the isolated test harness run
			// readiness validation via explicit follow-up probes, so they should not
			// block on the terminal spinApplication frame.
			returnAfterInitialSpinOkay = true;
		}
		if (returnAfterInitialSpinOkay == false && std::strcmp(argv[0], "local") != 0)
		{
			MothershipClusterRegistry clusterRegistry = openClusterRegistry();
			MothershipProdigyCluster targetCluster = {};
			String clusterLookupFailure = {};
			String clusterIdentity = {};
			clusterIdentity.setInvariant(argv[0]);
			if (clusterRegistry.getClusterByIdentity(clusterIdentity, targetCluster, &clusterLookupFailure))
			{
				// Test clusters validate readiness via explicit follow-up probes on the
				// same isolated harness. Do not block deploy on the terminal
				// spinApplication frame there.
				if (targetCluster.deploymentMode == MothershipClusterDeploymentMode::test)
				{
					returnAfterInitialSpinOkay = true;
				}
			}
		}

    if (!configureControlTarget(argv[0]))
    {
      exit(EXIT_FAILURE);
    }

		DeploymentPlan plan{};

		String json;
		json.append(argv[1]);
		json.need(simdjson::SIMDJSON_PADDING);

    simdjson::dom::parser parser;
    simdjson::dom::element doc;
    if (parser.parse(json.data(), json.size()).get(doc))
    {
      basics_log("invalid deployment plan json\n");
      exit(EXIT_FAILURE);
    }

      bool sawSubnet = false;
		debugLog("json_parsed");

		for (auto field : doc.get_object())
		{
			String key;
			key.setInvariant(field.key.data(), field.key.size());
			if (debugDeploy)
			{
				basics_log("DEPLOY_DEBUG field=");
				(void)std::fwrite(key.data(), 1, key.size(), stdout);
				basics_log("\n");
				std::fflush(stdout);
			}

			if (key.equal("config"_ctv))
			{
        if (field.value.type() != simdjson::dom::element_type::OBJECT)
        {
          basics_log("config requires a document\n");
          exit(EXIT_FAILURE);
        }

        bool hasConfigType = false;
            uint32_t configSizeSeenMask = 0;
				for (auto subfield : field.value.get_object())
				{
					String subkey;
					subkey.setInvariant(subfield.key.data(), subfield.key.size());

          if (subkey.equal("isolateCPUs"_ctv))
          {
            String failure = {};
            if (mothershipParseApplicationCPUIsolationMode(subfield.value, plan.config, &failure) == false)
            {
              basics_log("%s\n", failure.c_str());
              exit(EXIT_FAILURE);
            }

            break;
          }
        }

        for (auto subfield : field.value.get_object())
        {
          String subkey;
          subkey.setInvariant(subfield.key.data(), subfield.key.size());

					if (subkey.equal("type"_ctv))
					{
            if (subfield.value.type() != simdjson::dom::element_type::STRING)
            {
              basics_log("config.type requires a string\n");
              exit(EXIT_FAILURE);
            }

            String value;
            value.setInvariant(subfield.value.get_c_str());

						if (value.equal("ApplicationType::stateless"_ctv))
						{
							plan.config.type = ApplicationType::stateless;
                     hasConfigType = true;
						}
						else if (value.equal("ApplicationType::stateful"_ctv))
						{
							plan.config.type = ApplicationType::stateful;
                     hasConfigType = true;
						}
						else if (value.equal("ApplicationType::tunnel"_ctv))
						{
							plan.config.type = ApplicationType::tunnel;
                     hasConfigType = true;
						}
            else
            {
              basics_log("config.type not recognized\n");
              exit(EXIT_FAILURE);
            }
          }
          else if (subkey.equal("capabilities"_ctv))
          {
            if (subfield.value.type() != simdjson::dom::element_type::ARRAY)
            {
              basics_log("config.capabilities requires an array\n");
              exit(EXIT_FAILURE);
            }

            for (auto item : subfield.value.get_array())
            {
              if (item.type() != simdjson::dom::element_type::STRING)
              {
                basics_log("config.capabilities requires all string array members\n");
                exit(EXIT_FAILURE);
              }

              String value;
              value.assign(item.get_c_str());

							if (value.equal("CAP_NET_BIND_SERVICE"_ctv))
							{
								plan.config.capabilities.insert(CAP_NET_BIND_SERVICE);
							}
							else if (value.equal("CAP_NET_ADMIN"_ctv))
							{
								plan.config.capabilities.insert(CAP_NET_ADMIN);
							}
							else if (value.equal("CAP_NET_RAW"_ctv))
							{
								plan.config.capabilities.insert(CAP_NET_RAW);
							}
							else if (value.equal("CAP_SYS_ADMIN"_ctv))
							{
								plan.config.capabilities.insert(CAP_SYS_ADMIN);
							}
							else if (value.equal("CAP_BPF"_ctv))
							{
								plan.config.capabilities.insert(CAP_BPF);
							}
              else
              {
                basics_log("config.capabilities capability is not allowed\n");
                exit(EXIT_FAILURE);
              }
            }
          }
          else if (subkey.equal("allowedMachineTypes"_ctv))
          {
            basics_log("config.allowedMachineTypes removed; scheduling is resource-based\n");
            exit(EXIT_FAILURE);
          }
          else if (subkey.equal("preferredMachineTypes"_ctv))
          {
            basics_log("config.preferredMachineTypes removed; scheduling is resource-based\n");
            exit(EXIT_FAILURE);
          }
          else if (subkey.equal("machineResourceCriteria"_ctv))
          {
            basics_log("config.machineResourceCriteria removed; place minGPUs, gpuMemoryGB, nicSpeedGbps, and any internet thresholds directly on config\n");
            exit(EXIT_FAILURE);
          }
          else if (subkey.equal("applicationID"_ctv))
          {
            if (subfield.value.type() == simdjson::dom::element_type::INT64)
            {
              int64_t value = 0;
              (void)subfield.value.get(value);

								if (value <= 0 || value > UINT16_MAX)
								{
									basics_log("config.applicationID value invalid\n");
									exit(EXIT_FAILURE);
								}

							plan.config.applicationID = uint16_t(value);
            }
            else if (subfield.value.type() == simdjson::dom::element_type::STRING)
            {
               String reference;
               reference.setInvariant(subfield.value.get_c_str());
               if (socket.resolveApplicationIDReference(reference, plan.config.applicationID, false) == false)
               {
                  basics_log("config.applicationID symbolic reference invalid or unreserved; reserveApplicationID first\n");
                  exit(EXIT_FAILURE);
               }
            }
            else
            {
              basics_log("config.applicationID requires an integer or symbolic reference string\n");
              exit(EXIT_FAILURE);
            }
					}
					else if (subkey.equal("versionID"_ctv))
					{
            if (subfield.value.type() != simdjson::dom::element_type::INT64)
            {
              basics_log("config.versionID requires a number\n");
              exit(EXIT_FAILURE);
            }

            int64_t value = 0;
            (void)subfield.value.get(value);

						if (value <= 0 || value > 281'474'976'710'655) // max 48 bit unsigned
						{
							basics_log("config.versionID value invalid\n");
              exit(EXIT_FAILURE);
            }

						plan.config.versionID = uint64_t(value);
					}
               else if (subkey.equal("architecture"_ctv))
               {
            String failure = {};
            if (mothershipParseApplicationArchitectureField(subfield.value, plan.config, "config"_ctv, &failure) == false)
            {
              basics_log("%s\n", failure.c_str());
              exit(EXIT_FAILURE);
            }
               }
               else if (subkey.equal("requiredIsaFeatures"_ctv))
               {
            String failure = {};
            if (mothershipParseApplicationRequiredIsaFeaturesField(subfield.value, plan.config, "config"_ctv, &failure) == false)
            {
              basics_log("%s\n", failure.c_str());
              exit(EXIT_FAILURE);
            }
               }
               else
               {
                  String sizeFailure = {};
                  if (mothershipParseApplicationConfigSizeField(subkey, subfield.value, plan.config, configSizeSeenMask, "config"_ctv, &sizeFailure))
                  {
                  }
                  else if (sizeFailure.size() > 0)
                  {
                     basics_log("%s\n", sizeFailure.c_str());
                     exit(EXIT_FAILURE);
                  }
                  else
                  {
                     String criteriaFailure = {};
                     if (mothershipParseApplicationMachineSelectionField(subkey, subfield.value, plan.config, &criteriaFailure))
                     {
                     }
                     else if (criteriaFailure.size() > 0)
                     {
                        basics_log("%s\n", criteriaFailure.c_str());
                        exit(EXIT_FAILURE);
                     }
                     else if (subkey.equal("nHugepages2MB"_ctv))
                     {
                        basics_log("config.nHugepages2MB was removed because hugepages are no longer used\n");
                        exit(EXIT_FAILURE);
                     }
						else if (subkey.equal("isolateCPUs"_ctv))
						{
            String failure = {};
            if (mothershipParseApplicationCPUIsolationMode(subfield.value, plan.config, &failure) == false)
            {
              basics_log("%s\n", failure.c_str());
              exit(EXIT_FAILURE);
            }
						}
						else if (subkey.equal("nLogicalCores"_ctv))
						{
            String failure = {};
            if (mothershipParseApplicationCPURequest(subfield.value, plan.config, &failure) == false)
            {
              basics_log("%s\n", failure.c_str());
              exit(EXIT_FAILURE);
            }
						}
						else if (subkey.equal("nThreads"_ctv))
						{
                     basics_log("config.nThreads was removed because thread count is no longer an application-config knob\n");
                     exit(EXIT_FAILURE);
						}
						else if (subkey.equal("msTilHealthy"_ctv)) // maximum 32 seconds
						{
            if (subfield.value.type() != simdjson::dom::element_type::INT64)
            {
              basics_log("config.msTilHealthy requires a number\n");
              exit(EXIT_FAILURE);
            }

            int64_t value = 0;
            (void)subfield.value.get(value);

						if (value <= 0 || value > 32'000)
						{
							basics_log("config.msTilHealthy value invalid\n");
              exit(EXIT_FAILURE);
            }

						plan.config.msTilHealthy = uint32_t(value);
						}
						else if (subkey.equal("sTilHealthcheck"_ctv)) // maximum 1 minute
						{
            if (subfield.value.type() != simdjson::dom::element_type::INT64)
            {
              basics_log("config.sTilHealthcheck requires a number\n");
              exit(EXIT_FAILURE);
            }

            int64_t value = 0;
            (void)subfield.value.get(value);

						if (value <= 0 || value > 60'000)
						{
							basics_log("config.sTilHealthcheck value invalid\n");
              exit(EXIT_FAILURE);
            }

						plan.config.sTilHealthcheck = uint32_t(value);
						}
						else if (subkey.equal("sTilKillable"_ctv)) // maximum 2 minutes for now
						{
            if (subfield.value.type() != simdjson::dom::element_type::INT64)
            {
              basics_log("config.sTilKillable requires a number\n");
              exit(EXIT_FAILURE);
            }

            int64_t value = 0;
            (void)subfield.value.get(value);

						if (value <= 0 || value > 120'000)
						{
							basics_log("config.sTilKillable value invalid\n");
              exit(EXIT_FAILURE);
            }

						plan.config.sTilKillable = uint32_t(value);
						}
						else if (subkey.equal("needsPublic6"_ctv))
						{
            basics_log("config.needsPublic6 removed; use whiteholes on DeploymentPlan\n");
            exit(EXIT_FAILURE);
						}
						else if (subkey.equal("needsPublic4"_ctv))
						{
            basics_log("config.needsPublic4 removed; use whiteholes on DeploymentPlan\n");
            exit(EXIT_FAILURE);
						}
						else
						{
            basics_log("config.%s invalid field\n", subkey.c_str());
            exit(EXIT_FAILURE);
						}
                  }
               }
				}

          // Validate required config fields once all config keys are parsed.
          {
            String failure = {};
            if (mothershipValidateApplicationMachineSelectionFields(plan.config, "config"_ctv, &failure) == false)
            {
               basics_log("%s\n", failure.c_str());
               exit(EXIT_FAILURE);
            }

            if (mothershipValidateApplicationRuntimeRequirements(plan.config, "config"_ctv, &failure) == false)
            {
               basics_log("%s\n", failure.c_str());
               exit(EXIT_FAILURE);
            }
          }
          if (hasConfigType == false)
          {
            basics_log("config requires type parameter\n");
            exit(EXIT_FAILURE);
          }
			}
	      else if (key.equal("tls"_ctv))
	      {
	        if (field.value.type() != simdjson::dom::element_type::OBJECT)
	        {
	          basics_log("tls requires a document\n");
	          exit(EXIT_FAILURE);
	        }

	        plan.hasTlsIssuancePolicy = true;

	        for (auto subfield : field.value.get_object())
	        {
	          String sk;
	          sk.setInvariant(subfield.key.data(), subfield.key.size());

	          if (sk.equal("applicationID"_ctv))
	          {
	            if (subfield.value.type() == simdjson::dom::element_type::INT64)
	            {
	               int64_t v = 0;
	               (void)subfield.value.get(v);
	               if (v <= 0 || v > UINT16_MAX)
	               {
	                  basics_log("tls.applicationID invalid\n");
	                  exit(EXIT_FAILURE);
	               }
	               plan.tlsIssuancePolicy.applicationID = static_cast<uint16_t>(v);
	            }
	            else if (subfield.value.type() == simdjson::dom::element_type::STRING)
	            {
	               String reference;
	               reference.setInvariant(subfield.value.get_c_str());
	               if (socket.resolveApplicationIDReference(reference, plan.tlsIssuancePolicy.applicationID, false) == false)
	               {
	                  basics_log("tls.applicationID symbolic reference invalid or unreserved; reserveApplicationID first\n");
	                  exit(EXIT_FAILURE);
	               }
	            }
	            else
	            {
	               basics_log("tls.applicationID requires an integer or symbolic reference string\n");
	               exit(EXIT_FAILURE);
	            }
	          }
	          else if (sk.equal("enablePerContainerLeafs"_ctv))
	          {
	            if (subfield.value.type() != simdjson::dom::element_type::BOOL)
	            {
	              basics_log("tls.enablePerContainerLeafs requires a bool\n");
	              exit(EXIT_FAILURE);
	            }
	            bool b = false;
	            (void)subfield.value.get(b);
	            plan.tlsIssuancePolicy.enablePerContainerLeafs = b;
	          }
	          else if (sk.equal("leafValidityDays"_ctv))
	          {
	            if (subfield.value.type() != simdjson::dom::element_type::INT64)
	            {
	              basics_log("tls.leafValidityDays requires an integer\n");
	              exit(EXIT_FAILURE);
	            }

	            int64_t v = 0;
	            (void)subfield.value.get(v);
	            if (v <= 0 || v > 825)
	            {
	              basics_log("tls.leafValidityDays must be in 1..825\n");
	              exit(EXIT_FAILURE);
	            }
	            plan.tlsIssuancePolicy.leafValidityDays = static_cast<uint32_t>(v);
	          }
	          else if (sk.equal("renewLeadPercent"_ctv))
	          {
	            if (subfield.value.type() != simdjson::dom::element_type::INT64)
	            {
	              basics_log("tls.renewLeadPercent requires an integer\n");
	              exit(EXIT_FAILURE);
	            }

	            int64_t v = 0;
	            (void)subfield.value.get(v);
	            if (v <= 0 || v >= 100)
	            {
	              basics_log("tls.renewLeadPercent must be in 1..99\n");
	              exit(EXIT_FAILURE);
	            }
	            plan.tlsIssuancePolicy.renewLeadPercent = static_cast<uint8_t>(v);
	          }
	          else if (sk.equal("identityNames"_ctv))
	          {
	            if (subfield.value.type() != simdjson::dom::element_type::ARRAY)
	            {
	              basics_log("tls.identityNames requires an array\n");
	              exit(EXIT_FAILURE);
	            }

	            for (auto item : subfield.value.get_array())
	            {
	              if (item.type() != simdjson::dom::element_type::STRING)
	              {
	                basics_log("tls.identityNames requires string members\n");
	                exit(EXIT_FAILURE);
	              }
	              String name;
	              name.assign(item.get_c_str());
	              if (name.size() == 0)
	              {
	                basics_log("tls.identityNames contains empty name\n");
	                exit(EXIT_FAILURE);
	              }
	              plan.tlsIssuancePolicy.identityNames.push_back(name);
	            }
	          }
	          else
	          {
	            basics_log("tls invalid field\n");
	            exit(EXIT_FAILURE);
	          }
	        }

	        if (plan.tlsIssuancePolicy.applicationID == 0)
	        {
	          basics_log("tls.applicationID required\n");
	          exit(EXIT_FAILURE);
	        }
	      }
	      else if (key.equal("apiCredentials"_ctv))
	      {
	        if (field.value.type() != simdjson::dom::element_type::OBJECT)
	        {
	          basics_log("apiCredentials requires a document\n");
	          exit(EXIT_FAILURE);
	        }

	        plan.hasApiCredentialPolicy = true;

	        for (auto subfield : field.value.get_object())
	        {
	          String sk;
	          sk.setInvariant(subfield.key.data(), subfield.key.size());

	          if (sk.equal("applicationID"_ctv))
	          {
	            if (subfield.value.type() == simdjson::dom::element_type::INT64)
	            {
	               int64_t v = 0;
	               (void)subfield.value.get(v);
	               if (v <= 0 || v > UINT16_MAX)
	               {
	                  basics_log("apiCredentials.applicationID invalid\n");
	                  exit(EXIT_FAILURE);
	               }
	               plan.apiCredentialPolicy.applicationID = static_cast<uint16_t>(v);
	            }
	            else if (subfield.value.type() == simdjson::dom::element_type::STRING)
	            {
	               String reference;
	               reference.setInvariant(subfield.value.get_c_str());
	               if (socket.resolveApplicationIDReference(reference, plan.apiCredentialPolicy.applicationID, false) == false)
	               {
	                  basics_log("apiCredentials.applicationID symbolic reference invalid or unreserved; reserveApplicationID first\n");
	                  exit(EXIT_FAILURE);
	               }
	            }
	            else
	            {
	               basics_log("apiCredentials.applicationID requires an integer or symbolic reference string\n");
	               exit(EXIT_FAILURE);
	            }
	          }
	          else if (sk.equal("requiredCredentialNames"_ctv))
	          {
	            if (subfield.value.type() != simdjson::dom::element_type::ARRAY)
	            {
	              basics_log("apiCredentials.requiredCredentialNames requires an array\n");
	              exit(EXIT_FAILURE);
	            }
	            for (auto item : subfield.value.get_array())
	            {
	              if (item.type() != simdjson::dom::element_type::STRING)
	              {
	                basics_log("apiCredentials.requiredCredentialNames requires string members\n");
	                exit(EXIT_FAILURE);
	              }
	              String name;
	              name.assign(item.get_c_str());
	              if (name.size() == 0)
	              {
	                basics_log("apiCredentials.requiredCredentialNames contains empty name\n");
	                exit(EXIT_FAILURE);
	              }
	              plan.apiCredentialPolicy.requiredCredentialNames.push_back(name);
	            }
	          }
	          else if (sk.equal("refreshPushEnabled"_ctv))
	          {
	            if (subfield.value.type() != simdjson::dom::element_type::BOOL)
	            {
	              basics_log("apiCredentials.refreshPushEnabled requires a bool\n");
	              exit(EXIT_FAILURE);
	            }
	            bool b = false;
	            (void)subfield.value.get(b);
	            plan.apiCredentialPolicy.refreshPushEnabled = b;
	          }
	          else
	          {
	            basics_log("apiCredentials invalid field\n");
	            exit(EXIT_FAILURE);
	          }
	        }

	        if (plan.apiCredentialPolicy.applicationID == 0)
	        {
	          basics_log("apiCredentials.applicationID required\n");
	          exit(EXIT_FAILURE);
	        }

	        if (plan.apiCredentialPolicy.requiredCredentialNames.size() == 0)
	        {
	          basics_log("apiCredentials.requiredCredentialNames required\n");
	          exit(EXIT_FAILURE);
	        }
	      }
      else if (key.equal("minimumSubscriberCapacity"_ctv)) // minimum value 1024 for now
      {
				if (field.value.type() != simdjson::dom::element_type::INT64)
				{
					basics_log("minimumSubscriberCapacity requires a number\n");
              exit(EXIT_FAILURE);
				}

				int64_t value = 0;
				(void)field.value.get(value);

				if (value < 1024)
				{
					basics_log("minimumSubscriberCapacity value invalid\n");
              exit(EXIT_FAILURE);
				}

				plan.minimumSubscriberCapacity = uint32_t(value);
			}
			else if (key.equal("horizontalScalers"_ctv)) // minimum value 1024 for now
			{
				if (field.value.type() != simdjson::dom::element_type::ARRAY)
				{
					basics_log("horizontalScalers requires an array\n");
              exit(EXIT_FAILURE);
				}

				if (plan.verticalScalers.size() > 0)
				{
					basics_log("can't submit both horizontal and vertical scalers\n");
					exit(EXIT_FAILURE);
				}

					for (auto subfield : field.value.get_array())
					{
						if (subfield.type() != simdjson::dom::element_type::OBJECT)
						{
							basics_log("horizontalScalers requires HorizontalScaler array members\n");
							exit(EXIT_FAILURE);
						}

							HorizontalScaler& scaler = plan.horizontalScalers.emplace_back();
							bool hasPercentile = false;
							bool hasDirection = false;
							bool hasLifetime = false;

						for (auto item : subfield.get_object())
						{
							String key;
							key.setInvariant(item.key.data(), item.key.size());

							if (key.equal("name"_ctv))
							{
								if (item.value.type() != simdjson::dom::element_type::STRING)
								{
									basics_log("horizontalScalers.name requires a string\n");
									exit(EXIT_FAILURE);
								}

								String metricName;
								metricName.setInvariant(item.value.get_c_str());
								if (resolveScalerMetricNameFromAlias(metricName, scaler.name) == false)
								{
									scaler.name.assign(metricName);
								}
							}
						else if (key.equal("percentile"_ctv))
						{
							double value = 0;
							if (item.value.type() == simdjson::dom::element_type::DOUBLE)
							{
								(void)item.value.get(value);
							}
							else if (item.value.type() == simdjson::dom::element_type::INT64)
							{
								int64_t intValue = 0;
								(void)item.value.get(intValue);
								value = double(intValue);
							}
							else if (item.value.type() == simdjson::dom::element_type::UINT64)
							{
								uint64_t intValue = 0;
								(void)item.value.get(intValue);
								value = double(intValue);
							}
							else
							{
								basics_log("horizontalScalers.percentile requires a number\n");
								exit(EXIT_FAILURE);
							}

							if (!(value > 0.0 && value <= 100.0))
							{
								basics_log("horizontalScalers.percentile must be in (0, 100]\n");
								exit(EXIT_FAILURE);
							}

							scaler.percentile = value;
							hasPercentile = true;
						}
						else if (key.equal("operation"_ctv))
						{
							basics_log("horizontalScalers.operation is not supported; use percentile + threshold + direction\n");
							exit(EXIT_FAILURE);
						}
						else if (key.equal("direction"_ctv))
						{
							if (item.value.type() != simdjson::dom::element_type::STRING)
							{
								basics_log("horizontalScalers.direction requires a string\n");
								exit(EXIT_FAILURE);
							}

							String value;
							value.setInvariant(item.value.get_c_str());

							if (value.equal("upscale"_ctv) || value.equal("Scaler::Direction::upscale"_ctv))
							{
								scaler.direction = Scaler::Direction::upscale;
								hasDirection = true;
							}
							else if (value.equal("downscale"_ctv) || value.equal("Scaler::Direction::downscale"_ctv))
							{
								scaler.direction = Scaler::Direction::downscale;
								hasDirection = true;
							}
							else
							{
								basics_log("horizontalScalers.direction must be upscale or downscale\n");
								exit(EXIT_FAILURE);
							}
						}
						else if (key.equal("lookbackSeconds"_ctv))
						{
							if (item.value.type() != simdjson::dom::element_type::INT64)
							{
								basics_log("horizontalScalers.lookbackSeconds requires an integer\n");
								exit(EXIT_FAILURE);
							}

							int64_t value = 0;
								(void)item.value.get(value);

							if (value <= 0)
							{
								basics_log("horizontalScalers.lookbackSeconds must be positive\n");
								exit(EXIT_FAILURE);
							}

							scaler.lookbackSeconds = uint32_t(value);
						}
							else if (key.equal("nIntervals"_ctv))
							{
								basics_log("horizontalScalers.nIntervals is not supported; use lookbackSeconds\n");
								exit(EXIT_FAILURE);
							}
						else if (key.equal("threshold"_ctv))
						{
							if (item.value.type() != simdjson::dom::element_type::DOUBLE)
							{
								basics_log("horizontalScalers.threshold requires a double\n");
								exit(EXIT_FAILURE);
							}

							double value = 0.0;
								(void)item.value.get(value);

							if (value <= 0)
							{
								basics_log("horizontalScalers.threshold must be positive\n");
								exit(EXIT_FAILURE);
							}

							scaler.threshold = value;
						}
						else if (key.equal("upscaleThreshold"_ctv) || key.equal("downscaleThreshold"_ctv))
						{
							basics_log("horizontalScalers.%s is not supported; use threshold + direction\n", key.c_str());
							exit(EXIT_FAILURE);
						}
						else if (key.equal("minValue"_ctv))
						{
							if (item.value.type() != simdjson::dom::element_type::INT64)
							{
								basics_log("horizontalScalers.minValue requires an integer\n");
								exit(EXIT_FAILURE);
							}

							int64_t value = 0;
							(void)item.value.get(value);

							if (value <= 0)
							{
								basics_log("horizontalScalers.minValue must be positive\n");
								exit(EXIT_FAILURE);
							}

							scaler.minValue = uint32_t(value);
						}
						else if (key.equal("maxValue"_ctv))
						{
							if (item.value.type() != simdjson::dom::element_type::INT64)
							{
								basics_log("horizontalScalers.maxValue requires an integer\n");
								exit(EXIT_FAILURE);
							}

							int64_t value = 0;
							(void)item.value.get(value);

							if (value <= 0)
							{
								basics_log("horizontalScalers.maxValue must be positive\n");
								exit(EXIT_FAILURE);
							}

							scaler.maxValue = uint32_t(value);
						}
						else if (key.equal("lifetime"_ctv))
						{
							if (item.value.type() != simdjson::dom::element_type::STRING)
							{
								basics_log("horizontalScalers.lifetime requires a string\n");
								exit(EXIT_FAILURE);
							}

							String value;
							value.setInvariant(item.value.get_c_str());

								if (value.equal("ApplicationLifetime::base"_ctv))
								{
									scaler.lifetime = ApplicationLifetime::base;
									hasLifetime = true;
								}
								else if (value.equal("ApplicationLifetime::surge"_ctv))
								{
									scaler.lifetime = ApplicationLifetime::surge;
									hasLifetime = true;
								}
							else
							{
								basics_log("horizontalScalers.lifetime ApplicationLifetime either invalid or not allowed\n");
								exit(EXIT_FAILURE);
							}
						}
						else
						{
							basics_log("config.horizontalScalers bad field in HorizontalScaler\n");
							exit(EXIT_FAILURE);
						}
					}

					if (scaler.name.size() == 0)
					{
						basics_log("config.horizontalScalers name field of HorizontalScaler required\n");
						exit(EXIT_FAILURE);
					}

					if (hasPercentile == false)
					{
						basics_log("config.horizontalScalers percentile field of HorizontalScaler required\n");
						exit(EXIT_FAILURE);
					}

					if (scaler.lookbackSeconds == 0)
					{
						basics_log("config.horizontalScalers lookbackSeconds field of HorizontalScaler required\n");
						exit(EXIT_FAILURE);
					}

					if (scaler.threshold == 0)
					{
						basics_log("config.horizontalScalers threshold field of HorizontalScaler required\n");
						exit(EXIT_FAILURE);
					}

					if (hasDirection == false)
					{
						basics_log("config.horizontalScalers direction field of HorizontalScaler required\n");
						exit(EXIT_FAILURE);
					}

						if (hasLifetime == false)
						{
							basics_log("config.horizontalScalers lifetime field of HorizontalScaler required\n");
							exit(EXIT_FAILURE);
					}

					if (scaler.minValue > 0 && scaler.maxValue > 0 && scaler.minValue > scaler.maxValue)
					{
						basics_log("config.horizontalScalers minValue cannot exceed maxValue\n");
						exit(EXIT_FAILURE);
					}
				}
			}
			else if (key.equal("verticalScalers"_ctv)) // minimum value 1024 for now
			{
				if (field.value.type() != simdjson::dom::element_type::ARRAY)
				{
					basics_log("verticalScalers requires an array\n");
					exit(EXIT_FAILURE);
				}

				if (plan.horizontalScalers.size() > 0)
				{
					basics_log("can't submit both horizontal and vertical scalers\n");
					exit(EXIT_FAILURE);
				}

					for (auto subfield : field.value.get_array())
					{
						if (subfield.type() != simdjson::dom::element_type::OBJECT)
						{
							basics_log("verticalScalers requires VerticalScaler array members\n");
							exit(EXIT_FAILURE);
						}

						VerticalScaler& scaler = plan.verticalScalers.emplace_back();
						bool hasPercentile = false;
						bool hasDirection = false;
						bool hasResource = false;

						for (auto item : subfield.get_object())
						{
						String key;
						key.setInvariant(item.key.data(), item.key.size());

							if (key.equal("name"_ctv))
							{
								if (item.value.type() != simdjson::dom::element_type::STRING)
								{
									basics_log("verticalScalers.name requires a string\n");
									exit(EXIT_FAILURE);
								}

								String metricName;
								metricName.setInvariant(item.value.get_c_str());
								if (resolveScalerMetricNameFromAlias(metricName, scaler.name) == false)
								{
									scaler.name.assign(metricName);
								}
							}
						else if (key.equal("percentile"_ctv))
						{
							double value = 0;
							if (item.value.type() == simdjson::dom::element_type::DOUBLE)
							{
								(void)item.value.get(value);
							}
							else if (item.value.type() == simdjson::dom::element_type::INT64)
							{
								int64_t intValue = 0;
								(void)item.value.get(intValue);
								value = double(intValue);
							}
							else if (item.value.type() == simdjson::dom::element_type::UINT64)
							{
								uint64_t intValue = 0;
								(void)item.value.get(intValue);
								value = double(intValue);
							}
							else
							{
								basics_log("verticalScalers.percentile requires a number\n");
								exit(EXIT_FAILURE);
							}

							if (!(value > 0.0 && value <= 100.0))
							{
								basics_log("verticalScalers.percentile must be in (0, 100]\n");
								exit(EXIT_FAILURE);
							}

							scaler.percentile = value;
							hasPercentile = true;
						}
						else if (key.equal("operation"_ctv))
						{
							basics_log("verticalScalers.operation is not supported; use percentile + threshold + direction\n");
							exit(EXIT_FAILURE);
						}
						else if (key.equal("direction"_ctv))
						{
							if (item.value.type() != simdjson::dom::element_type::STRING)
							{
								basics_log("verticalScalers.direction requires a string\n");
								exit(EXIT_FAILURE);
							}

							String value;
							value.setInvariant(item.value.get_c_str());

							if (value.equal("upscale"_ctv) || value.equal("Scaler::Direction::upscale"_ctv))
							{
								scaler.direction = Scaler::Direction::upscale;
								hasDirection = true;
							}
							else if (value.equal("downscale"_ctv) || value.equal("Scaler::Direction::downscale"_ctv))
							{
								scaler.direction = Scaler::Direction::downscale;
								hasDirection = true;
							}
							else
							{
								basics_log("verticalScalers.direction must be upscale or downscale\n");
								exit(EXIT_FAILURE);
							}
						}
						else if (key.equal("lookbackSeconds"_ctv))
						{
							if (item.value.type() != simdjson::dom::element_type::INT64)
							{
								basics_log("verticalScalers.lookbackSeconds requires an integer\n");
								exit(EXIT_FAILURE);
							}

							int64_t value = 0;
								(void)item.value.get(value);

							if (value <= 0)
							{
								basics_log("verticalScalers.lookbackSeconds must be positive\n");
								exit(EXIT_FAILURE);
							}

							scaler.lookbackSeconds = uint32_t(value);
						}
							else if (key.equal("nIntervals"_ctv))
							{
								basics_log("verticalScalers.nIntervals is not supported; use lookbackSeconds\n");
								exit(EXIT_FAILURE);
							}
						else if (key.equal("threshold"_ctv))
						{
							if (item.value.type() != simdjson::dom::element_type::DOUBLE)
							{
								basics_log("verticalScalers.threshold requires a double\n");
								exit(EXIT_FAILURE);
							}

							double value = 0.0;
								(void)item.value.get(value);

							if (value <= 0)
							{
								basics_log("verticalScalers.threshold must be positive\n");
								exit(EXIT_FAILURE);
							}

							scaler.threshold = value;
						}
						else if (key.equal("upscaleThreshold"_ctv) || key.equal("downscaleThreshold"_ctv))
						{
							basics_log("verticalScalers.%s is not supported; use threshold + direction\n", key.c_str());
							exit(EXIT_FAILURE);
						}
						else if (key.equal("resource"_ctv))
						{
							if (item.value.type() != simdjson::dom::element_type::STRING)
							{
								basics_log("verticalScalers.resource requires a string\n");
								exit(EXIT_FAILURE);
							}

							String value;
							value.setInvariant(item.value.get_c_str());

							if (parseScalingDimensionAlias(value, scaler.resource))
							{
								hasResource = true;
							}
							else
							{
								basics_log("verticalScalers.resource ScalingDimension invalid\n");
								exit(EXIT_FAILURE);
							}
						}
						else if (key.equal("increment"_ctv))
						{
							if (item.value.type() != simdjson::dom::element_type::INT64)
							{
								basics_log("verticalScalers.increment requires an integer\n");
								exit(EXIT_FAILURE);
							}

							int64_t value = 0;
								(void)item.value.get(value);

							if (value <= 0)
							{
								basics_log("verticalScalers.increment must be positive\n");
								exit(EXIT_FAILURE);
							}

							scaler.increment = uint32_t(value);
						}
						else if (key.equal("minValue"_ctv))
						{
							if (item.value.type() != simdjson::dom::element_type::INT64)
							{
								basics_log("verticalScalers.minValue requires an integer\n");
								exit(EXIT_FAILURE);
							}

							int64_t value = 0;
							(void)item.value.get(value);

							if (value <= 0)
							{
								basics_log("verticalScalers.minValue must be positive\n");
								exit(EXIT_FAILURE);
							}

							scaler.minValue = uint32_t(value);
						}
						else if (key.equal("maxValue"_ctv))
						{
							if (item.value.type() != simdjson::dom::element_type::INT64)
							{
								basics_log("verticalScalers.maxValue requires an integer\n");
								exit(EXIT_FAILURE);
							}

							int64_t value = 0;
							(void)item.value.get(value);

							if (value <= 0)
							{
								basics_log("verticalScalers.maxValue must be positive\n");
								exit(EXIT_FAILURE);
							}

							scaler.maxValue = uint32_t(value);
						}
						else
						{
							basics_log("config.verticalScalers bad field in VerticalScaler\n");
							exit(EXIT_FAILURE);
						}
					}

					if (scaler.name.size() == 0)
					{
						basics_log("config.verticalScalers name field of VerticalScaler required\n");
						exit(EXIT_FAILURE);
					}

					if (hasPercentile == false)
					{
						basics_log("config.verticalScalers percentile field of VerticalScaler required\n");
						exit(EXIT_FAILURE);
					}

					if (scaler.lookbackSeconds == 0)
					{
						basics_log("config.verticalScalers lookbackSeconds field of VerticalScaler required\n");
						exit(EXIT_FAILURE);
					}

					if (scaler.threshold == 0)
					{
						basics_log("config.verticalScalers threshold field of VerticalScaler required\n");
						exit(EXIT_FAILURE);
					}

					if (hasDirection == false)
					{
						basics_log("config.verticalScalers direction field of VerticalScaler required\n");
						exit(EXIT_FAILURE);
					}

						if (hasResource == false)
						{
							basics_log("config.verticalScalers resource field of ScalingDimension required\n");
							exit(EXIT_FAILURE);
						}

					if (scaler.increment == 0)
					{
						basics_log("config.verticalScalers increment field of VerticalScaler required\n");
						exit(EXIT_FAILURE);
					}

					if (scaler.maxValue > 0 && scaler.minValue > scaler.maxValue)
					{
						basics_log("config.verticalScalers minValue cannot exceed maxValue\n");
						exit(EXIT_FAILURE);
					}
				}
			}
			else if (key.equal("isStateful"_ctv))
			{
        if (field.value.type() != simdjson::dom::element_type::BOOL)
        {
          basics_log("isStateful requires a bool\n");
          exit(EXIT_FAILURE);
        }

        {
          bool b = false;
          (void)field.value.get(b);
          plan.isStateful = b;
        }
			}
			else if (key.equal("stateful"_ctv))
			{
				if (field.value.type() != simdjson::dom::element_type::OBJECT)
				{
					basics_log("stateful requires a StatefulDeploymentPlan\n");
					exit(EXIT_FAILURE);
				}

				for (auto subfield : field.value.get_object())
				{
					String key;
					key.setInvariant(subfield.key.data(), subfield.key.size());

					if (key.equal("clientPrefix"_ctv))
					{
						if (subfield.value.type() != simdjson::dom::element_type::INT64)
						{
							basics_log("stateful.clientPrefix requires an integer\n");
							exit(EXIT_FAILURE);
						}

						int64_t value = 0;
						(void)subfield.value.get(value);

						if (value <= 0)
						{
							basics_log("stateful.clientPrefix must be positive\n");
							exit(EXIT_FAILURE);
						}

						plan.stateful.clientPrefix = value;
					}
					else if (key.equal("siblingPrefix"_ctv))
					{
						if (subfield.value.type() != simdjson::dom::element_type::INT64)
						{
							basics_log("stateful.siblingPrefix requires an integer\n");
							exit(EXIT_FAILURE);
						}

						int64_t value = 0;
						(void)subfield.value.get(value);

						if (value <= 0)
						{
							basics_log("stateful.siblingPrefix must be positive\n");
							exit(EXIT_FAILURE);
						}

						plan.stateful.siblingPrefix = value;
					}
					else if (key.equal("cousinPrefix"_ctv))
					{
						if (subfield.value.type() != simdjson::dom::element_type::INT64)
						{
							basics_log("stateful.cousinPrefix requires an integer\n");
							exit(EXIT_FAILURE);
						}

						int64_t value = 0;
						(void)subfield.value.get(value);

						if (value <= 0)
						{
							basics_log("stateful.cousinPrefix must be positive\n");
							exit(EXIT_FAILURE);
						}

						plan.stateful.cousinPrefix = value;
					}
					else if (key.equal("seedingPrefix"_ctv))
					{
						if (subfield.value.type() != simdjson::dom::element_type::INT64)
						{
							basics_log("stateful.seedingPrefix requires an integer\n");
							exit(EXIT_FAILURE);
						}

						int64_t value = 0;
						(void)subfield.value.get(value);

						if (value <= 0)
						{
							basics_log("stateful.seedingPrefix must be positive\n");
							exit(EXIT_FAILURE);
						}

						plan.stateful.seedingPrefix = value;
					}
					else if (key.equal("shardingPrefix"_ctv))
					{
						if (subfield.value.type() != simdjson::dom::element_type::INT64)
						{
							basics_log("stateful.shardingPrefix requires an integer\n");
							exit(EXIT_FAILURE);
						}

						int64_t value = 0;
						(void)subfield.value.get(value);

						if (value <= 0)
						{
							basics_log("stateful.shardingPrefix must be positive\n");
							exit(EXIT_FAILURE);
						}

						plan.stateful.shardingPrefix = value;
					}
						else if (key.equal("allowUpdateInPlace"_ctv))
						{
							if (subfield.value.type() != simdjson::dom::element_type::BOOL)
							{
								basics_log("stateful.allowUpdateInPlace requires a bool\n");
								exit(EXIT_FAILURE);
							}

							bool b = false;
							(void)subfield.value.get(b);
							plan.stateful.allowUpdateInPlace = b;
						}
						else if (key.equal("seedingAlways"_ctv))
						{
							if (subfield.value.type() != simdjson::dom::element_type::BOOL)
							{
								basics_log("stateful.seedingAlways requires a bool\n");
								exit(EXIT_FAILURE);
							}

							bool b = false;
							(void)subfield.value.get(b);
							plan.stateful.seedingAlways = b;
						}
						else if (key.equal("neverShard"_ctv))
						{
							if (subfield.value.type() != simdjson::dom::element_type::BOOL)
							{
								basics_log("stateful.neverShard requires a bool\n");
								exit(EXIT_FAILURE);
							}

							bool b = false;
							(void)subfield.value.get(b);
							plan.stateful.neverShard = b;
						}
						else if (key.equal("allMasters"_ctv))
						{
							if (subfield.value.type() != simdjson::dom::element_type::BOOL)
							{
								basics_log("stateful.allMasters requires a bool\n");
								exit(EXIT_FAILURE);
							}

							bool b = false;
							(void)subfield.value.get(b);
							plan.stateful.allMasters = b;
						}
						else
						{
							basics_log("stateful invalid field\n");
							exit(EXIT_FAILURE);
						}
				}

          if (plan.stateful.clientPrefix == 0)
          {
            basics_log("stateful.clientPrefix required\n");
            exit(EXIT_FAILURE);
          }

          if (plan.stateful.siblingPrefix == 0)
          {
            basics_log("stateful.siblingPrefix required\n");
            exit(EXIT_FAILURE);
          }

          if (plan.stateful.cousinPrefix == 0)
          {
            basics_log("stateful.cousinPrefix required\n");
            exit(EXIT_FAILURE);
          }

          if (plan.stateful.seedingPrefix == 0)
          {
            basics_log("stateful.seedingPrefix required\n");
            exit(EXIT_FAILURE);
          }

          if (plan.stateful.shardingPrefix == 0)
          {
            basics_log("stateful.shardingPrefix required\n");
            exit(EXIT_FAILURE);
          }
			}
            else if (key.equal("stateless"_ctv))
            {
				if (field.value.type() != simdjson::dom::element_type::OBJECT)
				{
					basics_log("stateless requires a StatelessDeploymentPlan\n");
					exit(EXIT_FAILURE);
				}

				for (auto subfield : field.value.get_object())
				{
					String key;
					key.setInvariant(subfield.key.data(), subfield.key.size());

					if (key.equal("nBase"_ctv))
					{
						if (subfield.value.type() != simdjson::dom::element_type::INT64)
						{
							basics_log("stateless.nBase requires an integer\n");
							exit(EXIT_FAILURE);
						}

						int64_t value = 0;
						(void)subfield.value.get(value);

						if (value <= 0)
						{
							basics_log("stateless.nBase must be positive\n");
							exit(EXIT_FAILURE);
						}

						plan.stateless.nBase = uint32_t(value);
					}
					else if (key.equal("maxPerRackRatio"_ctv))
					{
						if (subfield.value.type() != simdjson::dom::element_type::DOUBLE)
						{
							basics_log("stateless.maxPerRackRatio requires a float\n");
							exit(EXIT_FAILURE);
						}

						double value = 0.0;
						(void)subfield.value.get(value);

						if (value <= 0)
						{
							basics_log("stateless.maxPerRackRatio must be positive\n");
							exit(EXIT_FAILURE);
						}

						plan.stateless.maxPerRackRatio = float(value);
					}
					else if (key.equal("maxPerMachineRatio"_ctv))
					{
						if (subfield.value.type() != simdjson::dom::element_type::DOUBLE)
						{
							basics_log("stateless.maxPerMachineRatio requires a float\n");
							exit(EXIT_FAILURE);
						}

						double value = 0.0;
						(void)subfield.value.get(value);

						if (value <= 0)
						{
							basics_log("stateless.maxPerMachineRatio must be >0\n");
							exit(EXIT_FAILURE);
						}

						plan.stateless.maxPerMachineRatio = float(value);
					}
                    else if (key.equal("canaryCount"_ctv))
                    {
                        if (subfield.value.type() != simdjson::dom::element_type::INT64)
                        {
                            basics_log("canaryCount requires an integer\n");
                            exit(EXIT_FAILURE);
                        }

                        int64_t value = 0;
						(void)subfield.value.get(value);

                        if (value < 0)
                        {
                            basics_log("canaryCount must be positive\n");
                            exit(EXIT_FAILURE);
                        }

                        plan.canaryCount = uint32_t(value);
                    }
                    else if (key.equal("canariesMustLiveForMinutes"_ctv))
                    {
                        if (subfield.value.type() != simdjson::dom::element_type::INT64)
                        {
                            basics_log("canariesMustLiveForMinutes requires an integer\n");
                            exit(EXIT_FAILURE);
                        }

                        int64_t value = 0;
						(void)subfield.value.get(value);

                        if (value <= 0)
                        {
                            basics_log("canariesMustLiveForMinutes must be >0\n");
                            exit(EXIT_FAILURE);
                        }

                        plan.canariesMustLiveForMinutes = uint32_t(value);
                    }
						else if (key.equal("moveableDuringCompaction"_ctv))
						{
							if (subfield.value.type() != simdjson::dom::element_type::BOOL)
							{
								basics_log("stateless.moveableDuringCompaction requires a bool\n");
								exit(EXIT_FAILURE);
							}

							bool b = false;
							(void)subfield.value.get(b);
							plan.stateless.moveableDuringCompaction = b;
						}
					else
					{
						basics_log("stateless invalid field\n");
						exit(EXIT_FAILURE);
					}
                }

					if (plan.stateless.nBase == 0)
					{
						basics_log("stateless.nBase required\n");
						exit(EXIT_FAILURE);
					}

					if (plan.stateless.maxPerRackRatio == 0)
					{
						basics_log("stateless.maxPerRackRatio required\n");
						exit(EXIT_FAILURE);
					}

					if (plan.stateless.maxPerMachineRatio == 0)
					{
						basics_log("stateless.maxPerMachineRatio required\n");
						exit(EXIT_FAILURE);
					}

                    if (plan.canaryCount > 0 && plan.canariesMustLiveForMinutes == 0)
                    {
                        basics_log("canariesMustLiveForMinutes required if canaryCount > 0\n");
                        exit(EXIT_FAILURE);
                    }
            }
      else if (key.equal("canaryCount"_ctv))
      {
        if (field.value.type() != simdjson::dom::element_type::INT64)
        {
          basics_log("canaryCount requires an integer\n");
          exit(EXIT_FAILURE);
        }

        int64_t value = 0;
        (void)field.value.get(value);

                if (value < 0)
                {
                    basics_log("canaryCount must be positive\n");
          exit(EXIT_FAILURE);
        }

                plan.canaryCount = uint32_t(value);
            }
      else if (key.equal("canariesMustLiveForMinutes"_ctv))
      {
        if (field.value.type() != simdjson::dom::element_type::INT64)
        {
          basics_log("canariesMustLiveForMinutes requires an integer\n");
          exit(EXIT_FAILURE);
        }

        int64_t value = 0;
        (void)field.value.get(value);

                if (value <= 0)
                {
                    basics_log("canariesMustLiveForMinutes must be >0\n");
          exit(EXIT_FAILURE);
        }

                plan.canariesMustLiveForMinutes = uint32_t(value);
            }
			else if (key.equal("wormholes"_ctv))
			{
				if (field.value.type() != simdjson::dom::element_type::ARRAY)
				{
					basics_log("wormholes requires an array\n");
					exit(EXIT_FAILURE);
				}

					for (auto subfield : field.value.get_array())
					{
						if (subfield.type() != simdjson::dom::element_type::OBJECT)
						{
							basics_log("wormholes requires Wormhole array members\n");
							exit(EXIT_FAILURE);
						}

					Wormhole& wormhole = plan.wormholes.emplace_back();
               bool addressWasSet = false;
               bool routableAddressUUIDWasSet = false;
               bool sourceWasSet = false;
               bool quicCidKeyRotationHoursWasSet = false;

						for (auto item : subfield.get_object())
						{
						String key;
						key.setInvariant(item.key.data(), item.key.size());

						if (key.equal("externalAddress"_ctv))
						{
							if (item.value.type() != simdjson::dom::element_type::STRING)
							{
								basics_log("wormhole.externalAddress requires a string\n");
								exit(EXIT_FAILURE);
							}

							if (inet_pton(AF_INET, item.value.get_c_str(), wormhole.externalAddress.v6) == 1)
							{
								wormhole.externalAddress.is6 = false;
							}
							else if (inet_pton(AF_INET6, item.value.get_c_str(), wormhole.externalAddress.v6) == 1)
							{
								wormhole.externalAddress.is6 = true;
							}
							else
							{
								basics_log("wormholes.externalAddress is invalid\n");
								exit(EXIT_FAILURE);
							}

							addressWasSet = true;
						}
						else if (key.equal("externalPort"_ctv))
						{
              if (item.value.type() != simdjson::dom::element_type::INT64)
              {
                basics_log("wormhole.externalPort requires an integer\n");
                exit(EXIT_FAILURE);
              }

              int64_t value = 0;
              (void)item.value.get(value);

							if (value <= 0)
							{
								basics_log("wormhole.externalPort must be >0\n");
                exit(EXIT_FAILURE);
              }

							wormhole.externalPort = uint16_t(value);
						}
						else if (key.equal("containerPort"_ctv))
						{
              if (item.value.type() != simdjson::dom::element_type::INT64)
              {
                basics_log("wormhole.containerPort requires an integer\n");
                exit(EXIT_FAILURE);
              }
              int64_t value = 0;
              (void)item.value.get(value);

							if (value <= 0)
							{
								basics_log("wormhole.containerPort must be >0\n");
                exit(EXIT_FAILURE);
              }

							wormhole.containerPort = uint16_t(value);
						}
						else if (key.equal("layer4"_ctv))
						{
              if (item.value.type() != simdjson::dom::element_type::STRING)
              {
                basics_log("wormhole.layer4 requires a string\n");
                exit(EXIT_FAILURE);
              }

							String value;
							value.setInvariant(item.value.get_c_str());

              if (value.equal("TCP"_ctv))
              {
                wormhole.layer4 = IPPROTO_TCP;
              }
              else if (value.equal("UDP"_ctv))
              {
                wormhole.layer4 = IPPROTO_UDP;
              }
              else
              {
                basics_log("wormhole.layer4 invalid\n");
                exit(EXIT_FAILURE);
              }
						}
						else if (key.equal("isQuic"_ctv))
						{
              if (item.value.type() != simdjson::dom::element_type::BOOL)
              {
                basics_log("wormhole.isQuic requires a bool\n");
                exit(EXIT_FAILURE);
              }
              {
                bool b = false;
                (void)item.value.get(b);
                wormhole.isQuic = b;
              }
						}
                  else if (key.equal("userCapacity"_ctv))
                  {
                     String failure = {};
                     String context = {};
                     context.assign("wormhole.userCapacity"_ctv);
                     if (mothershipParseServiceUserCapacity(item.value, wormhole.userCapacity, context, &failure) == false)
                     {
                        basics_log("%s\n", failure.c_str());
                        exit(EXIT_FAILURE);
                     }
                  }
                  else if (key.equal("quicCidKeyRotationHours"_ctv))
                  {
                     String failure = {};
                     if (mothershipParseWormholeQuicCidKeyRotationHours(item.value, wormhole, &failure) == false)
                     {
                        basics_log("%s\n", failure.c_str());
                        exit(EXIT_FAILURE);
                     }

                     quicCidKeyRotationHoursWasSet = true;
                  }
						else if (key.equal("source"_ctv))
						{
              if (item.value.type() != simdjson::dom::element_type::STRING)
              {
                basics_log("wormhole.source requires a string\n");
                exit(EXIT_FAILURE);
              }

                     String value;
                     value.setInvariant(item.value.get_c_str());

                     if (parseExternalAddressSource(value, wormhole.source) == false)
                     {
                        basics_log("wormhole.source invalid\n");
                        exit(EXIT_FAILURE);
                     }

                     sourceWasSet = true;
						}
                  else if (key.equal("routableAddressUUID"_ctv))
                  {
                     if (item.value.type() != simdjson::dom::element_type::STRING)
                     {
                        basics_log("wormhole.routableAddressUUID requires a string\n");
                        exit(EXIT_FAILURE);
                     }

                     String value = {};
                     value.setInvariant(item.value.get_c_str());
                     if (value.size() == 0)
                     {
                        basics_log("wormhole.routableAddressUUID cannot be empty\n");
                        exit(EXIT_FAILURE);
                     }

                     wormhole.routableAddressUUID = String::numberFromHexString<uint128_t>(value);
                     if (wormhole.routableAddressUUID == 0)
                     {
                        basics_log("wormhole.routableAddressUUID invalid\n");
                        exit(EXIT_FAILURE);
                     }

                     routableAddressUUIDWasSet = true;
                  }
						else
						{
              basics_log("wormhole invalid field\n");
              exit(EXIT_FAILURE);
						}
					}

               if (addressWasSet == false && routableAddressUUIDWasSet == false)
               {
                  basics_log("wormhole.externalAddress or wormhole.routableAddressUUID field required\n");
                  exit(EXIT_FAILURE);
               }
               if (wormhole.externalPort == 0)
               {
                  basics_log("wormhole.externalPort field required\n");
                  exit(EXIT_FAILURE);
               }
               if (wormhole.containerPort == 0)
               {
                  basics_log("wormhole.containerPort field required\n");
                  exit(EXIT_FAILURE);
               }
               if (wormhole.layer4 == 0)
               {
                  basics_log("wormhole.layer4 field required\n");
                  exit(EXIT_FAILURE);
               }
               if (sourceWasSet == false)
               {
                  basics_log("wormhole.source field required\n");
                  exit(EXIT_FAILURE);
               }
               if (addressWasSet && routableAddressUUIDWasSet)
               {
                  basics_log("wormhole.externalAddress and wormhole.routableAddressUUID are mutually exclusive\n");
                  exit(EXIT_FAILURE);
               }
               if (wormhole.source == ExternalAddressSource::registeredRoutableAddress && routableAddressUUIDWasSet == false)
               {
                  basics_log("wormhole.source=registeredRoutableAddress requires wormhole.routableAddressUUID\n");
                  exit(EXIT_FAILURE);
               }
               if (wormhole.source != ExternalAddressSource::registeredRoutableAddress && routableAddressUUIDWasSet)
               {
                  basics_log("wormhole.routableAddressUUID requires source=registeredRoutableAddress\n");
                  exit(EXIT_FAILURE);
               }
               if (wormhole.isQuic && wormhole.layer4 != IPPROTO_UDP)
               {
                  basics_log("wormhole.isQuic requires layer4 == UDP\n");
                  exit(EXIT_FAILURE);
               }
               if (quicCidKeyRotationHoursWasSet && wormhole.isQuic == false)
               {
                  basics_log("wormhole.quicCidKeyRotationHours requires wormhole.isQuic\n");
                  exit(EXIT_FAILURE);
               }
				}
			}
      else if (key.equal("whiteholes"_ctv))
      {
         if (field.value.type() != simdjson::dom::element_type::ARRAY)
         {
            basics_log("whiteholes requires an array\n");
            exit(EXIT_FAILURE);
         }

         for (auto subfield : field.value.get_array())
         {
            if (subfield.type() != simdjson::dom::element_type::OBJECT)
            {
               basics_log("whiteholes requires object array members\n");
               exit(EXIT_FAILURE);
            }

            Whitehole need = {};
            bool transportWasSet = false;
            bool familyWasSet = false;
            bool sourceWasSet = false;

            for (auto item : subfield.get_object())
            {
               String subkey;
               subkey.setInvariant(item.key.data(), item.key.size());

               if (item.value.type() != simdjson::dom::element_type::STRING)
               {
                  basics_log("whiteholes fields require strings\n");
                  exit(EXIT_FAILURE);
               }

               String value;
               value.setInvariant(item.value.get_c_str());

               if (subkey.equal("transport"_ctv))
               {
                  if (parseExternalAddressTransport(value, need.transport) == false)
                  {
                     basics_log("whiteholes.transport invalid\n");
                     exit(EXIT_FAILURE);
                  }

                  transportWasSet = true;
               }
               else if (subkey.equal("family"_ctv))
               {
                  if (parseExternalAddressFamily(value, need.family) == false)
                  {
                     basics_log("whiteholes.family invalid\n");
                     exit(EXIT_FAILURE);
                  }

                  familyWasSet = true;
               }
               else if (subkey.equal("source"_ctv))
               {
                  if (parseExternalAddressSource(value, need.source) == false)
                  {
                     basics_log("whiteholes.source invalid\n");
                     exit(EXIT_FAILURE);
                  }

                  sourceWasSet = true;
               }
               else
               {
                  basics_log("whiteholes invalid field\n");
                  exit(EXIT_FAILURE);
               }
            }

            if (transportWasSet == false)
            {
               basics_log("whiteholes.transport required\n");
               exit(EXIT_FAILURE);
            }

            if (familyWasSet == false)
            {
               basics_log("whiteholes.family required\n");
               exit(EXIT_FAILURE);
            }

            if (sourceWasSet == false)
            {
               basics_log("whiteholes.source required\n");
               exit(EXIT_FAILURE);
            }

            if (need.source != ExternalAddressSource::hostPublicAddress
               && need.source != ExternalAddressSource::distributableSubnet)
            {
               basics_log("whiteholes currently require source == hostPublicAddress or distributableSubnet\n");
               exit(EXIT_FAILURE);
            }

            plan.whiteholes.push_back(need);
         }
      }
      else if (key.equal("externalAddressNeeds"_ctv))
      {
         basics_log("externalAddressNeeds removed; use whiteholes on DeploymentPlan\n");
         exit(EXIT_FAILURE);
      }
      else if (key.equal("requiresPublic6"_ctv) || key.equal("requiresPublic4"_ctv))
      {
         basics_log("%.*s removed; use whiteholes on DeploymentPlan\n", int(key.size()), key.data());
         exit(EXIT_FAILURE);
      }
      else if (key.equal("useHostNetworkNamespace"_ctv))
      {
         String failure;
         if (mothershipParseDeploymentPlanUseHostNetworkNamespace(field.value, plan, &failure) == false)
         {
            basics_log("%s\n", failure.c_str());
            exit(EXIT_FAILURE);
         }
			}
			else if (key.equal("subscriptions"_ctv))
			{
				if (field.value.type() != simdjson::dom::element_type::ARRAY)
				{
					basics_log("subscriptions requires an array\n");
					exit(EXIT_FAILURE);
				}

					for (auto subfield : field.value.get_array())
					{
						if (subfield.type() != simdjson::dom::element_type::OBJECT)
						{
							basics_log("subscriptions requires Subscription array members\n");
							exit(EXIT_FAILURE);
						}

					Subscription subscription;

						for (auto item : subfield.get_object())
						{
						String key;
						key.setInvariant(item.key.data(), item.key.size());

						if (key.equal("service"_ctv)) // we need to create a queryable registry for this
						{
							if (item.value.type() != simdjson::dom::element_type::STRING)
							{
								basics_log("subscription.service requires a string\n");
								exit(EXIT_FAILURE);
							}

							auto rawValue = item.value.get_string();
							if (rawValue.error())
							{
								basics_log("subscription.service requires a string\n");
								exit(EXIT_FAILURE);
							}

							String value;
							value.assign(rawValue.value().data(), rawValue.value().size());
							if (debugDeploy)
							{
								basics_log("DEPLOY_DEBUG subscription.service_len=%llu\n", static_cast<unsigned long long>(value.size()));
								std::fflush(stdout);
							}

								if (socket.resolveServiceReference(value, subscription.service))
								{
									if (debugDeploy)
									{
										basics_log("DEPLOY_DEBUG subscription.service_resolved=%llu\n", static_cast<unsigned long long>(subscription.service));
										std::fflush(stdout);
									}
									// resolved
								}
								else
								{
								basics_log("subscription.service service provided invalid\n");
								exit(EXIT_FAILURE);
							}
						}
						else if (key.equal("startAt"_ctv)) // ContainerState
						{
							if (item.value.type() != simdjson::dom::element_type::STRING)
							{
								basics_log("subscription.startAt requires a string\n");
								exit(EXIT_FAILURE);
							}

							String value;
							value.setInvariant(item.value.get_c_str());

							if (value.equal("ContainerState::scheduled"_ctv))
							{
								subscription.startAt = ContainerState::scheduled;
							}
							else if (value.equal("ContainerState::healthy"_ctv))
							{
								subscription.startAt = ContainerState::healthy;
							}
							else
							{
								basics_log("subscription.startAt ContainerState provided invalid or not allowed\n");
								exit(EXIT_FAILURE);
							}
						}
						else if (key.equal("stopAt"_ctv)) // ContainerState
						{
							if (item.value.type() != simdjson::dom::element_type::STRING)
							{
								basics_log("subscription.stopAt requires a string\n");
								exit(EXIT_FAILURE);
							}

							String value;
							value.setInvariant(item.value.get_c_str());

							if (value.equal("ContainerState::healthy"_ctv))
							{
								subscription.stopAt = ContainerState::healthy;
							}
							else if (value.equal("ContainerState::aboutToDestroy"_ctv))
							{
								subscription.stopAt = ContainerState::aboutToDestroy;
							}
							else if (value.equal("ContainerState::destroying"_ctv))
							{
								subscription.stopAt = ContainerState::destroying;
							}
							else
							{
								basics_log("subscription.stopAt ContainerState provided invalid or not allowed\n");
								exit(EXIT_FAILURE);
							}
						}
						else if (key.equal("nature"_ctv)) // SubscriptionNature
						{
							if (item.value.type() != simdjson::dom::element_type::STRING)
							{
								basics_log("subscription.nature requires a string\n");
								exit(EXIT_FAILURE);
							}

							String value;
							value.setInvariant(item.value.get_c_str());

							if (value.equal("SubscriptionNature::any"_ctv))
							{
								subscription.nature = SubscriptionNature::any;
							}
							else if (value.equal("SubscriptionNature::exclusiveSome"_ctv))
							{
								subscription.nature = SubscriptionNature::exclusiveSome;
							}
							else if (value.equal("SubscriptionNature::all"_ctv))
							{
								subscription.nature = SubscriptionNature::all;
							}
							else
							{
								basics_log("subscription.nature SubscriptionNature provided invalid or not allowed\n");
								exit(EXIT_FAILURE);
							}
						}
					}

					if (subscription.service == 0)
					{
						basics_log("subscription requires service parameter\n");
						exit(EXIT_FAILURE);
					}

					if (uint64_t(subscription.startAt) == 0)
					{
						basics_log("subscription requires startAt parameter\n");
						exit(EXIT_FAILURE);
					}

					if (uint64_t(subscription.stopAt) == 0)
					{
						basics_log("subscription requires stopAt parameter\n");
						exit(EXIT_FAILURE);
					}

					if (uint8_t(subscription.nature) == 0)
					{
						basics_log("subscription requires nature parameter\n");
						exit(EXIT_FAILURE);
					}

						bool replacedSubscription = false;
						for (uint32_t i = 0; i < plan.subscriptions.size(); i++)
						{
							if (plan.subscriptions[i].service == subscription.service)
							{
								plan.subscriptions[i] = subscription;
								replacedSubscription = true;
								break;
							}
						}

						if (replacedSubscription == false)
						{
							plan.subscriptions.push_back(subscription);
						}
					}
				}
      else if (key.equal("advertisements"_ctv))
      {
        if (field.value.type() != simdjson::dom::element_type::ARRAY)
        {
          basics_log("advertisements requires an array\n");
          exit(EXIT_FAILURE);
        }

        for (auto subfield : field.value.get_array())
        {
          if (subfield.type() != simdjson::dom::element_type::OBJECT)
          {
            basics_log("advertisements requires Advertisement array members\n");
            exit(EXIT_FAILURE);
          }

          Advertisement advertisement;

          for (auto item : subfield.get_object())
          {
            String key;
            key.setInvariant(item.key.data(), item.key.size());

						if (key.equal("service"_ctv)) // we need to create a queryable registry for this
						{
              if (item.value.type() != simdjson::dom::element_type::STRING)
              {
                basics_log("advertisement.service requires a string\n");
                exit(EXIT_FAILURE);
              }

							auto rawValue = item.value.get_string();
							if (rawValue.error())
							{
								basics_log("advertisement.service requires a string\n");
								exit(EXIT_FAILURE);
							}

							String value;
							value.assign(rawValue.value().data(), rawValue.value().size());
							if (debugDeploy)
							{
								basics_log("DEPLOY_DEBUG advertisement.service_len=%llu\n", static_cast<unsigned long long>(value.size()));
								std::fflush(stdout);
							}

								if (socket.resolveServiceReference(value, advertisement.service))
								{
									if (debugDeploy)
									{
										basics_log("DEPLOY_DEBUG advertisement.service_resolved=%llu\n", static_cast<unsigned long long>(advertisement.service));
										std::fflush(stdout);
									}
									// resolved
								}
								else
								{
								basics_log("advertisement.service service provided invalid\n");
                exit(EXIT_FAILURE);
              }
            }
            else if (key.equal("startAt"_ctv))
            {
              if (item.value.type() != simdjson::dom::element_type::STRING)
              {
                basics_log("advertisement.startAt requires a string\n");
                exit(EXIT_FAILURE);
              }

							String value;
							value.setInvariant(item.value.get_c_str());

							if (value.equal("ContainerState::scheduled"_ctv))
							{
								advertisement.startAt = ContainerState::scheduled;
							}
							else if (value.equal("ContainerState::healthy"_ctv))
							{
								advertisement.startAt = ContainerState::healthy;
							}
							else
							{
								basics_log("advertisement.startAt ContainerState provided invalid or not allowed\n");
                exit(EXIT_FAILURE);
              }
            }
            else if (key.equal("stopAt"_ctv))
            {
              if (item.value.type() != simdjson::dom::element_type::STRING)
              {
                basics_log("advertisement.stopAt requires a string\n");
                exit(EXIT_FAILURE);
              }

							String value;
							value.setInvariant(item.value.get_c_str());

							if (value.equal("ContainerState::healthy"_ctv))
							{
								advertisement.stopAt = ContainerState::healthy;
							}
							else if (value.equal("ContainerState::aboutToDestroy"_ctv))
							{
								advertisement.stopAt = ContainerState::aboutToDestroy;
							}
							else if (value.equal("ContainerState::destroying"_ctv))
							{
								advertisement.stopAt = ContainerState::destroying;
							}
							else
							{
								basics_log("advertisement.stopAt ContainerState provided invalid or not allowed\n");
                exit(EXIT_FAILURE);
              }
            }
            else if (key.equal("port"_ctv))
            {
              if (item.value.type() != simdjson::dom::element_type::INT64)
              {
                basics_log("advertisement.port requires an integer\n");
                exit(EXIT_FAILURE);
              }

              int64_t value = 0;
              (void)item.value.get(value);

							if (value > 0 && value < UINT16_MAX)
							{
								advertisement.port = uint16_t(value);
							}
							else
							{
								basics_log("advertisement.port value invalid\n");
                exit(EXIT_FAILURE);
              }
            }
            else if (key.equal("userCapacity"_ctv))
            {
               String failure;
               String context;
               context.assign("advertisement.userCapacity"_ctv);
               if (mothershipParseServiceUserCapacity(item.value, advertisement.userCapacity, context, &failure) == false)
               {
                  basics_log("%s\n", failure.c_str());
                  exit(EXIT_FAILURE);
               }
            }
          }

          if (advertisement.service == 0)
          {
            basics_log("advertisement requires service parameter\n");
            exit(EXIT_FAILURE);
          }

          if (uint64_t(advertisement.startAt) == 0)
          {
            basics_log("advertisement requires startAt parameter\n");
            exit(EXIT_FAILURE);
          }

          if (uint64_t(advertisement.stopAt) == 0)
          {
            basics_log("advertisement requires stopAt parameter\n");
            exit(EXIT_FAILURE);
          }

          if (advertisement.port == 0)
          {
            basics_log("advertisement requires port parameter\n");
            exit(EXIT_FAILURE);
          }

						bool replacedAdvertisement = false;
						for (uint32_t i = 0; i < plan.advertisements.size(); i++)
						{
							if (plan.advertisements[i].service == advertisement.service)
							{
								plan.advertisements[i] = advertisement;
								replacedAdvertisement = true;
								break;
							}
						}

						if (replacedAdvertisement == false)
						{
							plan.advertisements.push_back(advertisement);
						}
					}
				}
      else if (key.equal("moveConstructively"_ctv))
      {
        if (field.value.type() != simdjson::dom::element_type::BOOL)
        {
          basics_log("moveConstructively requires a bool\n");
          exit(EXIT_FAILURE);
        }

        {
          bool b = false;
          (void)field.value.get(b);
          plan.moveConstructively = b;
        }
      }
      else if (key.equal("requiresDatacenterUniqueTag"_ctv))
      {
        if (field.value.type() != simdjson::dom::element_type::BOOL)
        {
          basics_log("requiresDatacenterUniqueTag requires a bool\n");
          exit(EXIT_FAILURE);
        }

        {
          bool b = false;
          (void)field.value.get(b);
          plan.requiresDatacenterUniqueTag = b;
        }
			}
			else
			{
				basics_log("invalid DeploymentPlan field\n");
				exit(EXIT_FAILURE);
			}

					}

         if (plan.config.nLogicalCores == 0)
         {
            basics_log("ApplicationConfig is required\n");
            exit(EXIT_FAILURE);
         }

         if (plan.config.applicationID == MeshRegistry::Radar::applicationID && plan.config.nLogicalCores < radarMinimumLogicalCores)
         {
            basics_log("Radar requires config.nLogicalCores >= %u\n", radarMinimumLogicalCores);
            exit(EXIT_FAILURE);
         }

			if (plan.wormholes.size() > 0)
			{
				if (plan.isStateful)
				{
					basics_log("wormholes require stateless applications\n");
					exit(EXIT_FAILURE);
				}

            for (const Wormhole& wormhole : plan.wormholes)
            {
               if (wormhole.source != ExternalAddressSource::distributableSubnet
                  && wormhole.source != ExternalAddressSource::registeredRoutableAddress)
               {
                  basics_log("wormholes currently require source == distributableSubnet or registeredRoutableAddress\n");
                  exit(EXIT_FAILURE);
               }

               if (wormhole.source == ExternalAddressSource::registeredRoutableAddress && wormhole.routableAddressUUID == 0)
               {
                  basics_log("wormholes with source == registeredRoutableAddress require routableAddressUUID\n");
                  exit(EXIT_FAILURE);
               }

               if (wormhole.isQuic && wormhole.layer4 != IPPROTO_UDP)
               {
                  basics_log("wormholes with isQuic require layer4 == UDP\n");
                  exit(EXIT_FAILURE);
               }
            }
			}

         if (plan.whiteholes.size() > 0)
         {
            for (const Whitehole& whitehole : plan.whiteholes)
            {
               if (whitehole.source != ExternalAddressSource::hostPublicAddress
                  && whitehole.source != ExternalAddressSource::distributableSubnet)
               {
                  basics_log("whiteholes currently require source == hostPublicAddress or distributableSubnet\n");
                  exit(EXIT_FAILURE);
               }
            }
         }

         if (plan.isStateful)
         {
            if (plan.stateless.nBase > 0)
            {
               basics_log("isStateful but provided StatelessDeploymentPlan\n");
               exit(EXIT_FAILURE);
            }
         }
         else
         {
            if (plan.stateful.clientPrefix > 0)
            {
               basics_log("isStateful == false but provided StatefulDeploymentPlan\n");
               exit(EXIT_FAILURE);
            }
         }

					if (plan.hasTlsIssuancePolicy)
					{
						if (plan.tlsIssuancePolicy.applicationID != plan.config.applicationID)
						{
							basics_log("tls.applicationID must match config.applicationID\n");
							exit(EXIT_FAILURE);
						}
					}

					if (plan.hasApiCredentialPolicy)
					{
						if (plan.apiCredentialPolicy.applicationID != plan.config.applicationID)
						{
							basics_log("apiCredentials.applicationID must match config.applicationID\n");
							exit(EXIT_FAILURE);
						}

						if (plan.apiCredentialPolicy.requiredCredentialNames.size() == 0)
						{
							basics_log("apiCredentials.requiredCredentialNames required\n");
							exit(EXIT_FAILURE);
						}
					}

					for (HorizontalScaler& scaler : plan.horizontalScalers)
					{
						if (scaler.minValue == 0)
						{
							// Default floor keeps stateless base counts at-or-above the initially requested base.
							if (plan.isStateful == false && scaler.lifetime == ApplicationLifetime::base)
							{
								scaler.minValue = plan.stateless.nBase;
							}
						}

						if (scaler.maxValue > 0 && scaler.minValue > scaler.maxValue)
						{
							basics_log("config.horizontalScalers minValue cannot exceed maxValue\n");
							exit(EXIT_FAILURE);
						}
					}

					for (VerticalScaler& scaler : plan.verticalScalers)
					{
						uint32_t requested = 0;

						switch (scaler.resource)
						{
							case ScalingDimension::cpu:
							{
								requested = plan.config.nLogicalCores;
								break;
							}
							case ScalingDimension::memory:
							{
								requested = plan.config.memoryMB;
								break;
							}
							case ScalingDimension::storage:
							{
								requested = plan.config.storageMB;
								break;
							}
							case ScalingDimension::runtimeIngressQueueWaitComposite:
							case ScalingDimension::runtimeIngressHandlerComposite:
							{
								basics_log("verticalScalers.resource only supports cpu/memory/storage dimensions\n");
								exit(EXIT_FAILURE);
							}
						}

						if (scaler.minValue == 0)
						{
							// Default floor keeps vertical downscale at-or-above initially requested resources.
							scaler.minValue = requested;
						}

						if (scaler.maxValue > 0 && scaler.minValue > scaler.maxValue)
						{
							basics_log("config.verticalScalers minValue cannot exceed maxValue\n");
							exit(EXIT_FAILURE);
						}

						switch (scaler.resource)
						{
							case ScalingDimension::cpu:
							{
								if (plan.config.nLogicalCores < scaler.minValue || (scaler.maxValue > 0 && plan.config.nLogicalCores > scaler.maxValue))
								{
									basics_log("config.nLogicalCores must be within verticalScalers minValue/maxValue bounds\n");
									exit(EXIT_FAILURE);
								}
								break;
							}
							case ScalingDimension::memory:
							{
								if (plan.config.memoryMB < scaler.minValue || (scaler.maxValue > 0 && plan.config.memoryMB > scaler.maxValue))
								{
									basics_log("config.memoryMB must be within verticalScalers minValue/maxValue bounds\n");
									exit(EXIT_FAILURE);
								}
								break;
							}
							case ScalingDimension::storage:
							{
								if (plan.config.storageMB < scaler.minValue || (scaler.maxValue > 0 && plan.config.storageMB > scaler.maxValue))
								{
									basics_log("config.storageMB must be within verticalScalers minValue/maxValue bounds\n");
									exit(EXIT_FAILURE);
								}
								break;
							}
							case ScalingDimension::runtimeIngressQueueWaitComposite:
							case ScalingDimension::runtimeIngressHandlerComposite:
							{
								basics_log("verticalScalers.resource only supports cpu/memory/storage dimensions\n");
								exit(EXIT_FAILURE);
							}
						}
					}

					if (plan.isStateful)
					{
						for (const HorizontalScaler& scaler : plan.horizontalScalers)
						{
							if (scaler.direction == Scaler::Direction::downscale)
							{
								basics_log("stateful deployments cannot set horizontalScalers.direction=downscale\n");
								exit(EXIT_FAILURE);
							}
						}

						for (const VerticalScaler& scaler : plan.verticalScalers)
						{
							if (scaler.direction == Scaler::Direction::downscale)
							{
								basics_log("stateful deployments cannot set verticalScalers.direction=downscale\n");
								exit(EXIT_FAILURE);
							}
						}
					}

				// they have to first build the container then pass us the filepath to the compressed blob
				String containerPath;
				containerPath.assign(argv[2]);

		if (Filesystem::fileExists(containerPath) == false)
		{
			basics_log("no file exists at containerPath provided\n");
			exit(EXIT_FAILURE);
		}

		if (prodigyIsZstdFile(containerPath) == false)
		{
			basics_log("file provided is not a zstd file\n");
			exit(EXIT_FAILURE);
		}

      if (std::strcmp(argv[0], "local") != 0)
      {
         MothershipClusterRegistry clusterRegistry = openClusterRegistry();
         MothershipProdigyCluster targetCluster = {};
         String lookupFailure = {};
         String clusterIdentity = {};
         clusterIdentity.setInvariant(argv[0]);
         if (clusterRegistry.getClusterByIdentity(clusterIdentity, targetCluster, &lookupFailure))
         {
            if (targetCluster.architecture != MachineCpuArchitecture::unknown
               && plan.config.architecture != targetCluster.architecture)
            {
               basics_log("config.architecture '%s' does not match cluster architecture '%s'\n",
                  machineCpuArchitectureName(plan.config.architecture),
                  machineCpuArchitectureName(targetCluster.architecture));
               exit(EXIT_FAILURE);
            }
         }
      }

		debugLog("plan_validated");

		// we could decompress it and test if it's a btrfs subvolume but.. just don't fuck with us lol
		// zstd -d /path/to/file.zstd -o /path/to/output
		// btrfs receive /path/to/mount/point < /path/to/decompressed/file

		if (socket.ensureConnected())
		{
		debugLog("socket_connected");
		// first measure the application against the cluster to make sure it fits
                  // Reserve for serialized plan
                  socket.wBuffer.reserve(socket.wBuffer.size() + 1024);
                  uint32_t headerOffset = Message::appendHeader(socket.wBuffer, MothershipTopic::measureApplication);
			Message::serializeAndAppendObject(socket.wBuffer, plan);
			Message::finish(socket.wBuffer, headerOffset);
			debugLog("measure_serialized");

			if (socket.send() == false) exit(EXIT_FAILURE);
			debugLog("measure_sent");

			if (Message *response = socket.recvExpectedTopic(MothershipTopic::measureApplication); response)
			{
				debugLog("measure_received");
				if (MothershipTopic(response->topic) != MothershipTopic::measureApplication)
				{
					basics_log("measureApplication failed: unexpected response topic %u\n", response->topic);
					exit(EXIT_FAILURE);
				}

				uint8_t *args = response->args;

				// nBase(4) nSurge(4) nFit(4)

				uint32_t nBase;
				Message::extractArg<ArgumentNature::fixed>(args, nBase);

				uint32_t nSurge;
				Message::extractArg<ArgumentNature::fixed>(args, nSurge);

				uint32_t nFit;
				Message::extractArg<ArgumentNature::fixed>(args, nFit);

				// nFit -> we can fit this many

				// nBase  -> we would schedule this many base
				// nSurge -> we would schedule this many surge

				uint32_t nNeeded = nBase + nSurge;

				if (nFit < nNeeded)
				{
					basics_log("we would need to schedule %u base instances and %u surge instances, but the cluster can only fit %u total instances", nBase, nSurge, nFit);
					exit(EXIT_FAILURE);
				}
				else
				{
					basics_log("we will schedule %u base instances and %u surge instances", nBase, nSurge);
				}
			}
			else exit(EXIT_FAILURE);

                  // Reserve for plan + file contents size header
                  socket.wBuffer.reserve(socket.wBuffer.size() + 1024);
	                  uint32_t spinHeaderOffset = Message::appendHeader(socket.wBuffer, MothershipTopic::spinApplication);
				Message::append(socket.wBuffer, plan.config.applicationID);
				Message::serializeAndAppendObject(socket.wBuffer, plan);
				debugLog("spin_plan_serialized");
				Message::appendFile(socket.wBuffer, containerPath);
				debugLog("spin_blob_appended");
				Message::finish(socket.wBuffer, spinHeaderOffset);

			if (socket.send() == false) exit(EXIT_FAILURE);
			debugLog("spin_sent");

			if (Message *response = socket.recvExpectedTopic(MothershipTopic::spinApplication); response)
			{
				debugLog("spin_received");
				uint8_t *args = response->args;

				uint8_t responseCode;
				Message::extractArg<ArgumentNature::fixed>(args, responseCode);
				String responseMessage;
				if (args != response->terminal())
				{
					Message::extractToStringView(args, responseMessage);
				}
				bool spinAccepted = false;

				switch (SpinApplicationResponseCode(responseCode))
				{
					case SpinApplicationResponseCode::invalidPlan:
					{
						if (responseMessage.size() > 0)
						{
							basics_log("%s\n", responseMessage.c_str());
						}
						basics_log("SpinApplicationResponseCode::invalidPlan\n");
						break;
					}
					case SpinApplicationResponseCode::okay:
					{
						basics_log("SpinApplicationResponseCode::okay\n");
						spinAccepted = true;
						break;
					}
					default:
					{
						basics_log("deploy failed: unexpected initial spinApplication frame %u\n", responseCode);
						break;
					}
				}

				if (!spinAccepted)
				{
					exit(EXIT_FAILURE);
				}

				// Dev and test harnesses validate readiness with active probes. Do not
				// block the CLI on the terminal spinApplication frame there.
				if (returnAfterInitialSpinOkay)
				{
					socket.close();
					return;
				}
			}
			else exit(EXIT_FAILURE);

			bool finished = false;

			do // loop until we get the terminal spinApplication frame
			{
				Message *response = socket.recvExpectedTopic(MothershipTopic::spinApplication);

				if (response == nullptr) exit(EXIT_FAILURE);

				uint8_t *args = response->args;

				uint8_t responseCode;
				Message::extractArg<ArgumentNature::fixed>(args, responseCode);

				switch (SpinApplicationResponseCode(responseCode))
				{
					case SpinApplicationResponseCode::progress:
					{
						String message;
						if (args != response->terminal())
						{
							Message::extractToStringView(args, message);
						}

						if (message.size() > 0)
						{
							basics_log("%s\n", message.c_str());
						}
						break;
					}
					case SpinApplicationResponseCode::failed:
					{
						basics_log("SpinApplicationResponseCode::failed\n");
						String message;
						if (args != response->terminal())
						{
							Message::extractToStringView(args, message);
						}
						if (message.size() > 0)
						{
							basics_log("%s\n", message.c_str());
						}
						exit(EXIT_FAILURE);
					}
					case SpinApplicationResponseCode::finished:
					{
						finished = true;
						break;
					}
					case SpinApplicationResponseCode::invalidPlan:
					{
						basics_log("SpinApplicationResponseCode::invalidPlan\n");
						String message;
						if (args != response->terminal())
						{
							Message::extractToStringView(args, message);
						}
						if (message.size() > 0)
						{
							basics_log("%s\n", message.c_str());
						}
						exit(EXIT_FAILURE);
					}
					case SpinApplicationResponseCode::okay:
					default: break;
				}

			} while (!finished);

			socket.close();
		}
		else
		{
			exit(EXIT_FAILURE);
		}
		}
	void runApplicationReport(int argc, char *argv[])
	{
		if (argc < 2)
		{
			basics_log("too few arguments. ex: applicationReport [target: local|clusterName|clusterUUID] [application name]\n");
			exit(EXIT_FAILURE);
		}

		if (configureControlTarget(argv[0]) == false)
		{
			exit(EXIT_FAILURE);
		}

		String name;
		name.setInvariant(argv[1]);

		uint16_t applicationID = 0;
		ApplicationIDReserveRequest request;
		request.applicationName = name;
		request.createIfMissing = false;

		ApplicationIDReserveResponse response;
		if (socket.requestApplicationID(request, response) && response.success && response.applicationID != 0)
		{
			applicationID = response.applicationID;
		}
		else if (auto it = MeshRegistry::applicationIDMappings.find(name); it != MeshRegistry::applicationIDMappings.end())
		{
			applicationID = it->second;
		}
		else
		{
			basics_log("application name does not exist in reserved application registry\n");
			exit(EXIT_FAILURE);
		}

		if (socket.ensureConnected())
		{
			Message::construct(socket.wBuffer, MothershipTopic::pullApplicationReport, applicationID);

			if (socket.send() == false) exit(EXIT_FAILURE);

			if (Message *response = socket.recvExpectedTopic(MothershipTopic::pullApplicationReport); response)
			{
				if (MothershipTopic(response->topic) != MothershipTopic::pullApplicationReport)
				{
					basics_log("applicationReport failed: unexpected response topic %u\n", response->topic);
					exit(EXIT_FAILURE);
				}

				uint8_t *args = response->args;

				String serializedReport;
				Message::extractToStringView(args, serializedReport);

				ApplicationStatusReport report;
            if (BitseryEngine::deserializeSafe(serializedReport, report) == false)
            {
               basics_log("applicationReport failed: invalid report payload\n");
               exit(EXIT_FAILURE);
				}

					String stringified;
					report.stringify(stringified);

					if (stringified.size() > 0)
					{
						std::fwrite(stringified.c_str(), 1, stringified.size(), stdout);
					}
					exit(EXIT_SUCCESS);
			}
			else exit(EXIT_FAILURE);
		}
		else
		{
			exit(EXIT_FAILURE);
		}
	}

   bool parseProviderCredentialJSON(simdjson::dom::element doc, MothershipProviderCredential& request, const char *context, bool requireName)
   {
      if (doc.type() != simdjson::dom::element_type::OBJECT)
      {
         basics_log("%s requires object json\n", context);
         return false;
      }

      for (auto field : doc.get_object())
      {
         String key;
         key.setInvariant(field.key.data(), field.key.size());

         if (key.equal("name"_ctv))
         {
            if (field.value.type() != simdjson::dom::element_type::STRING)
            {
               basics_log("%s.name requires string\n", context);
               return false;
            }

            request.name.assign(field.value.get_c_str());
         }
         else if (key.equal("provider"_ctv))
         {
            if (field.value.type() != simdjson::dom::element_type::STRING)
            {
               basics_log("%s.provider requires string\n", context);
               return false;
            }

            String provider;
            provider.setInvariant(field.value.get_c_str());
            if (parseMothershipClusterProvider(provider, request.provider) == false)
            {
               basics_log("%s.provider invalid\n", context);
               return false;
            }
         }
         else if (key.equal("mode"_ctv))
         {
            if (field.value.type() != simdjson::dom::element_type::STRING)
            {
               basics_log("%s.mode requires string\n", context);
               return false;
            }

            String mode = {};
            mode.setInvariant(field.value.get_c_str());
            if (parseMothershipProviderCredentialMode(mode, request.mode) == false)
            {
               basics_log("%s.mode invalid\n", context);
               return false;
            }
         }
         else if (key.equal("material"_ctv))
         {
            if (field.value.type() != simdjson::dom::element_type::STRING)
            {
               basics_log("%s.material requires string\n", context);
               return false;
            }

            request.material.assign(field.value.get_c_str());
         }
         else if (key.equal("impersonateServiceAccount"_ctv))
         {
            if (field.value.type() != simdjson::dom::element_type::STRING)
            {
               basics_log("%s.impersonateServiceAccount requires string\n", context);
               return false;
            }

            request.impersonateServiceAccount.assign(field.value.get_c_str());
         }
         else if (key.equal("credentialPath"_ctv))
         {
            if (field.value.type() != simdjson::dom::element_type::STRING)
            {
               basics_log("%s.credentialPath requires string\n", context);
               return false;
            }

            request.credentialPath.assign(field.value.get_c_str());
         }
         else if (key.equal("scope"_ctv))
         {
            if (field.value.type() != simdjson::dom::element_type::STRING)
            {
               basics_log("%s.scope requires string\n", context);
               return false;
            }

            request.scope.assign(field.value.get_c_str());
         }
         else if (key.equal("allowPropagateToProdigy"_ctv))
         {
            if (field.value.type() != simdjson::dom::element_type::BOOL)
            {
               basics_log("%s.allowPropagateToProdigy requires bool\n", context);
               return false;
            }

            bool value = false;
            if (field.value.get(value) != simdjson::SUCCESS)
            {
               basics_log("%s.allowPropagateToProdigy invalid\n", context);
               return false;
            }

            request.allowPropagateToProdigy = value;
         }
         else
         {
            basics_log("%s invalid field\n", context);
            return false;
         }
      }

      if (requireName && request.name.size() == 0)
      {
         basics_log("%s.name requires string\n", context);
         return false;
      }

      return true;
   }

   bool parseCloudIDArrayJSON(simdjson::dom::element doc, Vector<String>& cloudIDs, const char *context)
   {
      cloudIDs.clear();

      simdjson::dom::array array;
      if (doc.get(array) != simdjson::SUCCESS)
      {
         basics_log("%s requires json array\n", context);
         return false;
      }

      for (simdjson::dom::element item : array)
      {
         std::string_view value;
         if (item.get(value) != simdjson::SUCCESS)
         {
            basics_log("%s elements require string\n", context);
            return false;
         }

         String cloudID = {};
         cloudID.assign(value);
         if (cloudID.size() == 0)
         {
            basics_log("%s cloudID requires non-empty string\n", context);
            return false;
         }

         cloudIDs.push_back(cloudID);
      }

      if (cloudIDs.size() == 0)
      {
         basics_log("%s requires at least one cloudID\n", context);
         return false;
      }

      return true;
   }

   bool parseStringArrayJSON(simdjson::dom::element doc, Vector<String>& values, const char *context)
   {
      values.clear();

      if (doc.type() != simdjson::dom::element_type::ARRAY)
      {
         basics_log("%s requires an array\n", context);
         return false;
      }

      for (auto item : doc.get_array())
      {
         if (item.type() != simdjson::dom::element_type::STRING)
         {
            basics_log("%s requires string members\n", context);
            return false;
         }

         String value = {};
         value.assign(item.get_c_str());
         if (value.size() == 0)
         {
            basics_log("%s contains empty string\n", context);
            return false;
         }

         values.push_back(value);
      }

      return true;
   }

   bool parsePricingProviderCredentialOverrideJSON(
      simdjson::dom::element doc,
      MothershipProviderScopeTarget::PricingProviderCredentialOverride& credential,
      const char *context)
   {
      if (doc.type() != simdjson::dom::element_type::OBJECT)
      {
         basics_log("%s requires object json\n", context);
         return false;
      }

      for (auto field : doc.get_object())
      {
         String key;
         key.setInvariant(field.key.data(), field.key.size());

         if (key.equal("provider"_ctv))
         {
            if (field.value.type() != simdjson::dom::element_type::STRING)
            {
               basics_log("%s.provider requires string\n", context);
               return false;
            }

            String provider;
            provider.setInvariant(field.value.get_c_str());
            if (parseMothershipClusterProvider(provider, credential.provider) == false)
            {
               basics_log("%s.provider invalid\n", context);
               return false;
            }
         }
         else if (key.equal("material"_ctv))
         {
            if (field.value.type() != simdjson::dom::element_type::STRING)
            {
               basics_log("%s.material requires string\n", context);
               return false;
            }

            credential.material.assign(field.value.get_c_str());
         }
         else if (key.equal("scope"_ctv))
         {
            if (field.value.type() != simdjson::dom::element_type::STRING)
            {
               basics_log("%s.scope requires string\n", context);
               return false;
            }

            credential.scope.assign(field.value.get_c_str());
         }
         else
         {
            String failure = {};
            String contextText = {};
            contextText.assign(context);
            failure.snprintf<"{}.{} is not supported for pricing"_ctv>(contextText, key);
            basics_log("%s\n", failure.c_str());
            return false;
         }
      }

      return true;
   }

   bool parsePricingScopeTargetJSON(simdjson::dom::element doc, MothershipProviderScopeTarget& target, const char *context)
   {
      if (doc.type() != simdjson::dom::element_type::OBJECT)
      {
         basics_log("%s requires object json\n", context);
         return false;
      }

      for (auto field : doc.get_object())
      {
         String key = {};
         key.setInvariant(field.key.data(), field.key.size());

         if (key.equal("provider"_ctv))
         {
            if (field.value.type() != simdjson::dom::element_type::STRING)
            {
               basics_log("%s.provider requires string\n", context);
               return false;
            }

            String providerText = {};
            providerText.setInvariant(field.value.get_c_str());
            if (parseMothershipClusterProvider(providerText, target.provider) == false || target.provider == MothershipClusterProvider::unknown)
            {
               basics_log("%s.provider invalid\n", context);
               return false;
            }
         }
         else if (key.equal("providerScope"_ctv))
         {
            if (field.value.type() != simdjson::dom::element_type::STRING)
            {
               basics_log("%s.providerScope requires string\n", context);
               return false;
            }

            target.providerScope.assign(field.value.get_c_str());
         }
         else if (key.equal("providerCredentialName"_ctv))
         {
            if (field.value.type() != simdjson::dom::element_type::STRING)
            {
               basics_log("%s.providerCredentialName requires string\n", context);
               return false;
            }

            target.providerCredentialName.assign(field.value.get_c_str());
         }
         else if (key.equal("providerCredentialOverride"_ctv))
         {
            String overrideContext = {};
            String contextText = {};
            contextText.assign(context);
            overrideContext.snprintf<"{}.providerCredentialOverride"_ctv>(contextText);
            if (parsePricingProviderCredentialOverrideJSON(field.value, target.providerCredentialOverride, overrideContext.c_str()) == false)
            {
               return false;
            }

            target.hasProviderCredentialOverride = true;
         }
         else
         {
            basics_log("%s invalid field\n", context);
            return false;
         }
      }

      if (target.provider == MothershipClusterProvider::unknown)
      {
         basics_log("%s.provider required\n", context);
         return false;
      }

      if (target.providerScope.size() == 0 && target.hasProviderCredentialOverride && target.providerCredentialOverride.scope.size() > 0)
      {
         target.providerScope = target.providerCredentialOverride.scope;
      }

      if (target.providerScope.size() == 0)
      {
         basics_log("%s.providerScope required\n", context);
         return false;
      }

      if (target.providerCredentialName.size() == 0 && target.hasProviderCredentialOverride == false)
      {
         basics_log("%s.providerCredentialName or providerCredentialOverride required\n", context);
         return false;
      }

      return true;
   }

   bool parsePricingScopeTargetsJSON(simdjson::dom::element doc, Vector<MothershipProviderScopeTarget>& targets, const char *context)
   {
      targets.clear();
      String contextText = {};
      contextText.assign(context);

      if (doc.type() != simdjson::dom::element_type::ARRAY)
      {
         basics_log("%s requires an array\n", context);
         return false;
      }

      uint32_t index = 0;
      for (auto item : doc.get_array())
      {
         MothershipProviderScopeTarget target = {};
         String itemContext = {};
         itemContext.snprintf<"{}[{itoa}]"_ctv>(contextText, index);
         if (parsePricingScopeTargetJSON(item, target, itemContext.c_str()) == false)
         {
            return false;
         }

         targets.push_back(target);
         index += 1;
      }

      if (targets.empty())
      {
         basics_log("%s requires at least one target\n", context);
         return false;
      }

      return true;
   }

   void appendPricingTargetFailure(Vector<String>& targetFailures, const MothershipProviderScopeTarget& target, const String& failure)
   {
      String line = {};
      String provider = {};
      provider.assign(mothershipClusterProviderName(target.provider));
      line.snprintf<"provider={} providerScope={} failure={}"_ctv>(
         provider,
         target.providerScope.size() ? target.providerScope : "<none>"_ctv,
         failure.size() ? failure : "<unknown>"_ctv);
      targetFailures.push_back(line);
   }

   bool collectPricingTargets(
      const String& requestedCountry,
      const Vector<MothershipClusterProvider>& requestedProviders,
      const Vector<String>& requestedCredentialNames,
      const Vector<MothershipProviderScopeTarget>& explicitTargets,
      Vector<MothershipProviderScopeTarget>& activeTargets,
      MothershipPricingResolvedTargets& diagnostics,
      uint32_t& countryFilteredTargets,
      Vector<String>& targetFailures)
   {
      activeTargets.clear();
      diagnostics = MothershipPricingResolvedTargets();
      countryFilteredTargets = 0;
      targetFailures.clear();

      Vector<MothershipProviderScopeTarget> candidateTargets = {};
      if (explicitTargets.empty() == false)
      {
         candidateTargets = explicitTargets;
      }
      else if (mothershipResolveStoredPricingTargets(requestedProviders, requestedCredentialNames, diagnostics) == false)
      {
         return false;
      }
      else
      {
         candidateTargets = diagnostics.targets;
      }

      for (const MothershipProviderScopeTarget& target : candidateTargets)
      {
         String resolvedScope = {};
         String resolvedCountry = {};
         String failure = {};
         if (mothershipResolveScopeCountry(target.provider, target.providerScope, resolvedScope, resolvedCountry, &failure) == false)
         {
            appendPricingTargetFailure(targetFailures, target, failure);
            continue;
         }

         if (providerCountriesMatch(resolvedCountry, requestedCountry) == false)
         {
            countryFilteredTargets += 1;
            continue;
         }

         activeTargets.push_back(target);
      }

      return true;
   }

   static void printPricingDiagnostics(
      MothershipPricingResolvedTargets& diagnostics,
      uint32_t countryFilteredTargets,
      Vector<String>& targetFailures)
   {
      for (MothershipClusterProvider provider : diagnostics.missingCredentialProviders)
      {
         basics_log("  missingCredentialProvider=%s\n", mothershipClusterProviderName(provider));
      }

      for (MothershipClusterProvider provider : diagnostics.unsupportedProviders)
      {
         basics_log("  unsupportedProvider=%s\n", mothershipClusterProviderName(provider));
      }

      for (String& skipped : diagnostics.skippedCredentialNames)
      {
         basics_log("  skippedCredential=%s\n", skipped.c_str());
      }

      if (countryFilteredTargets > 0)
      {
         basics_log("  countryFilteredTargets=%u\n", countryFilteredTargets);
      }

      for (String& failure : targetFailures)
      {
         basics_log("  targetFailure=%s\n", failure.c_str());
      }
   }

   void collectProviderMachineCloudIDs(BrainIaaS& provider, const String& metro, Vector<String>& cloudIDs)
   {
      cloudIDs.clear();

      bytell_hash_set<Machine *> machines = {};
      provider.getMachines(nullptr, metro, machines);

      for (Machine *machine : machines)
      {
         if (machine != nullptr && machine->cloudID.size() > 0)
         {
            cloudIDs.push_back(machine->cloudID);
         }

         delete machine;
      }
   }

   void runCreateProviderCredential(int argc, char *argv[])
   {
      if (argc < 1)
      {
         basics_log("too few arguments. ex: createProviderCredential [json]\n");
         exit(EXIT_FAILURE);
      }

      MothershipProviderCredential request = {};

      String json;
      json.append(argv[0]);
      json.need(simdjson::SIMDJSON_PADDING);

      simdjson::dom::parser parser;
      simdjson::dom::element doc;
      if (parser.parse(json.data(), json.size()).get(doc))
      {
         basics_log("invalid json for createProviderCredential\n");
         exit(EXIT_FAILURE);
      }

      if (parseProviderCredentialJSON(doc, request, "createProviderCredential", true) == false)
      {
         exit(EXIT_FAILURE);
      }

      String failure;
      MothershipProviderCredential stored = {};
      MothershipProviderCredentialRegistry providerCredentialRegistry = openProviderCredentialRegistry();
      if (providerCredentialRegistry.createCredential(request, &stored, &failure) == false)
      {
         basics_log("createProviderCredential success=0 failure=%s\n", (failure.size() ? failure.c_str() : ""));
         exit(EXIT_FAILURE);
      }

      basics_log("createProviderCredential success=1 created=1\n");
      printProviderCredential(stored);
   }

   void runPullProviderCredential(int argc, char *argv[])
   {
      if (argc < 1)
      {
         basics_log("too few arguments. ex: pullProviderCredential [name]\n");
         exit(EXIT_FAILURE);
      }

      String name;
      name.assign(argv[0]);
      if (name.size() == 0)
      {
         basics_log("pullProviderCredential.name required\n");
         exit(EXIT_FAILURE);
      }

      String failure;
      MothershipProviderCredential credential = {};
      MothershipProviderCredentialRegistry providerCredentialRegistry = openProviderCredentialRegistry();
      if (providerCredentialRegistry.getCredential(name, credential, &failure) == false)
      {
         basics_log("pullProviderCredential success=0 name=%s failure=%s\n", name.c_str(), (failure.size() ? failure.c_str() : ""));
         exit(EXIT_FAILURE);
      }

      basics_log("pullProviderCredential success=1\n");
      printProviderCredential(credential);
   }

   void runPullProviderCredentials(int argc, char *argv[])
   {
      if (argc > 0)
      {
         basics_log("too many arguments. ex: pullProviderCredentials\n");
         exit(EXIT_FAILURE);
      }

      String failure;
      Vector<MothershipProviderCredential> credentials;
      MothershipProviderCredentialRegistry providerCredentialRegistry = openProviderCredentialRegistry();
      if (providerCredentialRegistry.listCredentials(credentials, &failure) == false)
      {
         basics_log("pullProviderCredentials success=0 failure=%s\n", (failure.size() ? failure.c_str() : ""));
         exit(EXIT_FAILURE);
      }

      basics_log("pullProviderCredentials success=1 count=%u\n", unsigned(credentials.size()));
      for (const MothershipProviderCredential& credential : credentials)
      {
         printProviderCredential(credential);
      }
   }

   void runRemoveProviderCredential(int argc, char *argv[])
   {
      if (argc < 1)
      {
         basics_log("too few arguments. ex: removeProviderCredential [name]\n");
         exit(EXIT_FAILURE);
      }

      String name;
      name.assign(argv[0]);
      if (name.size() == 0)
      {
         basics_log("removeProviderCredential.name required\n");
         exit(EXIT_FAILURE);
      }

      String failure;
      String referencingClusterName;
      bool referenced = providerCredentialReferencedByClusters(name, failure, &referencingClusterName);
      if (referenced)
      {
         failure.assign("provider credential is still referenced by cluster "_ctv);
         failure.append(referencingClusterName);
         basics_log("removeProviderCredential success=0 removed=0 name=%s failure=%s\n", name.c_str(), failure.c_str());
         exit(EXIT_FAILURE);
      }

      if (failure.size() > 0)
      {
         basics_log("removeProviderCredential success=0 removed=0 name=%s failure=%s\n", name.c_str(), failure.c_str());
         exit(EXIT_FAILURE);
      }

      MothershipProviderCredentialRegistry providerCredentialRegistry = openProviderCredentialRegistry();
      if (providerCredentialRegistry.removeCredential(name, &failure) == false)
      {
         basics_log("removeProviderCredential success=0 removed=0 name=%s failure=%s\n", name.c_str(), (failure.size() ? failure.c_str() : ""));
         exit(EXIT_FAILURE);
      }

      basics_log("removeProviderCredential success=1 removed=1 name=%s\n", name.c_str());
   }

   void runDestroyProviderMachines(int argc, char *argv[])
   {
      if (argc < 4)
      {
         basics_log("too few arguments. ex: destroyProviderMachines [provider] [providerCredentialName|providerCredentialOverride json] [providerScope] [json array of cloudIDs]\n");
         exit(EXIT_FAILURE);
      }

      String providerText = {};
      providerText.assign(argv[0]);
      String providerCredentialRef = {};
      providerCredentialRef.assign(argv[1]);
      String providerScope = {};
      providerScope.assign(argv[2]);

      if (providerText.size() == 0)
      {
         basics_log("destroyProviderMachines.provider required\n");
         exit(EXIT_FAILURE);
      }

      if (providerCredentialRef.size() == 0)
      {
         basics_log("destroyProviderMachines.providerCredentialName or providerCredentialOverride required\n");
         exit(EXIT_FAILURE);
      }

      if (providerScope.size() == 0)
      {
         basics_log("destroyProviderMachines.providerScope required\n");
         exit(EXIT_FAILURE);
      }

      MothershipClusterProvider providerKind = MothershipClusterProvider::unknown;
      if (parseMothershipClusterProvider(providerText, providerKind) == false || providerKind == MothershipClusterProvider::unknown)
      {
         basics_log("destroyProviderMachines.provider invalid\n");
         exit(EXIT_FAILURE);
      }

      String json = {};
      json.append(argv[3]);
      json.need(simdjson::SIMDJSON_PADDING);

      simdjson::dom::parser parser;
      simdjson::dom::element doc;
      if (parser.parse(json.data(), json.size()).get(doc))
      {
         basics_log("invalid json for destroyProviderMachines\n");
         exit(EXIT_FAILURE);
      }

      Vector<String> cloudIDs = {};
      if (parseCloudIDArrayJSON(doc, cloudIDs, "destroyProviderMachines.cloudIDs") == false)
      {
         exit(EXIT_FAILURE);
      }

      String failure = {};
      MothershipProviderCredential credential = {};
      String resolvedProviderCredentialName = {};
      bool inlineCredential = providerCredentialRef.size() > 0 && providerCredentialRef[0] == '{';
      if (inlineCredential)
      {
         String credentialJSON = {};
         credentialJSON.assign(providerCredentialRef);
         credentialJSON.need(simdjson::SIMDJSON_PADDING);

         simdjson::dom::parser credentialParser;
         simdjson::dom::element credentialDoc;
         if (credentialParser.parse(credentialJSON.data(), credentialJSON.size()).get(credentialDoc))
         {
            basics_log("invalid json for destroyProviderMachines.providerCredentialOverride\n");
            exit(EXIT_FAILURE);
         }

         if (parseProviderCredentialJSON(credentialDoc, credential, "destroyProviderMachines.providerCredentialOverride", false) == false)
         {
            exit(EXIT_FAILURE);
         }

         resolvedProviderCredentialName.assign("inline"_ctv);
      }
      else
      {
         MothershipProviderCredentialRegistry providerCredentialRegistry = openProviderCredentialRegistry();
         if (providerCredentialRegistry.getCredential(providerCredentialRef, credential, &failure) == false)
         {
            basics_log("destroyProviderMachines success=0 destroyed=0 failure=%s\n", (failure.size() ? failure.c_str() : ""));
            exit(EXIT_FAILURE);
         }

         resolvedProviderCredentialName = providerCredentialRef;
      }

      if (credential.provider != providerKind)
      {
         basics_log("destroyProviderMachines success=0 destroyed=0 failure=providerCredentialName provider does not match requested provider\n");
         exit(EXIT_FAILURE);
      }

      ProdigyRuntimeEnvironmentConfig runtimeEnvironment = {};
      if (mothershipMapClusterProviderEnvironment(providerKind, runtimeEnvironment.kind) == false)
      {
         basics_log("destroyProviderMachines success=0 destroyed=0 failure=unsupported provider\n");
         exit(EXIT_FAILURE);
      }

      runtimeEnvironment.providerScope = providerScope;
      if (MothershipProviderCredentialRegistry::applyCredentialToRuntimeEnvironment(credential, runtimeEnvironment, &failure) == false)
      {
         basics_log("destroyProviderMachines success=0 destroyed=0 failure=%s\n", (failure.size() ? failure.c_str() : ""));
         exit(EXIT_FAILURE);
      }

      std::unique_ptr<BrainIaaS> provider = prodigyCreateProviderBrainIaaS(runtimeEnvironment);
      if (provider == nullptr)
      {
         basics_log("destroyProviderMachines success=0 destroyed=0 failure=failed to construct provider iaas\n");
         exit(EXIT_FAILURE);
      }

      provider->configureRuntimeEnvironment(runtimeEnvironment);

      if (mothershipDestroyProviderMachines(*provider, cloudIDs, &failure) == false)
      {
         basics_log("destroyProviderMachines success=0 destroyed=0 failure=%s\n", (failure.size() ? failure.c_str() : ""));
         exit(EXIT_FAILURE);
      }

      Vector<String> visibleCloudIDs = {};
      bool pendingDestroy = true;
      for (uint32_t attempt = 0; attempt < 30 && pendingDestroy; ++attempt)
      {
         collectProviderMachineCloudIDs(*provider, providerScope, visibleCloudIDs);
         pendingDestroy = false;

         for (const String& requestedCloudID : cloudIDs)
         {
            for (const String& visibleCloudID : visibleCloudIDs)
            {
               if (visibleCloudID.equals(requestedCloudID))
               {
                  pendingDestroy = true;
                  break;
               }
            }

            if (pendingDestroy)
            {
               break;
            }
         }

         if (pendingDestroy)
         {
            usleep(2 * 1000 * 1000);
         }
      }

      if (pendingDestroy)
      {
         basics_log("destroyProviderMachines success=0 destroyed=0 failure=timed out waiting for provider machines to disappear from inventory\n");
         basics_log("  remainingVisibleCloudIDs=%u\n", unsigned(visibleCloudIDs.size()));
         for (const String& cloudID : visibleCloudIDs)
         {
            String cloudIDText = {};
            cloudIDText.assign(cloudID);
            basics_log("  visibleCloudID=%s\n", cloudIDText.c_str());
         }
         exit(EXIT_FAILURE);
      }

      basics_log("destroyProviderMachines success=1 destroyed=%u provider=%s providerCredentialName=%s providerScope=%s\n",
         unsigned(cloudIDs.size()),
         providerText.c_str(),
         resolvedProviderCredentialName.c_str(),
         providerScope.c_str());

      for (const String& cloudID : cloudIDs)
      {
         String cloudIDText = {};
         cloudIDText.assign(cloudID);
         basics_log("  cloudID=%s\n", cloudIDText.c_str());
      }
   }

   void runDestroyProviderClusterMachines(int argc, char *argv[])
   {
      if (argc < 4)
      {
         basics_log("too few arguments. ex: destroyProviderClusterMachines [provider] [providerCredentialName|providerCredentialOverride json] [providerScope] [clusterUUID]\n");
         exit(EXIT_FAILURE);
      }

      String providerText = {};
      providerText.assign(argv[0]);
      String providerCredentialRef = {};
      providerCredentialRef.assign(argv[1]);
      String providerScope = {};
      providerScope.assign(argv[2]);
      String clusterUUID = {};
      clusterUUID.assign(argv[3]);

      if (providerText.size() == 0)
      {
         basics_log("destroyProviderClusterMachines.provider required\n");
         exit(EXIT_FAILURE);
      }

      if (providerCredentialRef.size() == 0)
      {
         basics_log("destroyProviderClusterMachines.providerCredentialName or providerCredentialOverride required\n");
         exit(EXIT_FAILURE);
      }

      if (providerScope.size() == 0)
      {
         basics_log("destroyProviderClusterMachines.providerScope required\n");
         exit(EXIT_FAILURE);
      }

      if (clusterUUID.size() == 0)
      {
         basics_log("destroyProviderClusterMachines.clusterUUID required\n");
         exit(EXIT_FAILURE);
      }

      MothershipClusterProvider providerKind = MothershipClusterProvider::unknown;
      if (parseMothershipClusterProvider(providerText, providerKind) == false || providerKind == MothershipClusterProvider::unknown)
      {
         basics_log("destroyProviderClusterMachines.provider invalid\n");
         exit(EXIT_FAILURE);
      }

      String failure = {};
      MothershipProviderCredential credential = {};
      String resolvedProviderCredentialName = {};
      bool inlineCredential = providerCredentialRef.size() > 0 && providerCredentialRef[0] == '{';
      if (inlineCredential)
      {
         String credentialJSON = {};
         credentialJSON.assign(providerCredentialRef);
         credentialJSON.need(simdjson::SIMDJSON_PADDING);

         simdjson::dom::parser credentialParser;
         simdjson::dom::element credentialDoc;
         if (credentialParser.parse(credentialJSON.data(), credentialJSON.size()).get(credentialDoc))
         {
            basics_log("invalid json for destroyProviderClusterMachines.providerCredentialOverride\n");
            exit(EXIT_FAILURE);
         }

         if (parseProviderCredentialJSON(credentialDoc, credential, "destroyProviderClusterMachines.providerCredentialOverride", false) == false)
         {
            exit(EXIT_FAILURE);
         }

         resolvedProviderCredentialName.assign("inline"_ctv);
      }
      else
      {
         MothershipProviderCredentialRegistry providerCredentialRegistry = openProviderCredentialRegistry();
         if (providerCredentialRegistry.getCredential(providerCredentialRef, credential, &failure) == false)
         {
            basics_log("destroyProviderClusterMachines success=0 destroyed=0 failure=%s\n", (failure.size() ? failure.c_str() : ""));
            exit(EXIT_FAILURE);
         }

         resolvedProviderCredentialName = providerCredentialRef;
      }

      if (credential.provider != providerKind)
      {
         basics_log("destroyProviderClusterMachines success=0 destroyed=0 failure=providerCredentialName provider does not match requested provider\n");
         exit(EXIT_FAILURE);
      }

      ProdigyRuntimeEnvironmentConfig runtimeEnvironment = {};
      if (mothershipMapClusterProviderEnvironment(providerKind, runtimeEnvironment.kind) == false)
      {
         basics_log("destroyProviderClusterMachines success=0 destroyed=0 failure=unsupported provider\n");
         exit(EXIT_FAILURE);
      }

      runtimeEnvironment.providerScope = providerScope;
      if (MothershipProviderCredentialRegistry::applyCredentialToRuntimeEnvironment(credential, runtimeEnvironment, &failure) == false)
      {
         basics_log("destroyProviderClusterMachines success=0 destroyed=0 failure=%s\n", (failure.size() ? failure.c_str() : ""));
         exit(EXIT_FAILURE);
      }

      std::unique_ptr<BrainIaaS> provider = prodigyCreateProviderBrainIaaS(runtimeEnvironment);
      if (provider == nullptr)
      {
         basics_log("destroyProviderClusterMachines success=0 destroyed=0 failure=failed to construct provider iaas\n");
         exit(EXIT_FAILURE);
      }

      provider->configureRuntimeEnvironment(runtimeEnvironment);

      uint32_t destroyed = 0;
      if (mothershipDestroyProviderClusterMachines(*provider, clusterUUID, destroyed, &failure) == false)
      {
         basics_log("destroyProviderClusterMachines success=0 destroyed=0 failure=%s\n", (failure.size() ? failure.c_str() : ""));
         exit(EXIT_FAILURE);
      }

      basics_log("destroyProviderClusterMachines success=1 destroyed=%u provider=%s providerCredentialName=%s providerScope=%s clusterUUID=%s\n",
         destroyed,
         providerText.c_str(),
         resolvedProviderCredentialName.c_str(),
         providerScope.c_str(),
         clusterUUID.c_str());
   }

   void runSurveyProviderMachineOffers(int argc, char *argv[])
   {
      if (argc < 1)
      {
         basics_log("too few arguments. ex: surveyProviderMachineOffers [json]\n");
         exit(EXIT_FAILURE);
      }

      MothershipProviderOfferSurveyRequest request = {};
      bool sawCountry = false;
      bool sawBillingModel = false;
      bool sawProviders = false;
      bool allProviders = false;
      Vector<MothershipClusterProvider> requestedProviders = {};
      Vector<String> requestedCredentialNames = {};
      Vector<MothershipProviderScopeTarget> explicitTargets = {};

      String json = {};
      json.append(argv[0]);
      json.need(simdjson::SIMDJSON_PADDING);

      simdjson::dom::parser parser;
      simdjson::dom::element doc;
      if (parser.parse(json.data(), json.size()).get(doc))
      {
         basics_log("invalid json for surveyProviderMachineOffers\n");
         exit(EXIT_FAILURE);
      }

      if (doc.type() != simdjson::dom::element_type::OBJECT)
      {
         basics_log("surveyProviderMachineOffers requires object json\n");
         exit(EXIT_FAILURE);
      }

      for (auto field : doc.get_object())
      {
         String key = {};
         key.setInvariant(field.key.data(), field.key.size());

         if (key.equal("country"_ctv))
         {
            if (field.value.type() != simdjson::dom::element_type::STRING)
            {
               basics_log("surveyProviderMachineOffers.country requires string\n");
               exit(EXIT_FAILURE);
            }

            request.country.assign(field.value.get_c_str());
            sawCountry = true;
         }
         else if (key.equal("billingModel"_ctv))
         {
            if (field.value.type() != simdjson::dom::element_type::STRING)
            {
               basics_log("surveyProviderMachineOffers.billingModel requires string\n");
               exit(EXIT_FAILURE);
            }

            String text = {};
            text.setInvariant(field.value.get_c_str());
            if (parseProviderMachineBillingModel(text, request.billingModel) == false)
            {
               basics_log("surveyProviderMachineOffers.billingModel invalid\n");
               exit(EXIT_FAILURE);
            }

            sawBillingModel = true;
         }
         else if (key.equal("providers"_ctv))
         {
            String failure = {};
            if (mothershipParsePricingProvidersJSON(field.value, requestedProviders, allProviders, &failure) == false)
            {
               basics_log("surveyProviderMachineOffers.%s\n", failure.c_str());
               exit(EXIT_FAILURE);
            }

            if (allProviders)
            {
               requestedProviders.clear();
            }
            sawProviders = true;
         }
         else if (key.equal("providerCredentialNames"_ctv))
         {
            if (parseStringArrayJSON(field.value, requestedCredentialNames, "surveyProviderMachineOffers.providerCredentialNames") == false)
            {
               exit(EXIT_FAILURE);
            }
         }
         else if (key.equal("targets"_ctv))
         {
            if (parsePricingScopeTargetsJSON(field.value, explicitTargets, "surveyProviderMachineOffers.targets") == false)
            {
               exit(EXIT_FAILURE);
            }
         }
         else if (key.equal("machineKinds"_ctv))
         {
            String failure = {};
            if (mothershipParsePricingMachineKindsJSON(field.value, request.machineKindsMask, &failure) == false)
            {
               basics_log("surveyProviderMachineOffers.%s\n", failure.c_str());
               exit(EXIT_FAILURE);
            }
         }
         else if (key.equal("requireFreeTierEligible"_ctv))
         {
            if (field.value.type() != simdjson::dom::element_type::BOOL || field.value.get(request.requireFreeTierEligible) != simdjson::SUCCESS)
            {
               basics_log("surveyProviderMachineOffers.requireFreeTierEligible requires bool\n");
               exit(EXIT_FAILURE);
            }
         }
         else if (key.equal("minLogicalCores"_ctv))
         {
            uint64_t value = 0;
            if ((field.value.type() != simdjson::dom::element_type::INT64 && field.value.type() != simdjson::dom::element_type::UINT64)
               || field.value.get(value) != simdjson::SUCCESS
               || value > UINT32_MAX)
            {
               basics_log("surveyProviderMachineOffers.minLogicalCores invalid\n");
               exit(EXIT_FAILURE);
            }

            request.minLogicalCores = uint32_t(value);
         }
         else if (key.equal("minMemoryGB"_ctv))
         {
            uint32_t memoryMB = 0;
            if (mothershipParseJSONSizeGBToMB(field.value, memoryMB) == false)
            {
               basics_log("surveyProviderMachineOffers.minMemoryGB invalid\n");
               exit(EXIT_FAILURE);
            }

            request.minMemoryMB = memoryMB;
         }
         else if (key.equal("minStorageGB"_ctv))
         {
            uint32_t storageMB = 0;
            if (mothershipParseJSONSizeGBToMB(field.value, storageMB) == false)
            {
               basics_log("surveyProviderMachineOffers.minStorageGB invalid\n");
               exit(EXIT_FAILURE);
            }

            request.minStorageMB = storageMB;
         }
         else if (key.equal("minGPUs"_ctv))
         {
            uint64_t value = 0;
            if ((field.value.type() != simdjson::dom::element_type::INT64 && field.value.type() != simdjson::dom::element_type::UINT64)
               || field.value.get(value) != simdjson::SUCCESS
               || value > UINT32_MAX)
            {
               basics_log("surveyProviderMachineOffers.minGPUs invalid\n");
               exit(EXIT_FAILURE);
            }

            request.minGPUs = uint32_t(value);
         }
         else if (key.equal("minGPUMemoryGB"_ctv))
         {
            uint64_t value = 0;
            if ((field.value.type() != simdjson::dom::element_type::INT64 && field.value.type() != simdjson::dom::element_type::UINT64)
               || field.value.get(value) != simdjson::SUCCESS
               || value > UINT32_MAX)
            {
               basics_log("surveyProviderMachineOffers.minGPUMemoryGB invalid\n");
               exit(EXIT_FAILURE);
            }

            request.minGPUMemoryGB = uint32_t(value);
         }
         else if (key.equal("minNICSpeedGbps"_ctv))
         {
            uint64_t value = 0;
            if ((field.value.type() != simdjson::dom::element_type::INT64 && field.value.type() != simdjson::dom::element_type::UINT64)
               || field.value.get(value) != simdjson::SUCCESS
               || value > UINT32_MAX)
            {
               basics_log("surveyProviderMachineOffers.minNICSpeedGbps invalid\n");
               exit(EXIT_FAILURE);
            }

            request.minNICSpeedGbps = uint32_t(value);
         }
         else if (key.equal("requireHostPublic4"_ctv))
         {
            if (field.value.type() != simdjson::dom::element_type::BOOL || field.value.get(request.requireHostPublic4) != simdjson::SUCCESS)
            {
               basics_log("surveyProviderMachineOffers.requireHostPublic4 requires bool\n");
               exit(EXIT_FAILURE);
            }
         }
         else if (key.equal("requireHostPublic6"_ctv))
         {
            if (field.value.type() != simdjson::dom::element_type::BOOL || field.value.get(request.requireHostPublic6) != simdjson::SUCCESS)
            {
               basics_log("surveyProviderMachineOffers.requireHostPublic6 requires bool\n");
               exit(EXIT_FAILURE);
            }
         }
         else
         {
            basics_log("surveyProviderMachineOffers invalid field\n");
            exit(EXIT_FAILURE);
         }
      }

      if (sawCountry == false || request.country.size() == 0)
      {
         basics_log("surveyProviderMachineOffers.country required\n");
         exit(EXIT_FAILURE);
      }

      if (sawBillingModel == false)
      {
         basics_log("surveyProviderMachineOffers.billingModel required\n");
         exit(EXIT_FAILURE);
      }

      if (explicitTargets.empty() == false && (sawProviders || requestedCredentialNames.empty() == false))
      {
         basics_log("surveyProviderMachineOffers may specify targets or providers/providerCredentialNames, not both\n");
         exit(EXIT_FAILURE);
      }

      MothershipPricingResolvedTargets diagnostics = {};
      Vector<MothershipProviderScopeTarget> activeTargets = {};
      uint32_t countryFilteredTargets = 0;
      Vector<String> targetFailures = {};
      if (collectPricingTargets(request.country, requestedProviders, requestedCredentialNames, explicitTargets, activeTargets, diagnostics, countryFilteredTargets, targetFailures) == false)
      {
         String failure = "failed to resolve provider credentials"_ctv;
         basics_log("surveyProviderMachineOffers success=0 count=0 failure=%s missingCredentialProviders=%u unsupportedProviders=%u skippedCredentials=%u targetFailures=%u\n",
            failure.c_str(),
            unsigned(diagnostics.missingCredentialProviders.size()),
            unsigned(diagnostics.unsupportedProviders.size()),
            unsigned(diagnostics.skippedCredentialNames.size()),
            unsigned(targetFailures.size()));
         printPricingDiagnostics(diagnostics, countryFilteredTargets, targetFailures);
         exit(EXIT_FAILURE);
      }

      Vector<MothershipProviderMachineOffer> offers = {};
      for (const MothershipProviderScopeTarget& target : activeTargets)
      {
         MothershipProviderOfferSurveyRequest targetRequest = request;
         targetRequest.target = target;
         Vector<MothershipProviderMachineOffer> targetOffers = {};
         String failure = {};
         if (mothershipSurveyProviderMachineOffers(targetRequest, targetOffers, failure) == false)
         {
            appendPricingTargetFailure(targetFailures, target, failure);
            continue;
         }

         for (const MothershipProviderMachineOffer& offer : targetOffers)
         {
            offers.push_back(offer);
         }
      }

      std::sort(offers.begin(), offers.end(), [] (const MothershipProviderMachineOffer& a, const MothershipProviderMachineOffer& b) -> bool {
         if (a.hourlyMicrousd != b.hourlyMicrousd)
         {
            return a.hourlyMicrousd < b.hourlyMicrousd;
         }

         if (a.provider != b.provider)
         {
            return uint8_t(a.provider) < uint8_t(b.provider);
         }

         if (a.kind != b.kind)
         {
            return uint8_t(a.kind) < uint8_t(b.kind);
         }

         return mothershipStringLess(a.providerMachineType, b.providerMachineType);
      });

      if (offers.empty())
      {
         String failure = {};
         if (activeTargets.empty())
         {
            failure.assign("no provider scopes resolved for requested country"_ctv);
         }
         else
         {
            failure.assign("no offers matched the request"_ctv);
         }

         basics_log("surveyProviderMachineOffers success=0 count=0 failure=%s missingCredentialProviders=%u unsupportedProviders=%u skippedCredentials=%u targetFailures=%u\n",
            failure.c_str(),
            unsigned(diagnostics.missingCredentialProviders.size()),
            unsigned(diagnostics.unsupportedProviders.size()),
            unsigned(diagnostics.skippedCredentialNames.size()),
            unsigned(targetFailures.size()));
         printPricingDiagnostics(diagnostics, countryFilteredTargets, targetFailures);
         exit(EXIT_FAILURE);
      }

      basics_log("surveyProviderMachineOffers success=1 count=%u country=%s billingModel=%s missingCredentialProviders=%u unsupportedProviders=%u skippedCredentials=%u targetFailures=%u\n",
         unsigned(offers.size()),
         request.country.c_str(),
         providerMachineBillingModelName(request.billingModel),
         unsigned(diagnostics.missingCredentialProviders.size()),
         unsigned(diagnostics.unsupportedProviders.size()),
         unsigned(diagnostics.skippedCredentialNames.size()),
         unsigned(targetFailures.size()));
      printPricingDiagnostics(diagnostics, countryFilteredTargets, targetFailures);

      for (MothershipProviderMachineOffer& offer : offers)
      {
         basics_log("  provider=%s providerScope=%s country=%s region=%s zone=%s type=%s kind=%s billingModel=%s freeTierEligible=%d computeHourlyUSD=%.6f extraStorageUSDPerGBHour=%.6f ingressUSDPerGB=%.6f egressUSDPerGB=%.6f priceCompleteness=%u cores=%u memoryGB=%u storageGBDefault=%u gpuCount=%u gpuMemoryGBPerDevice=%u nicSpeedMbps=%u hostPublic4=%d hostPublic6=%d\n",
            mothershipClusterProviderName(offer.provider),
            offer.providerScope.c_str(),
            offer.country.c_str(),
            offer.region.c_str(),
            offer.zone.c_str(),
            offer.providerMachineType.c_str(),
            machineKindName(offer.kind),
            providerMachineBillingModelName(offer.billingModel),
            int(offer.freeTierEligible),
            mothershipMicrousdToUSD(offer.hourlyMicrousd),
            mothershipMicrousdToUSD(offer.extraStorageMicrousdPerGBHour),
            mothershipMicrousdToUSD(offer.ingressMicrousdPerGB),
            mothershipMicrousdToUSD(offer.egressMicrousdPerGB),
            unsigned(offer.priceCompleteness),
            unsigned(offer.nLogicalCores),
            unsigned(offer.nMemoryMB / 1024u),
            unsigned(offer.nStorageMBDefault / 1024u),
            unsigned(offer.gpuCount),
            unsigned(offer.gpuMemoryMBPerDevice / 1024u),
            unsigned(offer.nicSpeedMbps),
            int(offer.providesHostPublic4),
            int(offer.providesHostPublic6));
      }
   }

   void runEstimateClusterHourlyCost(int argc, char *argv[])
   {
      if (argc < 1)
      {
         basics_log("too few arguments. ex: estimateClusterHourlyCost [json]\n");
         exit(EXIT_FAILURE);
      }

      MothershipClusterCostEstimateRequest request = {};
      bool sawCountry = false;
      bool sawBillingModel = false;
      bool sawTarget = false;
      bool sawMachines = false;

      String json = {};
      json.append(argv[0]);
      json.need(simdjson::SIMDJSON_PADDING);

      simdjson::dom::parser parser;
      simdjson::dom::element doc;
      if (parser.parse(json.data(), json.size()).get(doc))
      {
         basics_log("invalid json for estimateClusterHourlyCost\n");
         exit(EXIT_FAILURE);
      }

      if (doc.type() != simdjson::dom::element_type::OBJECT)
      {
         basics_log("estimateClusterHourlyCost requires object json\n");
         exit(EXIT_FAILURE);
      }

      for (auto field : doc.get_object())
      {
         String key = {};
         key.setInvariant(field.key.data(), field.key.size());

         if (key.equal("target"_ctv))
         {
            if (parsePricingScopeTargetJSON(field.value, request.target, "estimateClusterHourlyCost.target") == false)
            {
               exit(EXIT_FAILURE);
            }

            sawTarget = true;
         }
         else if (key.equal("country"_ctv))
         {
            if (field.value.type() != simdjson::dom::element_type::STRING)
            {
               basics_log("estimateClusterHourlyCost.country requires string\n");
               exit(EXIT_FAILURE);
            }

            request.country.assign(field.value.get_c_str());
            sawCountry = true;
         }
         else if (key.equal("billingModel"_ctv))
         {
            if (field.value.type() != simdjson::dom::element_type::STRING)
            {
               basics_log("estimateClusterHourlyCost.billingModel requires string\n");
               exit(EXIT_FAILURE);
            }

            String text = {};
            text.setInvariant(field.value.get_c_str());
            if (parseProviderMachineBillingModel(text, request.billingModel) == false)
            {
               basics_log("estimateClusterHourlyCost.billingModel invalid\n");
               exit(EXIT_FAILURE);
            }

            sawBillingModel = true;
         }
         else if (key.equal("ingressGBPerHour"_ctv))
         {
            String failure = {};
            if (mothershipParseUnsignedDecimalGBToMB(field.value, request.ingressMBPerHour, &failure, "estimateClusterHourlyCost.ingressGBPerHour"_ctv) == false)
            {
               basics_log("%s\n", failure.c_str());
               exit(EXIT_FAILURE);
            }
         }
         else if (key.equal("egressGBPerHour"_ctv))
         {
            String failure = {};
            if (mothershipParseUnsignedDecimalGBToMB(field.value, request.egressMBPerHour, &failure, "estimateClusterHourlyCost.egressGBPerHour"_ctv) == false)
            {
               basics_log("%s\n", failure.c_str());
               exit(EXIT_FAILURE);
            }
         }
         else if (key.equal("machines"_ctv))
         {
            String failure = {};
            if (mothershipParsePricingMachineSelectionsJSON(field.value, request.machines, &failure) == false)
            {
               basics_log("estimateClusterHourlyCost.%s\n", failure.c_str());
               exit(EXIT_FAILURE);
            }

            sawMachines = true;
         }
         else if (key.equal("applications"_ctv))
         {
            String failure = {};
            if (mothershipParsePricingPlanningApplicationsJSON(field.value, request.applications, &failure) == false)
            {
               basics_log("estimateClusterHourlyCost.%s\n", failure.c_str());
               exit(EXIT_FAILURE);
            }
         }
         else
         {
            basics_log("estimateClusterHourlyCost invalid field\n");
            exit(EXIT_FAILURE);
         }
      }

      if (sawTarget == false)
      {
         basics_log("estimateClusterHourlyCost.target required\n");
         exit(EXIT_FAILURE);
      }

      if (sawCountry == false || request.country.size() == 0)
      {
         basics_log("estimateClusterHourlyCost.country required\n");
         exit(EXIT_FAILURE);
      }

      if (sawBillingModel == false)
      {
         basics_log("estimateClusterHourlyCost.billingModel required\n");
         exit(EXIT_FAILURE);
      }

      if (sawMachines == false || request.machines.empty())
      {
         basics_log("estimateClusterHourlyCost.machines required\n");
         exit(EXIT_FAILURE);
      }

      String resolvedScope = {};
      String resolvedCountry = {};
      String failure = {};
      if (mothershipResolveScopeCountry(request.target.provider, request.target.providerScope, resolvedScope, resolvedCountry, &failure) == false)
      {
         basics_log("estimateClusterHourlyCost success=0 failure=%s\n", failure.c_str());
         exit(EXIT_FAILURE);
      }

      if (providerCountriesMatch(resolvedCountry, request.country) == false)
      {
         basics_log("estimateClusterHourlyCost success=0 failure=target providerScope does not match requested country\n");
         exit(EXIT_FAILURE);
      }

      MothershipProviderOfferSurveyRequest surveyRequest = {};
      surveyRequest.target = request.target;
      surveyRequest.country = request.country;
      surveyRequest.billingModel = request.billingModel;
      surveyRequest.machineKindsMask = providerMachineKindMaskAll();

      Vector<MothershipProviderMachineOffer> offers = {};
      if (mothershipSurveyProviderMachineOffers(surveyRequest, offers, failure) == false)
      {
         basics_log("estimateClusterHourlyCost success=0 failure=%s\n", failure.c_str());
         exit(EXIT_FAILURE);
      }

      MothershipClusterHourlyEstimate estimate = {};
      if (mothershipEstimateClusterHourlyCost(request, offers, estimate) == false)
      {
         basics_log("estimateClusterHourlyCost success=0 failure=%s\n", (estimate.failure.size() ? estimate.failure.c_str() : "estimate failed"));
         exit(EXIT_FAILURE);
      }

      basics_log("estimateClusterHourlyCost success=1 fits=%d provider=%s providerScope=%s country=%s billingModel=%s hourlyUSD=%.6f computeUSD=%.6f storageUSD=%.6f ingressUSD=%.6f egressUSD=%.6f totalMachines=%u failure=%s\n",
         int(estimate.fits),
         mothershipClusterProviderName(request.target.provider),
         request.target.providerScope.c_str(),
         request.country.c_str(),
         providerMachineBillingModelName(request.billingModel),
         mothershipMicrousdToUSD(estimate.hourlyMicrousd),
         mothershipMicrousdToUSD(estimate.computeHourlyMicrousd),
         mothershipMicrousdToUSD(estimate.storageHourlyMicrousd),
         mothershipMicrousdToUSD(estimate.ingressHourlyMicrousd),
         mothershipMicrousdToUSD(estimate.egressHourlyMicrousd),
         unsigned(estimate.totalMachines),
         (estimate.failure.size() ? estimate.failure.c_str() : ""));

      if (estimate.fits == false)
      {
         exit(EXIT_FAILURE);
      }
   }

   void runRecommendClusterForApplications(int argc, char *argv[])
   {
      if (argc < 1)
      {
         basics_log("too few arguments. ex: recommendClusterForApplications [json]\n");
         exit(EXIT_FAILURE);
      }

      MothershipClusterRecommendationRequest request = {};
      bool sawCountry = false;
      bool sawBillingModel = false;
      bool sawProviders = false;
      bool allProviders = false;
      Vector<MothershipClusterProvider> requestedProviders = {};
      Vector<String> requestedCredentialNames = {};
      Vector<MothershipProviderScopeTarget> explicitTargets = {};

      String json = {};
      json.append(argv[0]);
      json.need(simdjson::SIMDJSON_PADDING);

      simdjson::dom::parser parser;
      simdjson::dom::element doc;
      if (parser.parse(json.data(), json.size()).get(doc))
      {
         basics_log("invalid json for recommendClusterForApplications\n");
         exit(EXIT_FAILURE);
      }

      if (doc.type() != simdjson::dom::element_type::OBJECT)
      {
         basics_log("recommendClusterForApplications requires object json\n");
         exit(EXIT_FAILURE);
      }

      for (auto field : doc.get_object())
      {
         String key = {};
         key.setInvariant(field.key.data(), field.key.size());

         if (key.equal("country"_ctv))
         {
            if (field.value.type() != simdjson::dom::element_type::STRING)
            {
               basics_log("recommendClusterForApplications.country requires string\n");
               exit(EXIT_FAILURE);
            }

            request.country.assign(field.value.get_c_str());
            sawCountry = true;
         }
         else if (key.equal("billingModel"_ctv))
         {
            if (field.value.type() != simdjson::dom::element_type::STRING)
            {
               basics_log("recommendClusterForApplications.billingModel requires string\n");
               exit(EXIT_FAILURE);
            }

            String text = {};
            text.setInvariant(field.value.get_c_str());
            if (parseProviderMachineBillingModel(text, request.billingModel) == false)
            {
               basics_log("recommendClusterForApplications.billingModel invalid\n");
               exit(EXIT_FAILURE);
            }

            sawBillingModel = true;
         }
         else if (key.equal("providers"_ctv))
         {
            String failure = {};
            if (mothershipParsePricingProvidersJSON(field.value, requestedProviders, allProviders, &failure) == false)
            {
               basics_log("recommendClusterForApplications.%s\n", failure.c_str());
               exit(EXIT_FAILURE);
            }

            if (allProviders)
            {
               requestedProviders.clear();
            }
            sawProviders = true;
         }
         else if (key.equal("providerCredentialNames"_ctv))
         {
            if (parseStringArrayJSON(field.value, requestedCredentialNames, "recommendClusterForApplications.providerCredentialNames") == false)
            {
               exit(EXIT_FAILURE);
            }
         }
         else if (key.equal("targets"_ctv))
         {
            if (parsePricingScopeTargetsJSON(field.value, explicitTargets, "recommendClusterForApplications.targets") == false)
            {
               exit(EXIT_FAILURE);
            }
         }
         else if (key.equal("minMachines"_ctv))
         {
            uint64_t value = 0;
            if ((field.value.type() != simdjson::dom::element_type::INT64 && field.value.type() != simdjson::dom::element_type::UINT64)
               || field.value.get(value) != simdjson::SUCCESS
               || value == 0
               || value > UINT32_MAX)
            {
               basics_log("recommendClusterForApplications.minMachines invalid\n");
               exit(EXIT_FAILURE);
            }

            request.minMachines = uint32_t(value);
         }
         else if (key.equal("machineKinds"_ctv))
         {
            String failure = {};
            if (mothershipParsePricingMachineKindsJSON(field.value, request.machineKindsMask, &failure) == false)
            {
               basics_log("recommendClusterForApplications.%s\n", failure.c_str());
               exit(EXIT_FAILURE);
            }
         }
         else if (key.equal("budgetHourlyUSD"_ctv))
         {
            String failure = {};
            if (mothershipParseUnsignedDecimalUSDToMicrousd(field.value, request.budgetMicrousd, &failure, "recommendClusterForApplications.budgetHourlyUSD"_ctv) == false)
            {
               basics_log("%s\n", failure.c_str());
               exit(EXIT_FAILURE);
            }

            request.hasBudget = true;
         }
         else if (key.equal("ingressGBPerHour"_ctv))
         {
            String failure = {};
            if (mothershipParseUnsignedDecimalGBToMB(field.value, request.ingressMBPerHour, &failure, "recommendClusterForApplications.ingressGBPerHour"_ctv) == false)
            {
               basics_log("%s\n", failure.c_str());
               exit(EXIT_FAILURE);
            }
         }
         else if (key.equal("egressGBPerHour"_ctv))
         {
            String failure = {};
            if (mothershipParseUnsignedDecimalGBToMB(field.value, request.egressMBPerHour, &failure, "recommendClusterForApplications.egressGBPerHour"_ctv) == false)
            {
               basics_log("%s\n", failure.c_str());
               exit(EXIT_FAILURE);
            }
         }
         else if (key.equal("applications"_ctv))
         {
            String failure = {};
            if (mothershipParsePricingPlanningApplicationsJSON(field.value, request.applications, &failure) == false)
            {
               basics_log("recommendClusterForApplications.%s\n", failure.c_str());
               exit(EXIT_FAILURE);
            }
         }
         else
         {
            basics_log("recommendClusterForApplications invalid field\n");
            exit(EXIT_FAILURE);
         }
      }

      if (sawCountry == false || request.country.size() == 0)
      {
         basics_log("recommendClusterForApplications.country required\n");
         exit(EXIT_FAILURE);
      }

      if (sawBillingModel == false)
      {
         basics_log("recommendClusterForApplications.billingModel required\n");
         exit(EXIT_FAILURE);
      }

      if (request.minMachines == 0)
      {
         basics_log("recommendClusterForApplications.minMachines required\n");
         exit(EXIT_FAILURE);
      }

      if (request.applications.empty())
      {
         basics_log("recommendClusterForApplications.applications required\n");
         exit(EXIT_FAILURE);
      }

      if (explicitTargets.empty() == false && (sawProviders || requestedCredentialNames.empty() == false))
      {
         basics_log("recommendClusterForApplications may specify targets or providers/providerCredentialNames, not both\n");
         exit(EXIT_FAILURE);
      }

      MothershipPricingResolvedTargets diagnostics = {};
      Vector<MothershipProviderScopeTarget> activeTargets = {};
      uint32_t countryFilteredTargets = 0;
      Vector<String> targetFailures = {};
      if (collectPricingTargets(request.country, requestedProviders, requestedCredentialNames, explicitTargets, activeTargets, diagnostics, countryFilteredTargets, targetFailures) == false)
      {
         String failure = "failed to resolve provider credentials"_ctv;
         basics_log("recommendClusterForApplications success=0 found=0 failure=%s missingCredentialProviders=%u unsupportedProviders=%u skippedCredentials=%u targetFailures=%u\n",
            failure.c_str(),
            unsigned(diagnostics.missingCredentialProviders.size()),
            unsigned(diagnostics.unsupportedProviders.size()),
            unsigned(diagnostics.skippedCredentialNames.size()),
            unsigned(targetFailures.size()));
         printPricingDiagnostics(diagnostics, countryFilteredTargets, targetFailures);
         exit(EXIT_FAILURE);
      }

      bool foundAny = false;
      MothershipClusterRecommendation best = {};
      for (const MothershipProviderScopeTarget& target : activeTargets)
      {
         MothershipProviderOfferSurveyRequest surveyRequest = {};
         surveyRequest.target = target;
         surveyRequest.country = request.country;
         surveyRequest.billingModel = request.billingModel;
         surveyRequest.machineKindsMask = request.machineKindsMask;

         Vector<MothershipProviderMachineOffer> offers = {};
         String failure = {};
         if (mothershipSurveyProviderMachineOffers(surveyRequest, offers, failure) == false)
         {
            appendPricingTargetFailure(targetFailures, target, failure);
            continue;
         }

         MothershipClusterRecommendation candidate = {};
         if (mothershipRecommendClusterForApplications(request, offers, target, candidate) == false)
         {
            appendPricingTargetFailure(targetFailures, target, candidate.failure.size() ? candidate.failure : failure);
            continue;
         }

         bool better = false;
         if (foundAny == false)
         {
            better = true;
         }
         else if (best.withinBudget != candidate.withinBudget)
         {
            better = candidate.withinBudget;
         }
         else if (candidate.hourlyMicrousd < best.hourlyMicrousd)
         {
            better = true;
         }
         else if (candidate.hourlyMicrousd == best.hourlyMicrousd && candidate.totalMachines < best.totalMachines)
         {
            better = true;
         }
         else if (candidate.hourlyMicrousd == best.hourlyMicrousd
            && candidate.totalMachines == best.totalMachines
            && candidate.target.provider != best.target.provider)
         {
            better = uint8_t(candidate.target.provider) < uint8_t(best.target.provider);
         }

         if (better)
         {
            best = candidate;
            foundAny = true;
         }
      }

      if (foundAny == false)
      {
         String failure = {};
         if (activeTargets.empty())
         {
            failure.assign("no provider scopes resolved for requested country"_ctv);
         }
         else
         {
            failure.assign("no feasible cluster recommendation found"_ctv);
         }

         basics_log("recommendClusterForApplications success=0 found=0 failure=%s missingCredentialProviders=%u unsupportedProviders=%u skippedCredentials=%u targetFailures=%u\n",
            failure.c_str(),
            unsigned(diagnostics.missingCredentialProviders.size()),
            unsigned(diagnostics.unsupportedProviders.size()),
            unsigned(diagnostics.skippedCredentialNames.size()),
            unsigned(targetFailures.size()));
         printPricingDiagnostics(diagnostics, countryFilteredTargets, targetFailures);
         exit(EXIT_FAILURE);
      }

      basics_log("recommendClusterForApplications success=1 found=%d withinBudget=%d provider=%s providerScope=%s country=%s billingModel=%s hourlyUSD=%.6f computeUSD=%.6f storageUSD=%.6f ingressUSD=%.6f egressUSD=%.6f minMachines=%u totalMachines=%u machineSelectionCount=%u missingCredentialProviders=%u unsupportedProviders=%u skippedCredentials=%u targetFailures=%u\n",
         int(best.found),
         int(best.withinBudget),
         mothershipClusterProviderName(best.target.provider),
         best.target.providerScope.c_str(),
         best.country.c_str(),
         providerMachineBillingModelName(best.billingModel),
         mothershipMicrousdToUSD(best.hourlyMicrousd),
         mothershipMicrousdToUSD(best.computeHourlyMicrousd),
         mothershipMicrousdToUSD(best.storageHourlyMicrousd),
         mothershipMicrousdToUSD(best.ingressHourlyMicrousd),
         mothershipMicrousdToUSD(best.egressHourlyMicrousd),
         unsigned(request.minMachines),
         unsigned(best.totalMachines),
         unsigned(best.machineSelections.size()),
         unsigned(diagnostics.missingCredentialProviders.size()),
         unsigned(diagnostics.unsupportedProviders.size()),
         unsigned(diagnostics.skippedCredentialNames.size()),
         unsigned(targetFailures.size()));
      for (uint32_t index = 0; index < best.machineSelections.size(); ++index)
      {
         const MothershipMachineOfferSelection& selection = best.machineSelections[index];
         String providerMachineType = selection.providerMachineType;
         basics_log("recommendClusterForApplications.machineSelection index=%u providerMachineType=%s kind=%s count=%u storageGB=%u\n",
            unsigned(index),
            providerMachineType.c_str(),
            machineKindName(selection.kind),
            unsigned(selection.count),
            unsigned(selection.storageMB / 1024u));
      }
      printPricingDiagnostics(diagnostics, countryFilteredTargets, targetFailures);
   }

   void runCreateCluster(int argc, char *argv[])
   {
      if (argc < 1)
      {
         basics_log("too few arguments. ex: createCluster [json]\n");
         exit(EXIT_FAILURE);
      }

      MothershipProdigyCluster request = {};
      MothershipProviderCredential providerCredentialOverride = {};
      bool hasProviderCredentialOverride = false;

      String json;
      json.append(argv[0]);
      json.need(simdjson::SIMDJSON_PADDING);

      simdjson::dom::parser parser;
      simdjson::dom::element doc;
      if (parser.parse(json.data(), json.size()).get(doc))
      {
         basics_log("invalid json for createCluster\n");
         exit(EXIT_FAILURE);
      }

      if (doc.type() != simdjson::dom::element_type::OBJECT)
      {
         basics_log("createCluster requires object json\n");
         exit(EXIT_FAILURE);
      }

      for (auto field : doc.get_object())
      {
         String key;
         key.setInvariant(field.key.data(), field.key.size());

         if (key.equal("name"_ctv))
         {
            if (field.value.type() != simdjson::dom::element_type::STRING)
            {
               basics_log("createCluster.name requires string\n");
               exit(EXIT_FAILURE);
            }

            request.name.assign(field.value.get_c_str());
         }
         else if (key.equal("deploymentMode"_ctv))
         {
            if (field.value.type() != simdjson::dom::element_type::STRING)
            {
               basics_log("createCluster.deploymentMode requires string\n");
               exit(EXIT_FAILURE);
            }

            String deploymentMode;
            deploymentMode.setInvariant(field.value.get_c_str());
            if (parseMothershipClusterDeploymentMode(deploymentMode, request.deploymentMode) == false)
            {
               basics_log("createCluster.deploymentMode invalid\n");
               exit(EXIT_FAILURE);
            }
         }
         else if (key.equal("includeLocalMachine"_ctv))
         {
            if (field.value.type() != simdjson::dom::element_type::BOOL)
            {
               basics_log("createCluster.includeLocalMachine requires bool\n");
               exit(EXIT_FAILURE);
            }

            bool value = false;
            if (field.value.get(value) != simdjson::SUCCESS)
            {
               basics_log("createCluster.includeLocalMachine invalid\n");
               exit(EXIT_FAILURE);
            }

            request.includeLocalMachine = value;
         }
         else if (key.equal("provider"_ctv))
         {
            if (field.value.type() != simdjson::dom::element_type::STRING)
            {
               basics_log("createCluster.provider requires string\n");
               exit(EXIT_FAILURE);
            }

            String provider;
            provider.setInvariant(field.value.get_c_str());
            if (parseMothershipClusterProvider(provider, request.provider) == false)
            {
               basics_log("createCluster.provider invalid\n");
               exit(EXIT_FAILURE);
            }
         }
         else if (key.equal("architecture"_ctv))
         {
            if (field.value.type() != simdjson::dom::element_type::STRING)
            {
               basics_log("createCluster.architecture requires string\n");
               exit(EXIT_FAILURE);
            }

            String architecture = {};
            architecture.setInvariant(field.value.get_c_str());
            if (parseMachineCpuArchitecture(architecture, request.architecture) == false
               || prodigyMachineCpuArchitectureSupportedTarget(request.architecture) == false)
            {
               basics_log("createCluster.architecture must be x86_64, aarch64, or riscv64\n");
               exit(EXIT_FAILURE);
            }
         }
         else if (key.equal("providerCredentialName"_ctv))
         {
            if (field.value.type() != simdjson::dom::element_type::STRING)
            {
               basics_log("createCluster.providerCredentialName requires string\n");
               exit(EXIT_FAILURE);
            }

            request.providerCredentialName.assign(field.value.get_c_str());
         }
         else if (key.equal("providerCredentialOverride"_ctv))
         {
            if (parseProviderCredentialJSON(field.value, providerCredentialOverride, "createCluster.providerCredentialOverride", false) == false)
            {
               exit(EXIT_FAILURE);
            }

            hasProviderCredentialOverride = true;
         }
         else if (key.equal("providerScope"_ctv))
         {
            if (field.value.type() != simdjson::dom::element_type::STRING)
            {
               basics_log("createCluster.providerScope requires string\n");
               exit(EXIT_FAILURE);
            }

            request.providerScope.assign(field.value.get_c_str());
         }
         else if (key.equal("gcp"_ctv))
         {
            if (parseClusterGcpConfigJSON(field.value, request.gcp, "createCluster.gcp") == false)
            {
               exit(EXIT_FAILURE);
            }
         }
         else if (key.equal("aws"_ctv))
         {
            if (parseClusterAwsConfigJSON(field.value, request.aws, "createCluster.aws") == false)
            {
               exit(EXIT_FAILURE);
            }
         }
         else if (key.equal("azure"_ctv))
         {
            if (parseClusterAzureConfigJSON(field.value, request.azure, "createCluster.azure") == false)
            {
               exit(EXIT_FAILURE);
            }
         }
         else if (key.equal("propagateProviderCredentialToProdigy"_ctv))
         {
            if (field.value.type() != simdjson::dom::element_type::BOOL)
            {
               basics_log("createCluster.propagateProviderCredentialToProdigy requires bool\n");
               exit(EXIT_FAILURE);
            }

            bool value = false;
            if (field.value.get(value) != simdjson::SUCCESS)
            {
               basics_log("createCluster.propagateProviderCredentialToProdigy invalid\n");
               exit(EXIT_FAILURE);
            }

            request.propagateProviderCredentialToProdigy = value;
         }
         else if (key.equal("controls"_ctv))
         {
            if (field.value.type() != simdjson::dom::element_type::ARRAY)
            {
               basics_log("createCluster.controls requires array\n");
               exit(EXIT_FAILURE);
            }

            for (auto item : field.value.get_array())
            {
               if (item.type() != simdjson::dom::element_type::OBJECT)
               {
                  basics_log("createCluster.controls requires object members\n");
                  exit(EXIT_FAILURE);
               }

               MothershipProdigyClusterControl control = {};

               for (auto controlField : item.get_object())
               {
                  String controlKey;
                  controlKey.setInvariant(controlField.key.data(), controlField.key.size());

                  if (controlKey.equal("kind"_ctv))
                  {
                     if (controlField.value.type() != simdjson::dom::element_type::STRING)
                     {
                        basics_log("createCluster.controls[].kind requires string\n");
                        exit(EXIT_FAILURE);
                     }

                     String controlKind;
                     controlKind.setInvariant(controlField.value.get_c_str());
                     if (parseMothershipClusterControlKind(controlKind, control.kind) == false)
                     {
                        basics_log("createCluster.controls[].kind invalid\n");
                        exit(EXIT_FAILURE);
                     }
                  }
                  else if (controlKey.equal("path"_ctv))
                  {
                     if (controlField.value.type() != simdjson::dom::element_type::STRING)
                     {
                        basics_log("createCluster.controls[].path requires string\n");
                        exit(EXIT_FAILURE);
                     }

                     control.path.assign(controlField.value.get_c_str());
                  }
                  else
                  {
                     basics_log("createCluster.controls invalid field\n");
                     exit(EXIT_FAILURE);
                  }
               }

               request.controls.push_back(control);
            }
         }
         else if (key.equal("test"_ctv))
         {
            if (field.value.type() != simdjson::dom::element_type::OBJECT)
            {
               basics_log("createCluster.test requires object\n");
               exit(EXIT_FAILURE);
            }

            request.test.specified = true;

            for (auto testField : field.value.get_object())
            {
               String testKey;
               testKey.setInvariant(testField.key.data(), testField.key.size());

               if (testKey.equal("workspaceRoot"_ctv))
               {
                  if (testField.value.type() != simdjson::dom::element_type::STRING)
                  {
                     basics_log("createCluster.test.workspaceRoot requires string\n");
                     exit(EXIT_FAILURE);
                  }

                  request.test.workspaceRoot.assign(testField.value.get_c_str());
               }
               else if (testKey.equal("machineCount"_ctv))
               {
                  int64_t value = 0;
                  if (testField.value.type() != simdjson::dom::element_type::INT64
                     || testField.value.get(value) != simdjson::SUCCESS
                     || value < 0
                     || value > INT32_MAX)
                  {
                     basics_log("createCluster.test.machineCount invalid\n");
                     exit(EXIT_FAILURE);
                  }

                  request.test.machineCount = uint32_t(value);
               }
               else if (testKey.equal("brainBootstrapFamily"_ctv))
               {
                  if (testField.value.type() != simdjson::dom::element_type::STRING)
                  {
                     basics_log("createCluster.test.brainBootstrapFamily requires string\n");
                     exit(EXIT_FAILURE);
                  }

                  String family = {};
                  family.setInvariant(testField.value.get_c_str());
                  if (parseMothershipClusterTestBootstrapFamily(family, request.test.brainBootstrapFamily) == false)
                  {
                     basics_log("createCluster.test.brainBootstrapFamily invalid\n");
                     exit(EXIT_FAILURE);
                  }
               }
               else if (testKey.equal("enableFakeIpv4Boundary"_ctv))
               {
                  if (testField.value.type() != simdjson::dom::element_type::BOOL)
                  {
                     basics_log("createCluster.test.enableFakeIpv4Boundary requires bool\n");
                     exit(EXIT_FAILURE);
                  }

                  bool value = false;
                  if (testField.value.get(value) != simdjson::SUCCESS)
                  {
                     basics_log("createCluster.test.enableFakeIpv4Boundary invalid\n");
                     exit(EXIT_FAILURE);
                  }

                  request.test.enableFakeIpv4Boundary = value;
               }
               else if (testKey.equal("interContainerMTU"_ctv))
               {
                  uint64_t value = 0;
                  if ((testField.value.type() != simdjson::dom::element_type::INT64
                        && testField.value.type() != simdjson::dom::element_type::UINT64)
                     || testField.value.get(value) != simdjson::SUCCESS
                     || value > UINT32_MAX)
                  {
                     basics_log("createCluster.test.interContainerMTU invalid\n");
                     exit(EXIT_FAILURE);
                  }

                  request.test.interContainerMTU = uint32_t(value);
               }
               else if (testKey.equal("host"_ctv))
               {
                  if (testField.value.type() != simdjson::dom::element_type::OBJECT)
                  {
                     basics_log("createCluster.test.host requires object\n");
                     exit(EXIT_FAILURE);
                  }

                  for (auto hostField : testField.value.get_object())
                  {
                     String hostKey;
                     hostKey.setInvariant(hostField.key.data(), hostField.key.size());

                     if (hostKey.equal("mode"_ctv))
                     {
                        if (hostField.value.type() != simdjson::dom::element_type::STRING)
                        {
                           basics_log("createCluster.test.host.mode requires string\n");
                           exit(EXIT_FAILURE);
                        }

                        String mode = {};
                        mode.setInvariant(hostField.value.get_c_str());
                        if (parseMothershipClusterTestHostMode(mode, request.test.host.mode) == false)
                        {
                           basics_log("createCluster.test.host.mode invalid\n");
                           exit(EXIT_FAILURE);
                        }
                     }
                     else if (hostKey.equal("ssh"_ctv))
                     {
                        if (parseClusterMachineSSHJSON(hostField.value, request.test.host.ssh, "createCluster.test.host.ssh") == false)
                        {
                           exit(EXIT_FAILURE);
                        }
                     }
                     else
                     {
                        basics_log("createCluster.test.host invalid field\n");
                        exit(EXIT_FAILURE);
                     }
                  }
               }
               else
               {
                  basics_log("createCluster.test invalid field\n");
                  exit(EXIT_FAILURE);
               }
            }
         }
         else if (key.equal("nBrains"_ctv))
         {
            int64_t value = 0;
            if (field.value.type() != simdjson::dom::element_type::INT64 || field.value.get(value) != simdjson::SUCCESS || value < 0 || value > INT32_MAX)
            {
               basics_log("createCluster.nBrains invalid\n");
               exit(EXIT_FAILURE);
            }

            request.nBrains = uint32_t(value);
         }
         else if (key.equal("machineSchemas"_ctv))
         {
            if (field.value.type() != simdjson::dom::element_type::ARRAY)
            {
               basics_log("createCluster.machineSchemas requires array\n");
               exit(EXIT_FAILURE);
            }

            for (auto item : field.value.get_array())
            {
               MothershipProdigyClusterMachineSchema schema = {};
               if (parseClusterMachineSchemaJSON(item, schema, "createCluster.machineSchemas[]") == false)
               {
                  exit(EXIT_FAILURE);
               }

               request.machineSchemas.push_back(schema);
            }
         }
         else if (key.equal("machines"_ctv))
         {
            if (parseMothershipClusterMachinesJSON(field.value, request.machines, "createCluster.machines") == false)
            {
               exit(EXIT_FAILURE);
            }
         }
         else if (key.equal("bootstrapSshUser"_ctv))
         {
            if (field.value.type() != simdjson::dom::element_type::STRING)
            {
               basics_log("createCluster.bootstrapSshUser requires string\n");
               exit(EXIT_FAILURE);
            }

            request.bootstrapSshUser.assign(field.value.get_c_str());
         }
         else if (key.equal("bootstrapSshPrivateKeyPath"_ctv))
         {
            if (field.value.type() != simdjson::dom::element_type::STRING)
            {
               basics_log("createCluster.bootstrapSshPrivateKeyPath requires string\n");
               exit(EXIT_FAILURE);
            }

            request.bootstrapSshPrivateKeyPath.assign(field.value.get_c_str());
         }
         else if (key.equal("bootstrapSshKeyPackage"_ctv))
         {
            if (parseSSHKeyPackageJSON(field.value, request.bootstrapSshKeyPackage, "createCluster.bootstrapSshKeyPackage") == false)
            {
               exit(EXIT_FAILURE);
            }
         }
         else if (key.equal("bootstrapSshHostKeyPackage"_ctv))
         {
            basics_log("createCluster.bootstrapSshHostKeyPackage has been removed; pin host keys per machine with ssh.hostPublicKeyOpenSSH\n");
            exit(EXIT_FAILURE);
         }
         else if (key.equal("remoteProdigyPath"_ctv))
         {
            if (field.value.type() != simdjson::dom::element_type::STRING)
            {
               basics_log("createCluster.remoteProdigyPath requires string\n");
               exit(EXIT_FAILURE);
            }

            request.remoteProdigyPath.assign(field.value.get_c_str());
         }
         else if (key.equal("sharedCpuOvercommit"_ctv))
         {
            String failure = {};
            if (mothershipParseSharedCPUOvercommitValue(field.value, request.sharedCPUOvercommitPermille, &failure, "createCluster.sharedCpuOvercommit"_ctv) == false)
            {
               basics_log("%s\n", failure.c_str());
               exit(EXIT_FAILURE);
            }
         }
         else if (key.equal("bgp"_ctv))
         {
            if (parseProdigyEnvironmentBGPJSONElement(field.value, request.bgp) == false)
            {
               basics_log("createCluster.bgp invalid\n");
               exit(EXIT_FAILURE);
            }
         }
         else if (key.equal("desiredEnvironment"_ctv))
         {
            if (field.value.type() != simdjson::dom::element_type::STRING)
            {
               basics_log("createCluster.desiredEnvironment requires string\n");
               exit(EXIT_FAILURE);
            }

            String environment;
            environment.setInvariant(field.value.get_c_str());
            if (parseProdigyEnvironmentKind(environment, request.desiredEnvironment) == false)
            {
               basics_log("createCluster.desiredEnvironment invalid\n");
               exit(EXIT_FAILURE);
            }
         }
         else
         {
            basics_log("createCluster invalid field\n");
            exit(EXIT_FAILURE);
         }
      }

      String failure;
      if (hasProviderCredentialOverride)
      {
         if (resolveMothershipClusterInlineProviderCredentialOverride(request, providerCredentialOverride, &failure) == false)
         {
            basics_log("createCluster success=0 failure=%s\n", (failure.size() ? failure.c_str() : ""));
            exit(EXIT_FAILURE);
         }

         MothershipProviderCredential storedCredential = {};
         MothershipProviderCredentialRegistry providerCredentialRegistry = openProviderCredentialRegistry();
         if (providerCredentialRegistry.upsertCredential(providerCredentialOverride, &storedCredential, &failure) == false)
         {
            basics_log("createCluster success=0 failure=%s\n", (failure.size() ? failure.c_str() : ""));
            exit(EXIT_FAILURE);
         }
      }

      MothershipProviderCredential referencedCredential = {};
      MothershipProviderCredential *credentialPtr = nullptr;
      if (validateClusterProviderCredentialReference(request, failure, &referencedCredential) == false)
      {
         basics_log("createCluster success=0 failure=%s\n", (failure.size() ? failure.c_str() : ""));
         exit(EXIT_FAILURE);
      }

      if (request.providerCredentialName.size() > 0)
      {
         credentialPtr = &referencedCredential;
      }

      if (inferClusterMachineSchemaCpuCapabilities(request, credentialPtr, failure) == false)
      {
         basics_log("createCluster success=0 failure=%s\n", (failure.size() ? failure.c_str() : ""));
         exit(EXIT_FAILURE);
      }

      MothershipProdigyCluster stored = {};
      {
         MothershipClusterRegistry clusterRegistry = openClusterRegistry();
         if (clusterRegistry.createCluster(request, &stored, &failure) == false)
         {
            basics_log("createCluster success=0 failure=%s\n", (failure.size() ? failure.c_str() : ""));
            exit(EXIT_FAILURE);
         }
      }

      ClusterCreateHooks hooks(this);
      MothershipClusterCreateTimingSummary timingSummary = {};
      if (mothershipStandUpCluster(stored, credentialPtr, hooks, &timingSummary, &failure) == false)
      {
         persistClusterRefreshFailure(stored, failure);
#if PRODIGY_ENABLE_CREATE_TIMING_ATTRIBUTION
         printCreateClusterTimingSummary(timingSummary);
#endif
         basics_log("createCluster success=0 created=1 name=%s failure=%s\n", stored.name.c_str(), (failure.size() ? failure.c_str() : ""));
         exit(EXIT_FAILURE);
      }

      persistClusterTopology(stored, stored.topology);
#if PRODIGY_ENABLE_CREATE_TIMING_ATTRIBUTION
      printCreateClusterTimingSummary(timingSummary);
#endif
      basics_log("createCluster success=1 created=1\n");
      printManagedCluster(stored);
   }

   void runPrintClusters(int argc, char *argv[])
   {
      if (argc != 0)
      {
         basics_log("too many arguments. ex: printClusters\n");
         exit(EXIT_FAILURE);
      }

      String failure;
      Vector<MothershipProdigyCluster> clusters;
      MothershipClusterRegistry clusterRegistry = openClusterRegistry();
      if (clusterRegistry.listClusters(clusters, &failure) == false)
      {
         basics_log("printClusters success=0 failure=%s\n", (failure.size() ? failure.c_str() : ""));
         exit(EXIT_FAILURE);
      }

      basics_log("printClusters success=1 count=%u\n", unsigned(clusters.size()));
      for (const MothershipProdigyCluster& cluster : clusters)
      {
         printManagedCluster(cluster);
      }
   }

   void runRemoveCluster(int argc, char *argv[])
   {
      if (argc < 1)
      {
         basics_log("too few arguments. ex: removeCluster [name|clusterUUID]\n");
         exit(EXIT_FAILURE);
      }

      String name;
      name.assign(argv[0]);
      if (name.size() == 0)
      {
         basics_log("removeCluster.identity required\n");
         exit(EXIT_FAILURE);
      }

      String failure;
      MothershipProdigyCluster cluster = {};
      {
         MothershipClusterRegistry clusterRegistry = openClusterRegistry();
         if (clusterRegistry.getClusterByIdentity(name, cluster, &failure) == false)
         {
            basics_log("removeCluster success=0 removed=0 identity=%s failure=%s\n", name.c_str(), (failure.size() ? failure.c_str() : ""));
            exit(EXIT_FAILURE);
         }
      }

      MothershipClusterRemoveSummary summary = {};
      RemoveClusterHooks hooks(this);
      if (mothershipRemoveClusterRuntime(cluster, hooks, summary, &failure) == false)
      {
         basics_log("removeCluster success=0 removed=0 identity=%s failure=%s\n", name.c_str(), (failure.size() ? failure.c_str() : ""));
         exit(EXIT_FAILURE);
      }

      {
         MothershipClusterRegistry clusterRegistry = openClusterRegistry();
         if (clusterRegistry.removeClusterByIdentity(name, &failure) == false)
         {
            basics_log("removeCluster success=0 removed=0 identity=%s failure=%s\n", name.c_str(), (failure.size() ? failure.c_str() : ""));
            exit(EXIT_FAILURE);
         }
      }

      basics_log("removeCluster success=1 removed=1 identity=%s wipedLocalMachine=%u wipedAdoptedMachines=%u destroyedCreatedCloudMachines=%u\n",
         name.c_str(),
         unsigned(summary.stoppedLocalMachine),
         unsigned(summary.wipedAdoptedMachines),
         unsigned(summary.destroyedCreatedCloudMachines));
   }

	void runUpdateProdigy(int argc, char *argv[])
	{
		if (argc < 2)
		{
			basics_log("too few arguments. ex: updateProdigy [target: local|clusterName|clusterUUID] [path to prodigy binary or bundle]\n");
			exit(EXIT_FAILURE);
		}

		String inputPath;
		inputPath.assign(argv[1]);

		if (inputPath.size() == 0)
		{
			basics_log("updateProdigy requires a non-empty path to prodigy binary or bundle\n");
			exit(EXIT_FAILURE);
		}

		if (access(inputPath.c_str(), R_OK) != 0)
		{
			basics_log("updateProdigy path is inaccessible: %s\n", inputPath.c_str());
			exit(EXIT_FAILURE);
		}

      MachineCpuArchitecture targetArchitecture = MachineCpuArchitecture::unknown;
      String failure;
      if (resolveProdigyBundleTargetArchitecture(argv[0], targetArchitecture, &failure) == false)
      {
         basics_log("updateProdigy failed to resolve target architecture: %s\n", failure.c_str());
         exit(EXIT_FAILURE);
      }

		String bundlePath;
		if (prodigyResolveBundleArtifactInput(inputPath, targetArchitecture, bundlePath, &failure) == false)
		{
			basics_log("updateProdigy failed to resolve bundle: %s\n", failure.c_str());
			exit(EXIT_FAILURE);
		}

      String actualBundleDigest;
      if (prodigyApproveBundleArtifact(bundlePath, actualBundleDigest, &failure) == false)
      {
         basics_log("updateProdigy rejected bundle: %s\n", failure.c_str());
         exit(EXIT_FAILURE);
      }

		uint32_t bundleSize = Filesystem::fileSize(bundlePath);
		if (bundleSize == 0)
		{
			basics_log("updateProdigy bundle path is empty or inaccessible: %s\n", bundlePath.c_str());
			exit(EXIT_FAILURE);
		}

		// Reject bad upgrade artifacts before any control-socket bootstrap so the
		// failure is deterministic even when the target cluster is unreachable.
		if (!configureControlTarget(argv[0]))
		{
			exit(EXIT_FAILURE);
		}

		if (socket.connect() == 0)
		{
			uint32_t headerOffset = Message::appendHeader(socket.wBuffer, MothershipTopic::updateProdigy);
			Message::appendFile(socket.wBuffer, bundlePath);
			Message::finish(socket.wBuffer, headerOffset);

			if (socket.send() == false)
			{
				exit(EXIT_FAILURE);
			}

			basics_log("updateProdigy dispatched: stage=%s bytes=%u path=%s sha256=%s\n",
            argv[0], bundleSize, bundlePath.c_str(), actualBundleDigest.c_str());
			socket.close();
		}
		else
		{
			exit(EXIT_FAILURE);
		}
	}

	void runReserveApplicationID(int argc, char *argv[])
	{
		if (argc < 2)
		{
			basics_log("too few arguments. ex: reserveApplicationID [target: local|clusterName|clusterUUID] [json]\n");
			exit(EXIT_FAILURE);
		}

		if (!configureControlTarget(argv[0]))
		{
			exit(EXIT_FAILURE);
		}

		ApplicationIDReserveRequest request;

		String json;
		json.append(argv[1]);
		json.need(simdjson::SIMDJSON_PADDING);

		simdjson::dom::parser parser;
		simdjson::dom::element doc;
		if (parser.parse(json.data(), json.size()).get(doc))
		{
			basics_log("invalid json for reserveApplicationID\n");
			exit(EXIT_FAILURE);
		}

		for (auto field : doc.get_object())
		{
			String key;
			key.setInvariant(field.key.data(), field.key.size());

			if (key.equal("applicationName"_ctv))
			{
				if (field.value.type() != simdjson::dom::element_type::STRING)
				{
					basics_log("reserveApplicationID.applicationName requires string\n");
					exit(EXIT_FAILURE);
				}

				request.applicationName.assign(field.value.get_c_str());
			}
			else if (key.equal("requestedApplicationID"_ctv))
			{
				int64_t value = 0;
				if (field.value.type() != simdjson::dom::element_type::INT64 || field.value.get(value) != simdjson::SUCCESS || value <= 0 || value > UINT16_MAX)
				{
					basics_log("reserveApplicationID.requestedApplicationID invalid\n");
					exit(EXIT_FAILURE);
				}

				request.requestedApplicationID = uint16_t(value);
			}
			else if (key.equal("createIfMissing"_ctv))
			{
				if (field.value.type() != simdjson::dom::element_type::BOOL)
				{
					basics_log("reserveApplicationID.createIfMissing requires bool\n");
					exit(EXIT_FAILURE);
				}

				bool value = true;
				(void)field.value.get(value);
				request.createIfMissing = value;
			}
			else
			{
				basics_log("reserveApplicationID invalid field\n");
				exit(EXIT_FAILURE);
			}
		}

		if (request.applicationName.size() == 0)
		{
			basics_log("reserveApplicationID.applicationName required\n");
			exit(EXIT_FAILURE);
		}

		ApplicationIDReserveResponse response;
		if (socket.requestApplicationID(request, response) == false)
		{
			exit(EXIT_FAILURE);
		}

		basics_log("reserveApplicationID success=%d name=%s appID=%u created=%d failure=%s\n",
			int(response.success),
			response.applicationName.c_str(),
			unsigned(response.applicationID),
			int(response.created),
			(response.failure.size() ? response.failure.c_str() : ""));

		if (response.success == false)
		{
			exit(EXIT_FAILURE);
		}
	}

	void runReserveServiceID(int argc, char *argv[])
	{
		if (argc < 2)
		{
			basics_log("too few arguments. ex: reserveServiceID [target: dev|prod|local|clusterName|clusterUUID] [json]\n");
			exit(EXIT_FAILURE);
		}

		if (configureControlTarget(argv[0]) == false)
		{
			exit(EXIT_FAILURE);
		}

		ApplicationServiceReserveRequest request = {};
		request.createIfMissing = true;

		String json;
		json.append(argv[1]);
		json.need(simdjson::SIMDJSON_PADDING);

		simdjson::dom::parser parser;
		simdjson::dom::element doc;
		if (parser.parse(json.data(), json.size()).get(doc))
		{
			basics_log("invalid json for reserveServiceID\n");
			exit(EXIT_FAILURE);
		}

		for (auto field : doc.get_object())
		{
			String key;
			key.setInvariant(field.key.data(), field.key.size());

			if (key.equal("applicationName"_ctv))
			{
				if (field.value.type() != simdjson::dom::element_type::STRING)
				{
					basics_log("reserveServiceID.applicationName requires string\n");
					exit(EXIT_FAILURE);
				}

				request.applicationName.assign(field.value.get_c_str());
			}
			else if (key.equal("applicationID"_ctv))
			{
				int64_t value = 0;
				if (field.value.type() != simdjson::dom::element_type::INT64 || field.value.get(value) != simdjson::SUCCESS || value <= 0 || value > UINT16_MAX)
				{
					basics_log("reserveServiceID.applicationID invalid\n");
					exit(EXIT_FAILURE);
				}

				request.applicationID = uint16_t(value);
			}
			else if (key.equal("serviceName"_ctv))
			{
				if (field.value.type() != simdjson::dom::element_type::STRING)
				{
					basics_log("reserveServiceID.serviceName requires string\n");
					exit(EXIT_FAILURE);
				}

				request.serviceName.assign(field.value.get_c_str());
			}
			else if (key.equal("requestedServiceSlot"_ctv))
			{
				int64_t value = 0;
				if (field.value.type() != simdjson::dom::element_type::INT64 || field.value.get(value) != simdjson::SUCCESS || value <= 0 || value > UINT8_MAX)
				{
					basics_log("reserveServiceID.requestedServiceSlot invalid\n");
					exit(EXIT_FAILURE);
				}

				request.requestedServiceSlot = uint8_t(value);
			}
			else if (key.equal("kind"_ctv))
			{
				if (field.value.type() != simdjson::dom::element_type::STRING)
				{
					basics_log("reserveServiceID.kind requires string\n");
					exit(EXIT_FAILURE);
				}

				String kind;
				kind.setInvariant(field.value.get_c_str());
				if (kind.equal("stateless"_ctv))
				{
					request.kind = ApplicationServiceIdentity::Kind::stateless;
				}
				else if (kind.equal("stateful"_ctv))
				{
					request.kind = ApplicationServiceIdentity::Kind::stateful;
				}
				else
				{
					basics_log("reserveServiceID.kind invalid\n");
					exit(EXIT_FAILURE);
				}
			}
			else if (key.equal("createIfMissing"_ctv))
			{
				if (field.value.type() != simdjson::dom::element_type::BOOL)
				{
					basics_log("reserveServiceID.createIfMissing requires bool\n");
					exit(EXIT_FAILURE);
				}

				bool value = true;
				(void)field.value.get(value);
				request.createIfMissing = value;
			}
			else
			{
				basics_log("reserveServiceID invalid field\n");
				exit(EXIT_FAILURE);
			}
		}

		if (request.serviceName.size() == 0)
		{
			basics_log("reserveServiceID.serviceName required\n");
			exit(EXIT_FAILURE);
		}

		ApplicationServiceReserveResponse response;
		if (socket.requestServiceID(request, response) == false)
		{
			printConnectFailure();
			exit(EXIT_FAILURE);
		}

		basics_log("reserveServiceID success=%d app=%s appID=%u service=%s slot=%u kind=%u value=%llu created=%d failure=%s\n",
			int(response.success),
			response.applicationName.c_str(),
			unsigned(response.applicationID),
			response.serviceName.c_str(),
			unsigned(response.serviceSlot),
			unsigned(response.kind),
			static_cast<unsigned long long>(response.service),
			int(response.created),
			(response.failure.size() ? response.failure.c_str() : ""));

		if (response.success == false)
		{
			exit(EXIT_FAILURE);
		}
	}

	void runRegisterRoutableSubnet(int argc, char *argv[])
	{
		if (argc < 2)
		{
			basics_log("too few arguments. ex: registerRoutableSubnet [target: local|clusterName|clusterUUID] [json]\n");
			exit(EXIT_FAILURE);
		}

		if (configureControlTarget(argv[0]) == false)
		{
			exit(EXIT_FAILURE);
		}

		RoutableSubnetRegistration request = {};
      bool sawSubnet = false;
      bool sawUsage = false;

		String json;
		json.append(argv[1]);
		json.need(simdjson::SIMDJSON_PADDING);

		simdjson::dom::parser parser;
		simdjson::dom::element doc;
		if (parser.parse(json.data(), json.size()).get(doc))
		{
			basics_log("invalid json for registerRoutableSubnet\n");
			exit(EXIT_FAILURE);
		}

		for (auto field : doc.get_object())
		{
			String key;
			key.setInvariant(field.key.data(), field.key.size());

			if (key.equal("name"_ctv))
			{
				if (field.value.type() != simdjson::dom::element_type::STRING)
				{
					basics_log("registerRoutableSubnet.name requires string\n");
					exit(EXIT_FAILURE);
				}

				request.subnet.name.assign(field.value.get_c_str());
			}
			else if (key.equal("subnet"_ctv))
			{
				if (field.value.type() != simdjson::dom::element_type::STRING)
				{
					basics_log("registerRoutableSubnet.subnet requires string\n");
					exit(EXIT_FAILURE);
				}

				if (parseCIDRPrefix(field.value.get_c_str(), request.subnet.subnet) == false)
				{
					basics_log("registerRoutableSubnet.subnet invalid CIDR\n");
					exit(EXIT_FAILURE);
				}

            sawSubnet = true;
			}
			else if (key.equal("routing"_ctv))
			{
				if (field.value.type() != simdjson::dom::element_type::STRING)
				{
					basics_log("registerRoutableSubnet.routing requires string\n");
					exit(EXIT_FAILURE);
				}

				String routing;
				routing.setInvariant(field.value.get_c_str());
				if (parseExternalSubnetRouting(routing, request.subnet.routing) == false)
				{
					basics_log("registerRoutableSubnet.routing invalid\n");
					exit(EXIT_FAILURE);
				}
			}
         else if (key.equal("usage"_ctv))
         {
            if (field.value.type() != simdjson::dom::element_type::STRING)
            {
               basics_log("registerRoutableSubnet.usage requires string\n");
               exit(EXIT_FAILURE);
            }

            String usage;
            usage.setInvariant(field.value.get_c_str());
            if (parseExternalSubnetUsage(usage, request.subnet.usage) == false)
            {
               basics_log("registerRoutableSubnet.usage invalid\n");
               exit(EXIT_FAILURE);
            }

            sawUsage = true;
         }
			else
			{
				basics_log("registerRoutableSubnet invalid field\n");
				exit(EXIT_FAILURE);
			}
		}

		if (request.subnet.name.size() == 0)
		{
			basics_log("registerRoutableSubnet.name required\n");
			exit(EXIT_FAILURE);
		}

      if (request.subnet.routing != ExternalSubnetRouting::switchboardBGP)
      {
         basics_log("registerRoutableSubnet only supports routing=switchboardBGP\n");
         exit(EXIT_FAILURE);
      }

		if (sawSubnet == false)
		{
			basics_log("registerRoutableSubnet.subnet required\n");
			exit(EXIT_FAILURE);
		}

      if (sawUsage == false)
      {
         basics_log("registerRoutableSubnet.usage required\n");
         exit(EXIT_FAILURE);
      }

      if (routableExternalSubnetHasSupportedBreadth(request.subnet) == false)
      {
         if (request.subnet.subnet.network.is6)
         {
            basics_log("registerRoutableSubnet ipv6 subnets must be between /4 and /48\n");
         }
         else
         {
            basics_log("registerRoutableSubnet ipv4 subnets must be between /4 and /24\n");
         }
         exit(EXIT_FAILURE);
      }

		if (socket.connect() != 0)
		{
			exit(EXIT_FAILURE);
		}

		uint32_t headerOffset = Message::appendHeader(socket.wBuffer, MothershipTopic::registerRoutableSubnet);
		Message::serializeAndAppendObject(socket.wBuffer, request);
		Message::finish(socket.wBuffer, headerOffset);

		if (socket.send() == false)
		{
			exit(EXIT_FAILURE);
		}

		Message *responseMessage = socket.recvExpectedTopic(MothershipTopic::registerRoutableSubnet);
		if (responseMessage == nullptr)
		{
			exit(EXIT_FAILURE);
		}

		String serializedResponse;
		uint8_t *responseArgs = responseMessage->args;
		Message::extractToStringView(responseArgs, serializedResponse);

		RoutableSubnetRegistration response;
		if (BitseryEngine::deserializeSafe(serializedResponse, response) == false)
		{
			basics_log("registerRoutableSubnet response decode failed\n");
			exit(EXIT_FAILURE);
		}

		char prefixBuffer[INET6_ADDRSTRLEN + 8] = {0};
		(void)formatCIDRPrefix(response.subnet.subnet, prefixBuffer, sizeof(prefixBuffer));
      String subnetUUIDText = {};
      subnetUUIDText.assignItoh(response.subnet.uuid);

		basics_log("registerRoutableSubnet success=%d created=%d name=%s uuid=%s subnet=%s routing=%s usage=%s failure=%s\n",
			int(response.success),
			int(response.created),
			response.subnet.name.c_str(),
         subnetUUIDText.c_str(),
			prefixBuffer,
			externalSubnetRoutingName(response.subnet.routing),
         externalSubnetUsageName(response.subnet.usage),
			(response.failure.size() ? response.failure.c_str() : ""));

		if (response.success == false)
		{
			exit(EXIT_FAILURE);
		}
	}

	void runUnregisterRoutableSubnet(int argc, char *argv[])
	{
		if (argc < 2)
		{
			basics_log("too few arguments. ex: unregisterRoutableSubnet [target: local|clusterName|clusterUUID] [name]\n");
			exit(EXIT_FAILURE);
		}

		if (configureControlTarget(argv[0]) == false)
		{
			exit(EXIT_FAILURE);
		}

		RoutableSubnetUnregistration request = {};
		request.name.assign(argv[1]);

		if (request.name.size() == 0)
		{
			basics_log("unregisterRoutableSubnet.name required\n");
			exit(EXIT_FAILURE);
		}

		if (socket.connect() != 0)
		{
			exit(EXIT_FAILURE);
		}

		uint32_t headerOffset = Message::appendHeader(socket.wBuffer, MothershipTopic::unregisterRoutableSubnet);
		Message::serializeAndAppendObject(socket.wBuffer, request);
		Message::finish(socket.wBuffer, headerOffset);

		if (socket.send() == false)
		{
			exit(EXIT_FAILURE);
		}

		Message *responseMessage = socket.recvExpectedTopic(MothershipTopic::unregisterRoutableSubnet);
		if (responseMessage == nullptr)
		{
			exit(EXIT_FAILURE);
		}

		String serializedResponse;
		uint8_t *responseArgs = responseMessage->args;
		Message::extractToStringView(responseArgs, serializedResponse);

		RoutableSubnetUnregistration response;
		if (BitseryEngine::deserializeSafe(serializedResponse, response) == false)
		{
			basics_log("unregisterRoutableSubnet response decode failed\n");
			exit(EXIT_FAILURE);
		}

		basics_log("unregisterRoutableSubnet success=%d removed=%d name=%s failure=%s\n",
			int(response.success),
			int(response.removed),
			response.name.c_str(),
			(response.failure.size() ? response.failure.c_str() : ""));

		if (response.success == false)
		{
			exit(EXIT_FAILURE);
		}
	}

	void runPullRoutableSubnets(int argc, char *argv[])
	{
		if (argc < 1)
		{
			basics_log("too few arguments. ex: pullRoutableSubnets [target: local|clusterName|clusterUUID]\n");
			exit(EXIT_FAILURE);
		}

		if (configureControlTarget(argv[0]) == false)
		{
			exit(EXIT_FAILURE);
		}

		if (socket.connect() != 0)
		{
			exit(EXIT_FAILURE);
		}

		Message::construct(socket.wBuffer, MothershipTopic::pullRoutableSubnets);

		if (socket.send() == false)
		{
			exit(EXIT_FAILURE);
		}

		Message *responseMessage = socket.recvExpectedTopic(MothershipTopic::pullRoutableSubnets);
		if (responseMessage == nullptr)
		{
			exit(EXIT_FAILURE);
		}

		String serializedResponse;
		uint8_t *responseArgs = responseMessage->args;
		Message::extractToStringView(responseArgs, serializedResponse);

		RoutableSubnetRegistryReport response;
		if (BitseryEngine::deserializeSafe(serializedResponse, response) == false)
		{
			basics_log("pullRoutableSubnets response decode failed\n");
			exit(EXIT_FAILURE);
		}

		if (response.success == false)
		{
			basics_log("pullRoutableSubnets success=0 failure=%s\n", (response.failure.size() ? response.failure.c_str() : ""));
			exit(EXIT_FAILURE);
		}

		basics_log("pullRoutableSubnets success=1 count=%u\n", unsigned(response.subnets.size()));
		for (const DistributableExternalSubnet& subnet : response.subnets)
		{
			char prefixBuffer[INET6_ADDRSTRLEN + 8] = {0};
			if (formatCIDRPrefix(subnet.subnet, prefixBuffer, sizeof(prefixBuffer)) == false)
			{
				std::strcpy(prefixBuffer, "<invalid>");
			}

			String subnetName = subnet.name;
         String subnetUUIDText = {};
         subnetUUIDText.assignItoh(subnet.uuid);
			basics_log("  name=%s uuid=%s subnet=%s routing=%s usage=%s\n",
				subnetName.c_str(),
            subnetUUIDText.c_str(),
				prefixBuffer,
				externalSubnetRoutingName(subnet.routing),
            externalSubnetUsageName(subnet.usage));
		}
	}

   void runRegisterRoutableAddress(int argc, char *argv[])
   {
      if (argc < 2)
      {
         basics_log("too few arguments. ex: registerRoutableAddress [target: local|clusterName|clusterUUID] [json]\n");
         exit(EXIT_FAILURE);
      }

      if (configureControlTarget(argv[0]) == false)
      {
         exit(EXIT_FAILURE);
      }

      RoutableAddressRegistration request = {};
      bool sawKind = false;
      bool sawFamily = false;

      String json = {};
      json.append(argv[1]);
      json.need(simdjson::SIMDJSON_PADDING);

      simdjson::dom::parser parser;
      simdjson::dom::element doc;
      if (parser.parse(json.data(), json.size()).get(doc))
      {
         basics_log("invalid json for registerRoutableAddress\n");
         exit(EXIT_FAILURE);
      }

      for (auto field : doc.get_object())
      {
         String key = {};
         key.setInvariant(field.key.data(), field.key.size());

         if (key.equal("name"_ctv))
         {
            if (field.value.type() != simdjson::dom::element_type::STRING)
            {
               basics_log("registerRoutableAddress.name requires string\n");
               exit(EXIT_FAILURE);
            }

            request.name.assign(field.value.get_c_str());
         }
         else if (key.equal("kind"_ctv))
         {
            if (field.value.type() != simdjson::dom::element_type::STRING)
            {
               basics_log("registerRoutableAddress.kind requires string\n");
               exit(EXIT_FAILURE);
            }

            String value = {};
            value.setInvariant(field.value.get_c_str());
            if (parseRoutableAddressKind(value, request.kind) == false)
            {
               basics_log("registerRoutableAddress.kind invalid\n");
               exit(EXIT_FAILURE);
            }

            sawKind = true;
         }
         else if (key.equal("family"_ctv))
         {
            if (field.value.type() != simdjson::dom::element_type::STRING)
            {
               basics_log("registerRoutableAddress.family requires string\n");
               exit(EXIT_FAILURE);
            }

            String value = {};
            value.setInvariant(field.value.get_c_str());
            if (parseExternalAddressFamily(value, request.family) == false)
            {
               basics_log("registerRoutableAddress.family invalid\n");
               exit(EXIT_FAILURE);
            }

            sawFamily = true;
         }
         else if (key.equal("machineUUID"_ctv))
         {
            if (field.value.type() != simdjson::dom::element_type::STRING)
            {
               basics_log("registerRoutableAddress.machineUUID requires string\n");
               exit(EXIT_FAILURE);
            }

            String value = {};
            value.setInvariant(field.value.get_c_str());
            request.machineUUID = String::numberFromHexString<uint128_t>(value);
            if (request.machineUUID == 0)
            {
               basics_log("registerRoutableAddress.machineUUID invalid\n");
               exit(EXIT_FAILURE);
            }
         }
         else if (key.equal("uuid"_ctv))
         {
            if (field.value.type() != simdjson::dom::element_type::STRING)
            {
               basics_log("registerRoutableAddress.uuid requires string\n");
               exit(EXIT_FAILURE);
            }

            String value = {};
            value.setInvariant(field.value.get_c_str());
            request.uuid = String::numberFromHexString<uint128_t>(value);
            if (request.uuid == 0)
            {
               basics_log("registerRoutableAddress.uuid invalid\n");
               exit(EXIT_FAILURE);
            }
         }
         else if (key.equal("requestedAddress"_ctv))
         {
            if (field.value.type() != simdjson::dom::element_type::STRING)
            {
               basics_log("registerRoutableAddress.requestedAddress requires string\n");
               exit(EXIT_FAILURE);
            }

            request.requestedAddress.assign(field.value.get_c_str());
         }
         else if (key.equal("providerPool"_ctv))
         {
            if (field.value.type() != simdjson::dom::element_type::STRING)
            {
               basics_log("registerRoutableAddress.providerPool requires string\n");
               exit(EXIT_FAILURE);
            }

            request.providerPool.assign(field.value.get_c_str());
         }
         else
         {
            basics_log("registerRoutableAddress invalid field\n");
            exit(EXIT_FAILURE);
         }
      }

      if (request.name.size() == 0)
      {
         basics_log("registerRoutableAddress.name required\n");
         exit(EXIT_FAILURE);
      }

      if (sawKind == false)
      {
         basics_log("registerRoutableAddress.kind required\n");
         exit(EXIT_FAILURE);
      }

      if (sawFamily == false)
      {
         basics_log("registerRoutableAddress.family required\n");
         exit(EXIT_FAILURE);
      }

      if (socket.connect() != 0)
      {
         exit(EXIT_FAILURE);
      }

      uint32_t headerOffset = Message::appendHeader(socket.wBuffer, MothershipTopic::registerRoutableAddress);
      Message::serializeAndAppendObject(socket.wBuffer, request);
      Message::finish(socket.wBuffer, headerOffset);

      if (socket.send() == false)
      {
         exit(EXIT_FAILURE);
      }

      Message *responseMessage = socket.recvExpectedTopic(MothershipTopic::registerRoutableAddress);
      if (responseMessage == nullptr)
      {
         exit(EXIT_FAILURE);
      }

      String serializedResponse = {};
      uint8_t *responseArgs = responseMessage->args;
      Message::extractToStringView(responseArgs, serializedResponse);

      RoutableAddressRegistration response = {};
      if (BitseryEngine::deserializeSafe(serializedResponse, response) == false)
      {
         basics_log("registerRoutableAddress response decode failed\n");
         exit(EXIT_FAILURE);
      }

      String uuidText = {};
      uuidText.assignItoh(response.uuid);
      String machineUUIDText = {};
      machineUUIDText.assignItoh(response.machineUUID);
      String addressText = {};
      if (ClusterMachine::renderIPAddressLiteral(response.address, addressText) == false)
      {
         addressText.assign("<invalid>"_ctv);
      }

      basics_log("registerRoutableAddress success=%d created=%d name=%s uuid=%s kind=%s family=%s machineUUID=%s address=%s failure=%s\n",
         int(response.success),
         int(response.created),
         response.name.c_str(),
         uuidText.c_str(),
         routableAddressKindName(response.kind),
         response.family == ExternalAddressFamily::ipv6 ? "ipv6" : "ipv4",
         machineUUIDText.c_str(),
         addressText.c_str(),
         (response.failure.size() ? response.failure.c_str() : ""));

      if (response.success == false)
      {
         exit(EXIT_FAILURE);
      }
   }

   void runUnregisterRoutableAddress(int argc, char *argv[])
   {
      if (argc < 2)
      {
         basics_log("too few arguments. ex: unregisterRoutableAddress [target: local|clusterName|clusterUUID] [name|uuid]\n");
         exit(EXIT_FAILURE);
      }

      if (configureControlTarget(argv[0]) == false)
      {
         exit(EXIT_FAILURE);
      }

      RoutableAddressUnregistration request = {};
      String identifier = {};
      identifier.assign(argv[1]);
      request.name = identifier;
      request.uuid = String::numberFromHexString<uint128_t>(identifier);

      if (request.name.size() == 0 && request.uuid == 0)
      {
         basics_log("unregisterRoutableAddress requires name or uuid\n");
         exit(EXIT_FAILURE);
      }

      if (socket.connect() != 0)
      {
         exit(EXIT_FAILURE);
      }

      uint32_t headerOffset = Message::appendHeader(socket.wBuffer, MothershipTopic::unregisterRoutableAddress);
      Message::serializeAndAppendObject(socket.wBuffer, request);
      Message::finish(socket.wBuffer, headerOffset);

      if (socket.send() == false)
      {
         exit(EXIT_FAILURE);
      }

      Message *responseMessage = socket.recvExpectedTopic(MothershipTopic::unregisterRoutableAddress);
      if (responseMessage == nullptr)
      {
         exit(EXIT_FAILURE);
      }

      String serializedResponse = {};
      uint8_t *responseArgs = responseMessage->args;
      Message::extractToStringView(responseArgs, serializedResponse);

      RoutableAddressUnregistration response = {};
      if (BitseryEngine::deserializeSafe(serializedResponse, response) == false)
      {
         basics_log("unregisterRoutableAddress response decode failed\n");
         exit(EXIT_FAILURE);
      }

      String uuidText = {};
      uuidText.assignItoh(response.uuid);
      basics_log("unregisterRoutableAddress success=%d removed=%d name=%s uuid=%s failure=%s\n",
         int(response.success),
         int(response.removed),
         response.name.c_str(),
         uuidText.c_str(),
         (response.failure.size() ? response.failure.c_str() : ""));

      if (response.success == false)
      {
         exit(EXIT_FAILURE);
      }
   }

   void runPullRoutableAddresses(int argc, char *argv[])
   {
      if (argc < 1)
      {
         basics_log("too few arguments. ex: pullRoutableAddresses [target: local|clusterName|clusterUUID]\n");
         exit(EXIT_FAILURE);
      }

      if (configureControlTarget(argv[0]) == false)
      {
         exit(EXIT_FAILURE);
      }

      if (socket.connect() != 0)
      {
         exit(EXIT_FAILURE);
      }

      Message::construct(socket.wBuffer, MothershipTopic::pullRoutableAddresses);

      if (socket.send() == false)
      {
         exit(EXIT_FAILURE);
      }

      Message *responseMessage = socket.recvExpectedTopic(MothershipTopic::pullRoutableAddresses);
      if (responseMessage == nullptr)
      {
         exit(EXIT_FAILURE);
      }

      String serializedResponse = {};
      uint8_t *responseArgs = responseMessage->args;
      Message::extractToStringView(responseArgs, serializedResponse);

      RoutableAddressRegistryReport response = {};
      if (BitseryEngine::deserializeSafe(serializedResponse, response) == false)
      {
         basics_log("pullRoutableAddresses response decode failed\n");
         exit(EXIT_FAILURE);
      }

      if (response.success == false)
      {
         basics_log("pullRoutableAddresses success=0 failure=%s\n", (response.failure.size() ? response.failure.c_str() : ""));
         exit(EXIT_FAILURE);
      }

      basics_log("pullRoutableAddresses success=1 count=%u\n", unsigned(response.addresses.size()));
      for (const RegisteredRoutableAddress& address : response.addresses)
      {
         String uuidText = {};
         uuidText.assignItoh(address.uuid);
         String machineUUIDText = {};
         machineUUIDText.assignItoh(address.machineUUID);
         String addressText = {};
         String nameText = {};
         nameText.assign(address.name);
         String providerPoolText = {};
         providerPoolText.assign(address.providerPool);
         if (ClusterMachine::renderIPAddressLiteral(address.address, addressText) == false)
         {
            addressText.assign("<invalid>"_ctv);
         }

         basics_log("  name=%s uuid=%s kind=%s family=%s machineUUID=%s address=%s providerPool=%s\n",
            nameText.c_str(),
            uuidText.c_str(),
            routableAddressKindName(address.kind),
            address.family == ExternalAddressFamily::ipv6 ? "ipv6" : "ipv4",
            machineUUIDText.c_str(),
            addressText.c_str(),
            providerPoolText.c_str());
      }
   }
	void runUpsertTlsVaultFactory(int argc, char *argv[])
	{
		if (argc < 2)
		{
			basics_log("too few arguments. ex: upsertTlsVaultFactory [target: local|clusterName|clusterUUID] [json]\n");
			exit(EXIT_FAILURE);
		}

		if (!configureControlTarget(argv[0]))
		{
			exit(EXIT_FAILURE);
		}

		TlsVaultFactoryUpsertRequest request;
		request.scheme = 0; // p256
		request.mode = 0;
		request.defaultLeafValidityDays = 15;
		request.renewLeadPercent = 10;

		String json;
		json.append(argv[1]);
		json.need(simdjson::SIMDJSON_PADDING);

		simdjson::dom::parser parser;
		simdjson::dom::element doc;
		if (parser.parse(json.data(), json.size()).get(doc))
		{
			basics_log("invalid json for upsertTlsVaultFactory\n");
			exit(EXIT_FAILURE);
		}

		for (auto field : doc.get_object())
		{
			String key;
			key.setInvariant(field.key.data(), field.key.size());

			if (key.equal("applicationID"_ctv))
			{
				int64_t value = 0;
				if (field.value.type() != simdjson::dom::element_type::INT64 || field.value.get(value) != simdjson::SUCCESS || value <= 0 || value > UINT16_MAX)
				{
					basics_log("upsertTlsVaultFactory.applicationID invalid\n");
					exit(EXIT_FAILURE);
				}
				request.applicationID = uint16_t(value);
			}
			else if (key.equal("mode"_ctv))
			{
				if (field.value.type() != simdjson::dom::element_type::STRING)
				{
					basics_log("upsertTlsVaultFactory.mode requires string\n");
					exit(EXIT_FAILURE);
				}
				String mode;
				mode.setInvariant(field.value.get_c_str());
				if (mode.equal("generate"_ctv)) request.mode = 0;
				else if (mode.equal("import"_ctv)) request.mode = 1;
				else
				{
					basics_log("upsertTlsVaultFactory.mode invalid\n");
					exit(EXIT_FAILURE);
				}
			}
			else if (key.equal("scheme"_ctv))
			{
				if (field.value.type() != simdjson::dom::element_type::STRING)
				{
					basics_log("upsertTlsVaultFactory.scheme requires string\n");
					exit(EXIT_FAILURE);
				}
				String scheme;
				scheme.setInvariant(field.value.get_c_str());
				if (scheme.equal("p256"_ctv)) request.scheme = 0;
				else if (scheme.equal("ed25519"_ctv)) request.scheme = 1;
				else
				{
					basics_log("upsertTlsVaultFactory.scheme invalid\n");
					exit(EXIT_FAILURE);
				}
			}
			else if (key.equal("importRootCertPem"_ctv))
			{
				request.importRootCertPem.assign(field.value.get_c_str());
			}
			else if (key.equal("importRootKeyPem"_ctv))
			{
				request.importRootKeyPem.assign(field.value.get_c_str());
			}
			else if (key.equal("importIntermediateCertPem"_ctv))
			{
				request.importIntermediateCertPem.assign(field.value.get_c_str());
			}
			else if (key.equal("importIntermediateKeyPem"_ctv))
			{
				request.importIntermediateKeyPem.assign(field.value.get_c_str());
			}
			else if (key.equal("defaultLeafValidityDays"_ctv))
			{
				int64_t value = 0;
				if (field.value.type() != simdjson::dom::element_type::INT64 || field.value.get(value) != simdjson::SUCCESS || value <= 0 || value > 825)
				{
					basics_log("upsertTlsVaultFactory.defaultLeafValidityDays invalid\n");
					exit(EXIT_FAILURE);
				}
				request.defaultLeafValidityDays = uint32_t(value);
			}
			else if (key.equal("renewLeadPercent"_ctv))
			{
				int64_t value = 0;
				if (field.value.type() != simdjson::dom::element_type::INT64 || field.value.get(value) != simdjson::SUCCESS || value <= 0 || value >= 100)
				{
					basics_log("upsertTlsVaultFactory.renewLeadPercent invalid\n");
					exit(EXIT_FAILURE);
				}
				request.renewLeadPercent = uint8_t(value);
			}
			else
			{
				basics_log("upsertTlsVaultFactory invalid field\n");
				exit(EXIT_FAILURE);
			}
		}

		if (request.applicationID == 0)
		{
			basics_log("upsertTlsVaultFactory.applicationID required\n");
			exit(EXIT_FAILURE);
		}

		if (socket.connect() != 0)
		{
			exit(EXIT_FAILURE);
		}

		uint32_t headerOffset = Message::appendHeader(socket.wBuffer, MothershipTopic::upsertTlsVaultFactory);
		Message::serializeAndAppendObject(socket.wBuffer, request);
		Message::finish(socket.wBuffer, headerOffset);

		if (socket.send() == false)
		{
			exit(EXIT_FAILURE);
		}

		Message *responseMessage = socket.recvExpectedTopic(MothershipTopic::upsertTlsVaultFactory);
		if (responseMessage == nullptr)
		{
			exit(EXIT_FAILURE);
		}

		String serializedResponse;
		uint8_t *responseArgs = responseMessage->args;
		Message::extractToStringView(responseArgs, serializedResponse);

		TlsVaultFactoryUpsertResponse response;
		if (BitseryEngine::deserializeSafe(serializedResponse, response) == false)
		{
			basics_log("upsertTlsVaultFactory response decode failed\n");
			exit(EXIT_FAILURE);
		}

		basics_log("upsertTlsVaultFactory success=%d appID=%u generation=%llu created=%d mode=%u failure=%s\n",
			int(response.success),
			unsigned(response.applicationID),
			(unsigned long long)response.factoryGeneration,
			int(response.created),
			unsigned(response.mode),
			(response.failure.size() ? response.failure.c_str() : ""));

		if (response.success == false)
		{
			exit(EXIT_FAILURE);
		}
	}

	void runUpsertApiCredentialSet(int argc, char *argv[])
	{
		if (argc < 2)
		{
			basics_log("too few arguments. ex: upsertApiCredentialSet [target: local|clusterName|clusterUUID] [json]\n");
			exit(EXIT_FAILURE);
		}

		if (!configureControlTarget(argv[0]))
		{
			exit(EXIT_FAILURE);
		}

		ApiCredentialSetUpsertRequest request;
		request.reason.assign("manual"_ctv);

		String json;
		json.append(argv[1]);
		json.need(simdjson::SIMDJSON_PADDING);

		simdjson::dom::parser parser;
		simdjson::dom::element doc;
		if (parser.parse(json.data(), json.size()).get(doc))
		{
			basics_log("invalid json for upsertApiCredentialSet\n");
			exit(EXIT_FAILURE);
		}

		for (auto field : doc.get_object())
		{
			String key;
			key.setInvariant(field.key.data(), field.key.size());

			if (key.equal("applicationID"_ctv))
			{
				int64_t value = 0;
				if (field.value.type() != simdjson::dom::element_type::INT64 || field.value.get(value) != simdjson::SUCCESS || value <= 0 || value > UINT16_MAX)
				{
					basics_log("upsertApiCredentialSet.applicationID invalid\n");
					exit(EXIT_FAILURE);
				}
				request.applicationID = uint16_t(value);
			}
			else if (key.equal("reason"_ctv))
			{
				if (field.value.type() != simdjson::dom::element_type::STRING)
				{
					basics_log("upsertApiCredentialSet.reason requires string\n");
					exit(EXIT_FAILURE);
				}
				request.reason.assign(field.value.get_c_str());
			}
			else if (key.equal("removeCredentialNames"_ctv))
			{
				if (field.value.type() != simdjson::dom::element_type::ARRAY)
				{
					basics_log("upsertApiCredentialSet.removeCredentialNames requires array\n");
					exit(EXIT_FAILURE);
				}
				for (auto item : field.value.get_array())
				{
					if (item.type() != simdjson::dom::element_type::STRING)
					{
						basics_log("upsertApiCredentialSet.removeCredentialNames requires string members\n");
						exit(EXIT_FAILURE);
					}
					String name;
					name.assign(item.get_c_str());
					request.removeCredentialNames.push_back(name);
				}
			}
			else if (key.equal("upsertCredentials"_ctv))
			{
				if (field.value.type() != simdjson::dom::element_type::ARRAY)
				{
					basics_log("upsertApiCredentialSet.upsertCredentials requires array\n");
					exit(EXIT_FAILURE);
				}

				for (auto item : field.value.get_array())
				{
					if (item.type() != simdjson::dom::element_type::OBJECT)
					{
						basics_log("upsertApiCredentialSet.upsertCredentials requires object members\n");
						exit(EXIT_FAILURE);
					}

					ApiCredential credential;
					for (auto credField : item.get_object())
					{
						String credKey;
						credKey.setInvariant(credField.key.data(), credField.key.size());

						if (credKey.equal("name"_ctv))
						{
							credential.name.assign(credField.value.get_c_str());
						}
						else if (credKey.equal("provider"_ctv))
						{
							credential.provider.assign(credField.value.get_c_str());
						}
							else if (credKey.equal("material"_ctv))
							{
								credential.material.assign(credField.value.get_c_str());
							}
							else if (credKey.equal("metadata"_ctv))
							{
								if (credField.value.type() != simdjson::dom::element_type::OBJECT)
								{
									basics_log("upsertApiCredentialSet.upsertCredentials[].metadata requires object\n");
									exit(EXIT_FAILURE);
								}

								for (auto metadataField : credField.value.get_object())
								{
									if (metadataField.value.type() != simdjson::dom::element_type::STRING)
									{
										basics_log("upsertApiCredentialSet.upsertCredentials[].metadata requires string values\n");
										exit(EXIT_FAILURE);
									}

									String metadataKey;
									metadataKey.setInvariant(metadataField.key.data(), metadataField.key.size());
									if (metadataKey.size() == 0)
									{
										basics_log("upsertApiCredentialSet.upsertCredentials[].metadata contains empty key\n");
										exit(EXIT_FAILURE);
									}

									String metadataValue;
									metadataValue.assign(metadataField.value.get_c_str());
									credential.metadata.insert_or_assign(metadataKey, metadataValue);
								}
							}
							else if (credKey.equal("generation"_ctv))
							{
								int64_t value = 0;
								(void)credField.value.get(value);
							if (value > 0) credential.generation = uint64_t(value);
						}
						else if (credKey.equal("expiresAtMs"_ctv))
						{
							int64_t value = 0;
							(void)credField.value.get(value);
							credential.expiresAtMs = value;
						}
						else if (credKey.equal("activeFromMs"_ctv))
						{
							int64_t value = 0;
							(void)credField.value.get(value);
							credential.activeFromMs = value;
						}
						else if (credKey.equal("sunsetAtMs"_ctv))
						{
							int64_t value = 0;
							(void)credField.value.get(value);
							credential.sunsetAtMs = value;
						}
						else
						{
							basics_log("upsertApiCredentialSet.upsertCredentials invalid field\n");
							exit(EXIT_FAILURE);
						}
					}

					if (credential.name.size() == 0)
					{
						basics_log("upsertApiCredentialSet.upsertCredentials[].name required\n");
						exit(EXIT_FAILURE);
					}

					request.upsertCredentials.push_back(credential);
				}
			}
			else
			{
				basics_log("upsertApiCredentialSet invalid field\n");
				exit(EXIT_FAILURE);
			}
		}

		if (request.applicationID == 0)
		{
			basics_log("upsertApiCredentialSet.applicationID required\n");
			exit(EXIT_FAILURE);
		}

		if (socket.connect() != 0)
		{
			exit(EXIT_FAILURE);
		}

		uint32_t headerOffset = Message::appendHeader(socket.wBuffer, MothershipTopic::upsertApiCredentialSet);
		Message::serializeAndAppendObject(socket.wBuffer, request);
		Message::finish(socket.wBuffer, headerOffset);

		if (socket.send() == false)
		{
			exit(EXIT_FAILURE);
		}

		Message *responseMessage = socket.recvExpectedTopic(MothershipTopic::upsertApiCredentialSet);
		if (responseMessage == nullptr)
		{
			exit(EXIT_FAILURE);
		}

		String serializedResponse;
		uint8_t *responseArgs = responseMessage->args;
		Message::extractToStringView(responseArgs, serializedResponse);

		ApiCredentialSetUpsertResponse response;
		if (BitseryEngine::deserializeSafe(serializedResponse, response) == false)
		{
			basics_log("upsertApiCredentialSet response decode failed\n");
			exit(EXIT_FAILURE);
		}

		basics_log("upsertApiCredentialSet success=%d appID=%u setGeneration=%llu updated=%u removed=%u failure=%s\n",
			int(response.success),
			unsigned(response.applicationID),
			(unsigned long long)response.setGeneration,
			unsigned(response.updatedNames.size()),
			unsigned(response.removedNames.size()),
			(response.failure.size() ? response.failure.c_str() : ""));

		if (response.success == false)
		{
			exit(EXIT_FAILURE);
		}
	}

	void runMintClientTlsIdentity(int argc, char *argv[])
	{
		if (argc < 2)
		{
			basics_log("too few arguments. ex: mintClientTlsIdentity [target: local|clusterName|clusterUUID] [json]\n");
			exit(EXIT_FAILURE);
		}

		if (!configureControlTarget(argv[0]))
		{
			exit(EXIT_FAILURE);
		}

		ClientTlsMintRequest request;
		request.scheme = 0; // p256
		request.reason.assign("manual"_ctv);

		String json;
		json.append(argv[1]);
		json.need(simdjson::SIMDJSON_PADDING);

		simdjson::dom::parser parser;
		simdjson::dom::element doc;
		if (parser.parse(json.data(), json.size()).get(doc))
		{
			basics_log("invalid json for mintClientTlsIdentity\n");
			exit(EXIT_FAILURE);
		}

		for (auto field : doc.get_object())
		{
			String key;
			key.setInvariant(field.key.data(), field.key.size());

			if (key.equal("applicationID"_ctv))
			{
				int64_t value = 0;
				if (field.value.type() != simdjson::dom::element_type::INT64 || field.value.get(value) != simdjson::SUCCESS || value <= 0 || value > UINT16_MAX)
				{
					basics_log("mintClientTlsIdentity.applicationID invalid\n");
					exit(EXIT_FAILURE);
				}
				request.applicationID = uint16_t(value);
			}
			else if (key.equal("name"_ctv))
			{
				request.name.assign(field.value.get_c_str());
			}
			else if (key.equal("subjectCommonName"_ctv))
			{
				request.subjectCommonName.assign(field.value.get_c_str());
			}
			else if (key.equal("validityDays"_ctv))
			{
				int64_t value = 0;
				(void)field.value.get(value);
				if (value > 0 && value <= 825)
				{
					request.validityDays = uint32_t(value);
				}
				else
				{
					basics_log("mintClientTlsIdentity.validityDays invalid\n");
					exit(EXIT_FAILURE);
				}
			}
			else if (key.equal("reason"_ctv))
			{
				request.reason.assign(field.value.get_c_str());
			}
			else if (key.equal("scheme"_ctv))
			{
				String scheme;
				scheme.setInvariant(field.value.get_c_str());
				if (scheme.equal("p256"_ctv)) request.scheme = 0;
				else if (scheme.equal("ed25519"_ctv)) request.scheme = 1;
				else
				{
					basics_log("mintClientTlsIdentity.scheme invalid\n");
					exit(EXIT_FAILURE);
				}
			}
			else if (key.equal("dnsSans"_ctv))
			{
				if (field.value.type() != simdjson::dom::element_type::ARRAY)
				{
					basics_log("mintClientTlsIdentity.dnsSans requires array\n");
					exit(EXIT_FAILURE);
				}
				for (auto item : field.value.get_array())
				{
					if (item.type() != simdjson::dom::element_type::STRING)
					{
						basics_log("mintClientTlsIdentity.dnsSans requires string members\n");
						exit(EXIT_FAILURE);
					}
					String san;
					san.assign(item.get_c_str());
					request.dnsSans.push_back(san);
				}
			}
			else if (key.equal("tags"_ctv))
			{
				if (field.value.type() != simdjson::dom::element_type::ARRAY)
				{
					basics_log("mintClientTlsIdentity.tags requires array\n");
					exit(EXIT_FAILURE);
				}
				for (auto item : field.value.get_array())
				{
					if (item.type() != simdjson::dom::element_type::STRING)
					{
						basics_log("mintClientTlsIdentity.tags requires string members\n");
						exit(EXIT_FAILURE);
					}
					String tag;
					tag.assign(item.get_c_str());
					request.tags.push_back(tag);
				}
			}
			else
			{
				basics_log("mintClientTlsIdentity invalid field\n");
				exit(EXIT_FAILURE);
			}
		}

		if (request.applicationID == 0 || request.name.size() == 0)
		{
			basics_log("mintClientTlsIdentity requires applicationID and name\n");
			exit(EXIT_FAILURE);
		}

		if (socket.connect() != 0)
		{
			exit(EXIT_FAILURE);
		}

		uint32_t headerOffset = Message::appendHeader(socket.wBuffer, MothershipTopic::mintClientTlsIdentity);
		Message::serializeAndAppendObject(socket.wBuffer, request);
		Message::finish(socket.wBuffer, headerOffset);

		if (socket.send() == false)
		{
			exit(EXIT_FAILURE);
		}

		Message *responseMessage = socket.recvExpectedTopic(MothershipTopic::mintClientTlsIdentity);
		if (responseMessage == nullptr)
		{
			exit(EXIT_FAILURE);
		}

		String serializedResponse;
		uint8_t *responseArgs = responseMessage->args;
		Message::extractToStringView(responseArgs, serializedResponse);

		ClientTlsMintResponse response;
		if (BitseryEngine::deserializeSafe(serializedResponse, response) == false)
		{
			basics_log("mintClientTlsIdentity response decode failed\n");
			exit(EXIT_FAILURE);
		}

		basics_log("mintClientTlsIdentity success=%d appID=%u name=%s generation=%llu notAfter=%lld failure=%s\n",
			int(response.success),
			unsigned(response.applicationID),
			response.name.c_str(),
			(unsigned long long)response.generation,
			(long long)response.notAfterMs,
			(response.failure.size() ? response.failure.c_str() : ""));

		if (response.success == false)
		{
			exit(EXIT_FAILURE);
		}
	}

#ifdef PRODIGY_MOTHERSHIP_TEST_ACCESS
public:

	bool unitTestConfigureSeedCluster(const MothershipProdigyCluster& cluster, const BrainConfig& config, String *failure = nullptr)
	{
		ClusterCreateHooks hooks(this);
		return hooks.configureSeedCluster(cluster, config, failure);
	}

	bool unitTestFetchSeedTopology(const MothershipProdigyCluster& cluster, ClusterTopology& topology, String *failure = nullptr)
	{
		ClusterCreateHooks hooks(this);
		return hooks.fetchSeedTopology(cluster, topology, failure);
	}

	bool unitTestApplyAddMachines(const MothershipProdigyCluster& cluster, const AddMachines& request, ClusterTopology& topology, String *failure = nullptr)
	{
		ClusterCreateHooks hooks(this);
		return hooks.applyAddMachines(cluster, request, topology, nullptr, failure);
	}

   bool unitTestConfigureClusterSocket(const MothershipProdigyCluster& cluster, Vector<MothershipProdigyClusterMachine>& remoteCandidates, String *failure = nullptr)
   {
      remoteCandidates.clear();
      if (socket.configureCluster(cluster, failure) == false)
      {
         return false;
      }

      remoteCandidates = socket.unitTestRemoteMachines();
      if (failure)
      {
         failure->clear();
      }
      return true;
   }
#endif

public:

	void start(int argc, char *argv[])
	{
		String operation;
		operation.setInvariant(argv[0]);

		argc -= 1;
		argv += 1;

		if (operation.equal("deploy"_ctv))
		{
			runDeploy(argc, argv);
		}
		else if (operation.equal("applicationReport"_ctv))
		{
			runApplicationReport(argc, argv);
		}
      else if (operation.equal("clusterReport"_ctv))
      {
         runClusterReport(argc, argv);
      }
      else if (operation.equal("createProviderCredential"_ctv))
      {
         runCreateProviderCredential(argc, argv);
      }
      else if (operation.equal("pullProviderCredential"_ctv))
      {
         runPullProviderCredential(argc, argv);
      }
      else if (operation.equal("pullProviderCredentials"_ctv))
      {
         runPullProviderCredentials(argc, argv);
      }
      else if (operation.equal("removeProviderCredential"_ctv))
      {
         runRemoveProviderCredential(argc, argv);
      }
      else if (operation.equal("destroyProviderMachines"_ctv))
      {
         runDestroyProviderMachines(argc, argv);
      }
      else if (operation.equal("destroyProviderClusterMachines"_ctv))
      {
         runDestroyProviderClusterMachines(argc, argv);
      }
      else if (operation.equal("surveyProviderMachineOffers"_ctv))
      {
         runSurveyProviderMachineOffers(argc, argv);
      }
      else if (operation.equal("estimateClusterHourlyCost"_ctv))
      {
         runEstimateClusterHourlyCost(argc, argv);
      }
      else if (operation.equal("recommendClusterForApplications"_ctv))
      {
         runRecommendClusterForApplications(argc, argv);
      }
      else if (operation.equal("createCluster"_ctv))
      {
         runCreateCluster(argc, argv);
      }
      else if (operation.equal("printClusters"_ctv))
      {
         runPrintClusters(argc, argv);
      }
      else if (operation.equal("setLocalClusterMembership"_ctv))
      {
         runSetLocalClusterMembership(argc, argv);
      }
      else if (operation.equal("setTestClusterMachineCount"_ctv))
      {
         runSetTestClusterMachineCount(argc, argv);
      }
      else if (operation.equal("upsertMachineSchemas"_ctv))
      {
         runUpsertMachineSchemas(argc, argv);
      }
      else if (operation.equal("deltaMachineBudget"_ctv))
      {
         runDeltaMachineBudget(argc, argv);
      }
      else if (operation.equal("deleteMachineSchema"_ctv))
      {
         runDeleteMachineSchema(argc, argv);
      }
      else if (operation.equal("removeCluster"_ctv))
      {
         runRemoveCluster(argc, argv);
      }
		else if (operation.equal("updateProdigy"_ctv))
		{
			runUpdateProdigy(argc, argv);
		}
		else if (operation.equal("reserveApplicationID"_ctv))
		{
			runReserveApplicationID(argc, argv);
		}
		else if (operation.equal("reserveServiceID"_ctv))
		{
			runReserveServiceID(argc, argv);
		}
		else if (operation.equal("upsertTlsVaultFactory"_ctv))
		{
			runUpsertTlsVaultFactory(argc, argv);
		}
		else if (operation.equal("upsertApiCredentialSet"_ctv))
		{
			runUpsertApiCredentialSet(argc, argv);
		}
		else if (operation.equal("registerRoutableSubnet"_ctv))
		{
			runRegisterRoutableSubnet(argc, argv);
		}
		else if (operation.equal("unregisterRoutableSubnet"_ctv))
		{
			runUnregisterRoutableSubnet(argc, argv);
		}
		else if (operation.equal("pullRoutableSubnets"_ctv))
		{
			runPullRoutableSubnets(argc, argv);
		}
      else if (operation.equal("registerRoutableAddress"_ctv))
      {
         runRegisterRoutableAddress(argc, argv);
      }
      else if (operation.equal("unregisterRoutableAddress"_ctv))
      {
         runUnregisterRoutableAddress(argc, argv);
      }
      else if (operation.equal("pullRoutableAddresses"_ctv))
      {
         runPullRoutableAddresses(argc, argv);
      }
		else if (operation.equal("mintClientTlsIdentity"_ctv))
		{
			runMintClientTlsIdentity(argc, argv);
		}
		else
		{
			basics_log("operation invalid\n");
			exit(EXIT_FAILURE);
		}
	}
};

int main (int argc, char *argv[])
{
   if (argc < 2)
   {
      static constexpr char usage[] =
         "must be called like: ./mothership [operation: help, createProviderCredential, pullProviderCredential, pullProviderCredentials, removeProviderCredential, destroyProviderMachines, destroyProviderClusterMachines, surveyProviderMachineOffers, estimateClusterHourlyCost, recommendClusterForApplications, createCluster, printClusters, setLocalClusterMembership, setTestClusterMachineCount, upsertMachineSchemas, deltaMachineBudget, deleteMachineSchema, removeCluster, deploy, applicationReport, clusterReport, updateProdigy, reserveApplicationID, reserveServiceID, registerRoutableSubnet, unregisterRoutableSubnet, pullRoutableSubnets, registerRoutableAddress, unregisterRoutableAddress, pullRoutableAddresses, upsertTlsVaultFactory, upsertApiCredentialSet, mintClientTlsIdentity]";
      std::fwrite(usage, 1, sizeof(usage) - 1, stdout);
      exit(EXIT_FAILURE);
   }

	String operation;
	operation.setInvariant(argv[1]);

	if (operation.equal("help"_ctv))
   {
      String message;
      message.append("the following operations are available:\n"_ctv);
      message.append("createProviderCredential [json]\n");
         message.append("\tcreates a named provider auth profile in Mothership's local credential registry\n");
      message.append("pullProviderCredential [name]\n");
         message.append("\tshows one provider auth profile without printing any secret material\n");
      message.append("pullProviderCredentials\n");
         message.append("\tlists all provider auth profiles without printing any secret material\n");
      message.append("removeProviderCredential [name]\n");
         message.append("\tremoves one provider credential if no managed cluster still references it\n");
      message.append("destroyProviderMachines [provider] [providerCredentialName|providerCredentialOverride json] [providerScope] [json array of cloudIDs]\n");
         message.append("\tdestroys arbitrary provider machines by cloudID through BrainIaaS using a stored or inline provider credential\n");
      message.append("destroyProviderClusterMachines [provider] [providerCredentialName|providerCredentialOverride json] [providerScope] [clusterUUID]\n");
         message.append("\tdestroys all provider machines tagged with app=prodigy and the given clusterUUID through BrainIaaS using a stored or inline provider credential\n");
      message.append("surveyProviderMachineOffers [json]\n");
         message.append("\tsurveys AWS, GCP, and/or Azure machine offers for one required country, one required billingModel=hourly|spot, optional machineKinds vm|bareMetal, and optional requireFreeTierEligible\n");
         message.append("\tproviders may be [\"all\"] or explicit providers; if credentials are missing for requested providers, that is reported back explicitly\n");
      message.append("estimateClusterHourlyCost [json]\n");
         message.append("\testimates hourly cost for a concrete machine recipe on one explicit provider target within one required country and one required billingModel=hourly|spot\n");
         message.append("\taccepts optional ingressGBPerHour and egressGBPerHour and includes compute, extra storage, ingress, and egress cost components in the result\n");
      message.append("recommendClusterForApplications [json]\n");
         message.append("\trecommends the cheapest AWS/GCP/Azure cluster for a required country and billingModel=hourly|spot, optionally under budget, across providers=[\"all\"] or an explicit provider set\n");
         message.append("\taccepts required minMachines plus optional ingressGBPerHour and egressGBPerHour, and now considers up to three distinct machine types per recommendation\n");
      message.append("createCluster [json]\n");
         message.append("\tcreates a managed Prodigy cluster record, assigns a clusterUUID, and uses providerCredentialName or an inline providerCredentialOverride secret block\n");
         message.append("\tfor persistent fake clusters, prefer deploymentMode=test instead of invoking prodigy_dev_netns_harness.sh directly\n");
      message.append("printClusters\n");
         message.append("\tlists all managed Prodigy cluster records with their clusterUUIDs\n");
      message.append("setLocalClusterMembership [name|clusterUUID] [json]\n");
         message.append("\trequires deploymentMode=local and atomically replaces the stored local membership spec with exact json fields includeLocalMachine and machines before reconciling and persisting on live success\n");
      message.append("setTestClusterMachineCount [name|clusterUUID] [json]\n");
         message.append("\trequires deploymentMode=test and updates only test.machineCount through exact json field machineCount before restarting/reconciling and persisting on live success\n");
      message.append("upsertMachineSchemas [name|clusterUUID] [json object|array]\n");
         message.append("\tremote clusters only; creates or partially overwrites machine schema budget rows keyed by schema, then reconciles created capacity to match\n");
      message.append("deltaMachineBudget [name|clusterUUID] [json]\n");
         message.append("\tremote clusters only; requires an existing schema row, adds a signed delta to its budget, clamps the final budget to zero, and reconciles\n");
      message.append("deleteMachineSchema [name|clusterUUID] [schema]\n");
         message.append("\tremote clusters only; removes one machine schema budget row by schema and reconciles any excess created machines away\n");
      message.append("removeCluster [name|clusterUUID]\n");
         message.append("\tremoves one managed Prodigy cluster record\n");
      message.append("clusterReport [target: local|clusterName|clusterUUID]\n");
         message.append("\tfetches the current cluster-wide machine and application status report from the master brain\n");
         message.append("\tfor stored cluster targets, it also refreshes the cached authoritative topology and refresh metadata in the local cluster registry\n");
		message.append("deploy [target: local|clusterName|clusterUUID] [deployment plan json] [path to container blob]\n");
			message.append("\tdeploys an application on the cluster\n");
		message.append("applicationReport [target: local|clusterName|clusterUUID] [application name]\n");
			message.append("\tfetches the state of each deployment of the application\n");
			message.append("\tex: applicationReport local Radar\n");
		message.append("updateProdigy [target: local|clusterName|clusterUUID] [path to prodigy binary or bundle]\n");
			message.append("\tpushes the exact prodigy bundle this mothership build was compiled to approve, and rejects any other bundle before dispatch\n");
		message.append("reserveApplicationID [target: local|clusterName|clusterUUID] [json]\n");
			message.append("\treserves and returns an applicationID for an application name\n");
		message.append("reserveServiceID [target: dev|prod|local|clusterName|clusterUUID] [json]\n");
			message.append("\treserves and returns a serviceID for a reserved application service name\n");
		message.append("registerRoutableSubnet [target: local|clusterName|clusterUUID] [json]\n");
			message.append("\tregisters or updates a bgp-announced routable subnet; ipv4 must be /4../24 and ipv6 must be /4../48, the environment must have bgp enabled, and json.usage must be wormholes, whiteholes, or both\n");
		message.append("unregisterRoutableSubnet [target: local|clusterName|clusterUUID] [name]\n");
			message.append("\tremoves a routable subnet from the replicated registry by name\n");
		message.append("pullRoutableSubnets [target: local|clusterName|clusterUUID]\n");
			message.append("\tlists the currently registered routable subnets\n");
      message.append("registerRoutableAddress [target: local|clusterName|clusterUUID] [json]\n");
         message.append("\tregisters an exact externally reachable address of kind testFakeAddress, anyHostPublicAddress, or providerElasticAddress and returns its uuid\n");
      message.append("unregisterRoutableAddress [target: local|clusterName|clusterUUID] [name|uuid]\n");
         message.append("\tremoves a registered exact routable address by name or uuid\n");
      message.append("pullRoutableAddresses [target: local|clusterName|clusterUUID]\n");
         message.append("\tlists the currently registered exact routable addresses\n");
		message.append("upsertTlsVaultFactory [target: local|clusterName|clusterUUID] [json]\n");
			message.append("\tcreates/updates an application TLS vault factory\n");
		message.append("upsertApiCredentialSet [target: local|clusterName|clusterUUID] [json]\n");
			message.append("\tcreates/updates API credential set for an application\n");
		message.append("mintClientTlsIdentity [target: local|clusterName|clusterUUID] [json]\n");
			message.append("\tmints a client TLS identity from an existing application vault factory\n");

      if (message.size() > 0)
      {
		   std::fwrite(message.c_str(), 1, message.size(), stdout);
      }
	}
	else
	{
		Mothership mothership;
		mothership.start(argc - 1, ++argv);
	}

   return 0;
}
