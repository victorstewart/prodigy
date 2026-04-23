#include <prodigy/persistent.state.h>
#include <prodigy/remote.bootstrap.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

class TestClusterMachineSpec
{
public:

   String private4;
   String private6;
   String public6;
   uint32_t rackUUID = 0;
};

static void printUsage(const char *argv0)
{
   std::fprintf(
      stderr,
      "usage: %s --role=brain|neuron --control-socket-path=/path --local-index=N --brains=N --machine=PRIVATE4,PRIVATE6,PUBLIC6[,RACK] [...]\n",
      argv0);
}

static bool parseUInt32(const char *text, uint32_t& value)
{
   if (text == nullptr || text[0] == '\0')
   {
      return false;
   }

   char *tail = nullptr;
   unsigned long parsed = std::strtoul(text, &tail, 10);
   if (tail == nullptr || tail[0] != '\0' || parsed > UINT32_MAX)
   {
      return false;
   }

   value = uint32_t(parsed);
   return true;
}

static bool splitMachineArgument(const char *text, TestClusterMachineSpec& spec)
{
   if (text == nullptr || text[0] == '\0')
   {
      return false;
   }

   std::vector<String> fields;
   const char *cursor = text;
   const char *fieldStart = text;
   while (true)
   {
      if (*cursor == ',' || *cursor == '\0')
      {
         String field = {};
         field.setInvariant(fieldStart, uint64_t(cursor - fieldStart));
         fields.push_back(field);

         if (*cursor == '\0')
         {
            break;
         }

         fieldStart = cursor + 1;
      }

      cursor += 1;
   }

   if (fields.size() != 3 && fields.size() != 4)
   {
      return false;
   }

   auto assignIfPresent = [] (const String& input, String& output) -> void {

      if (input.size() == 0 || input.equals("-"_ctv))
      {
         output.clear();
         return;
      }

      output.assign(input);
   };

   assignIfPresent(fields[0], spec.private4);
   assignIfPresent(fields[1], spec.private6);
   assignIfPresent(fields[2], spec.public6);

   if (fields.size() == 4)
   {
      String ownedRack = {};
      ownedRack.assign(fields[3]);
      if (ownedRack.size() > 0 && ownedRack.equals("-"_ctv) == false)
      {
         uint32_t parsedRackUUID = 0;
         if (parseUInt32(ownedRack.c_str(), parsedRackUUID) == false)
         {
            return false;
         }

         spec.rackUUID = parsedRackUUID;
      }
   }

   return spec.private4.size() > 0 || spec.private6.size() > 0 || spec.public6.size() > 0;
}

static void appendMachineAddressIfPresent(Vector<ClusterMachineAddress>& addresses, const String& address, uint8_t cidr)
{
   if (address.size() == 0)
   {
      return;
   }

   prodigyAppendUniqueClusterMachineAddress(addresses, address, cidr);
}

int main(int argc, char *argv[])
{
   String role = {};
   String controlSocketPath = {};
   uint32_t localIndex = 0;
   uint32_t nBrains = 0;
   std::vector<TestClusterMachineSpec> machineSpecs;

   for (int index = 1; index < argc; ++index)
   {
      const char *arg = argv[index];

      if (std::strncmp(arg, "--role=", 7) == 0)
      {
         role.assign(arg + 7);
      }
      else if (std::strncmp(arg, "--control-socket-path=", 22) == 0)
      {
         controlSocketPath.assign(arg + 22);
      }
      else if (std::strncmp(arg, "--local-index=", 14) == 0)
      {
         if (parseUInt32(arg + 14, localIndex) == false)
         {
            std::fprintf(stderr, "invalid --local-index\n");
            return EXIT_FAILURE;
         }
      }
      else if (std::strncmp(arg, "--brains=", 9) == 0)
      {
         if (parseUInt32(arg + 9, nBrains) == false)
         {
            std::fprintf(stderr, "invalid --brains\n");
            return EXIT_FAILURE;
         }
      }
      else if (std::strncmp(arg, "--machine=", 10) == 0)
      {
         TestClusterMachineSpec spec = {};
         if (splitMachineArgument(arg + 10, spec) == false)
         {
            std::fprintf(stderr, "invalid --machine argument\n");
            return EXIT_FAILURE;
         }

         machineSpecs.push_back(spec);
      }
      else
      {
         std::fprintf(stderr, "unknown argument: %s\n", arg);
         printUsage(argv[0]);
         return EXIT_FAILURE;
      }
   }

   if ((role.equal("brain"_ctv) == false && role.equal("neuron"_ctv) == false)
      || controlSocketPath.size() == 0
      || localIndex == 0
      || nBrains == 0
      || machineSpecs.empty())
   {
      printUsage(argv[0]);
      return EXIT_FAILURE;
   }

   if (localIndex > machineSpecs.size())
   {
      std::fprintf(stderr, "local index out of range\n");
      return EXIT_FAILURE;
   }

   if (nBrains > machineSpecs.size())
   {
      std::fprintf(stderr, "brain count exceeds machine count\n");
      return EXIT_FAILURE;
   }

   ClusterTopology topology = {};
   topology.version = 1;

   for (uint32_t index = 0; index < machineSpecs.size(); ++index)
   {
      const TestClusterMachineSpec& spec = machineSpecs[index];

      ClusterMachine machine = {};
      machine.source = ClusterMachineSource::adopted;
      machine.backing = ClusterMachineBacking::owned;
      machine.kind = MachineConfig::MachineKind::vm;
      machine.lifetime = MachineLifetime::reserved;
      machine.isBrain = ((index + 1) <= nBrains);
      machine.rackUUID = (spec.rackUUID != 0) ? spec.rackUUID : (index + 1);
      machine.creationTimeMs = Time::now<TimeResolution::ms>();
      machine.ssh.port = 22;

      appendMachineAddressIfPresent(machine.addresses.privateAddresses, spec.private4, 24);
      appendMachineAddressIfPresent(machine.addresses.privateAddresses, spec.private6, 64);
      appendMachineAddressIfPresent(machine.addresses.publicAddresses, spec.public6, 64);

      if (spec.private4.size() > 0)
      {
         machine.ssh.address = spec.private4;
      }
      else if (spec.private6.size() > 0)
      {
         machine.ssh.address = spec.private6;
      }
      else
      {
         machine.ssh.address = spec.public6;
      }

      topology.machines.push_back(machine);
   }

   prodigyNormalizeClusterTopologyPeerAddresses(topology);

   ProdigyPersistentBootState bootState = {};
   bootState.bootstrapConfig.nodeRole = role.equal("brain"_ctv)
      ? ProdigyBootstrapNodeRole::brain
      : ProdigyBootstrapNodeRole::neuron;
   bootState.bootstrapConfig.controlSocketPath = controlSocketPath;
   bootState.initialTopology = topology;

   const ClusterMachine& localMachine = topology.machines[localIndex - 1];
   prodigyRenderClusterTopologyBootstrapPeers(localMachine, topology, bootState.bootstrapConfig.bootstrapPeers);

   String bootJSON = {};
   renderProdigyPersistentBootStateJSON(bootState, bootJSON);
   (void)std::fwrite(bootJSON.data(), 1, size_t(bootJSON.size()), stdout);
   (void)std::fputc('\n', stdout);
   return EXIT_SUCCESS;
}
