#include <prodigy/machine.hardware.h>
#include <services/debug.h>
#include <prodigy/cluster.machine.helpers.h>
#include <prodigy/types.h>

#include <cstring>
#include <cstdio>
#include <cstdlib>

class TestSuite
{
public:

   int failed = 0;

   void expect(bool condition, const char *name)
   {
      if (condition)
      {
         basics_log("PASS: %s\n", name);
      }
      else
      {
         basics_log("FAIL: %s\n", name);
         failed += 1;
      }
   }
};

static bool stringContains(const String& haystack, const char *needle)
{
   String text = {};
   text.assign(haystack);
   return std::strstr(text.c_str(), needle) != nullptr;
}

static bool stringContains(const String& haystack, const String& needle)
{
   String ownedNeedle = {};
   ownedNeedle.assign(needle);
   return stringContains(haystack, ownedNeedle.c_str());
}

int main(void)
{
   TestSuite suite;

   {
      const char *savedHome = std::getenv("HOME");
      const char *savedConfigHome = std::getenv("XDG_CONFIG_HOME");
      String savedHomeText = {};
      String savedConfigHomeText = {};
      if (savedHome != nullptr) savedHomeText.assign(savedHome);
      if (savedConfigHome != nullptr) savedConfigHomeText.assign(savedConfigHome);

      ::setenv("HOME", "/tmp/prodigy-home", 1);
      ::setenv("XDG_CONFIG_HOME", "/tmp/prodigy-config", 1);

      String prefix = {};
      prodigyAppendCommandPrefix(prefix, 7);
      suite.expect(stringContains(prefix, "HOME='/tmp/prodigy-home'"), "command_prefix_includes_home_env");
      suite.expect(stringContains(prefix, "XDG_CONFIG_HOME='/tmp/prodigy-config'"), "command_prefix_includes_xdg_config_env");
      suite.expect(stringContains(prefix, "timeout --preserve-status -k 1s 7s sh -lc "), "command_prefix_includes_timeout");

      if (savedHome != nullptr) ::setenv("HOME", savedHomeText.c_str(), 1);
      else ::unsetenv("HOME");
      if (savedConfigHome != nullptr) ::setenv("XDG_CONFIG_HOME", savedConfigHomeText.c_str(), 1);
      else ::unsetenv("XDG_CONFIG_HOME");
   }

   {
      const char *savedHome = std::getenv("HOME");
      const char *savedConfigHome = std::getenv("XDG_CONFIG_HOME");
      String savedHomeText = {};
      String savedConfigHomeText = {};
      if (savedHome != nullptr) savedHomeText.assign(savedHome);
      if (savedConfigHome != nullptr) savedConfigHomeText.assign(savedConfigHome);

      ::unsetenv("HOME");
      ::unsetenv("XDG_CONFIG_HOME");

      struct passwd *user = ::getpwuid(::geteuid());
      suite.expect(user != nullptr && user->pw_dir != nullptr && user->pw_dir[0] != '\0', "command_prefix_passwd_home_available");

      if (user != nullptr && user->pw_dir != nullptr && user->pw_dir[0] != '\0')
      {
         String prefix = {};
         prodigyAppendCommandPrefix(prefix, 3);

         String expectedHome = {};
         expectedHome.assign(user->pw_dir);
         String expectedHomeNeedle = {};
         expectedHomeNeedle.snprintf<"HOME='{}'"_ctv>(expectedHome);
         suite.expect(stringContains(prefix, expectedHomeNeedle), "command_prefix_falls_back_to_passwd_home");

         String expectedConfigHome = {};
         expectedConfigHome.assign(expectedHome);
         if (expectedConfigHome.size() > 0 && expectedConfigHome[expectedConfigHome.size() - 1] != '/')
         {
            expectedConfigHome.append('/');
         }
         expectedConfigHome.append(".config"_ctv);
         String expectedConfigNeedle = {};
         expectedConfigNeedle.snprintf<"XDG_CONFIG_HOME='{}'"_ctv>(expectedConfigHome);
         suite.expect(stringContains(prefix, expectedConfigNeedle), "command_prefix_falls_back_to_passwd_config_home");
      }

      if (savedHome != nullptr) ::setenv("HOME", savedHomeText.c_str(), 1);
      else ::unsetenv("HOME");
      if (savedConfigHome != nullptr) ::setenv("XDG_CONFIG_HOME", savedConfigHomeText.c_str(), 1);
      else ::unsetenv("XDG_CONFIG_HOME");
   }

   {
      MachineCpuHardwareProfile cpu = {};
      prodigyPopulateCpuIdentityFromCpuinfo(
         "x86_64"_ctv,
         "vendor_id\t: GenuineIntel\nmodel name\t: Intel(R) Xeon(R) Platinum 8488C\nflags\t\t: fpu sse sse2 ssse3 sse4_2 avx avx2 avx512f\n"_ctv,
         cpu
      );
      suite.expect(cpu.architecture == MachineCpuArchitecture::x86_64, "parse_cpu_arch_x86_64");
      suite.expect(cpu.architectureVersion == "x86_64"_ctv, "parse_cpu_arch_version_x86_64");
      suite.expect(cpu.vendor == "GenuineIntel"_ctv, "parse_cpu_vendor_x86");
      suite.expect(cpu.isaFeatures.size() == 8, "parse_cpu_features_x86_count");
      suite.expect(cpu.isaFeatures[6] == "avx2"_ctv, "parse_cpu_features_x86_avx2");
      suite.expect(cpu.isaFeatures[7] == "avx512f"_ctv, "parse_cpu_features_x86_avx512f");
   }

   {
      MachineCpuHardwareProfile cpu = {};
      prodigyPopulateCpuIdentityFromCpuinfo(
         "aarch64"_ctv,
         "CPU implementer\t: 0x41\nCPU architecture: 8\nFeatures\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics sve\n"_ctv,
         cpu
      );
      suite.expect(cpu.architecture == MachineCpuArchitecture::aarch64, "parse_cpu_arch_aarch64");
      suite.expect(cpu.architectureVersion == "armv8"_ctv, "parse_cpu_arch_version_armv8");
      suite.expect(cpu.vendor == "0x41"_ctv, "parse_cpu_vendor_arm");
      suite.expect(cpu.isaFeatures.size() == 10, "parse_cpu_features_arm_count");
      suite.expect(cpu.isaFeatures[1] == "asimd"_ctv, "parse_cpu_features_arm_neon");
      suite.expect(cpu.isaFeatures[9] == "sve"_ctv, "parse_cpu_features_arm_sve");
   }

   {
      ProdigyCpuInventorySnapshot snapshot = {};
      suite.expect(
         prodigyParseLscpuJSON(
            "{\"lscpu\":[{\"field\":\"Architecture:\",\"data\":\"x86_64\"},{\"field\":\"Vendor ID:\",\"data\":\"GenuineIntel\"},{\"field\":\"Model name:\",\"data\":\"Intel(R) Xeon(R)\"},{\"field\":\"Thread(s) per core:\",\"data\":\"2\"},{\"field\":\"Socket(s):\",\"data\":\"2\"},{\"field\":\"NUMA node(s):\",\"data\":\"2\"},{\"field\":\"L3 cache:\",\"data\":\"60 MiB\"}]}"_ctv,
            snapshot
         ),
         "parse_lscpu_json"
      );
      suite.expect(
         prodigyParseLscpuTopologyCSV(
            "# comment\n0,yes,0,0,0\n1,yes,0,0,0\n2,yes,0,0,1\n3,yes,0,0,1\n4,yes,1,1,0\n5,yes,1,1,0\n"_ctv,
            snapshot
         ),
         "parse_lscpu_topology_csv"
      );
      suite.expect(snapshot.logicalCores == 6, "parse_lscpu_topology_logical_cores");
      suite.expect(snapshot.physicalCores == 3, "parse_lscpu_topology_physical_cores");
      suite.expect(snapshot.sockets == 2, "parse_lscpu_topology_sockets");
      suite.expect(snapshot.numaNodes == 2, "parse_lscpu_topology_numa_nodes");
      suite.expect(snapshot.threadsPerCore == 2, "parse_lscpu_topology_threads_per_core");
      suite.expect(snapshot.l3CacheMB == 60, "parse_lscpu_json_l3_cache");
      suite.expect(snapshot.architecture == MachineCpuArchitecture::x86_64, "parse_lscpu_json_architecture");
   }

   {
      uint64_t score = 0;
      suite.expect(
         prodigyParseSysbenchCpuOutput(
            "events per second:  4123.44\n"_ctv,
            score
         ),
         "parse_sysbench_events_per_second"
      );
      suite.expect(score == 4123, "parse_sysbench_events_per_second_value");

      suite.expect(
         prodigyParseSysbenchCpuOutput(
            "total number of events: 12345\n\ntotal time: 3.00s\n"_ctv,
            score
         ),
         "parse_sysbench_total_events"
      );
      suite.expect(score == 4115, "parse_sysbench_total_events_value");
   }

   {
      MachineMemoryHardwareProfile memory = {};
      prodigyParseDmidecodeMemoryDevices(
         "Memory Device\n"
         "\tSize: 16384 MB\n"
         "\tLocator: DIMM_A1\n"
         "\tBank Locator: BANK 0\n"
         "\tType: DDR5\n"
         "\tSpeed: 5600 MT/s\n"
         "\tManufacturer: Micron\n"
         "\tSerial Number: 12345678\n"
         "\tPart Number: MTC20F2085S1RC48BA1R\n\n"
         "Memory Device\n"
         "\tSize: No Module Installed\n"
         "\tLocator: DIMM_A2\n"_ctv,
         memory
      );
      suite.expect(memory.technology == MachineMemoryTechnology::ddr5, "parse_memory_modules_technology");
      suite.expect(memory.modules.size() == 1, "parse_memory_modules_count");
      suite.expect(memory.modules[0].locator == "DIMM_A1"_ctv, "parse_memory_module_locator");
      suite.expect(memory.modules[0].manufacturer == "Micron"_ctv, "parse_memory_module_manufacturer");
      suite.expect(memory.modules[0].partNumber == "MTC20F2085S1RC48BA1R"_ctv, "parse_memory_module_part_number");
      suite.expect(memory.modules[0].sizeMB == 16384, "parse_memory_module_size_mb");
      suite.expect(memory.modules[0].speedMTps == 5600, "parse_memory_module_speed_mtps");

      uint32_t latencyNs = 0;
      suite.expect(prodigyParseLatMemRdOutput("\"stride=128\\n\"\n0.00097656 82.14\n"_ctv, latencyNs), "parse_lat_mem_rd_output");
      suite.expect(latencyNs == 82, "parse_lat_mem_rd_output_value");

      uint32_t bandwidthMBps = 0;
      suite.expect(prodigyParseBwMemOutput("0.0 182345.88\n"_ctv, bandwidthMBps), "parse_bw_mem_output");
      suite.expect(bandwidthMBps == 182346, "parse_bw_mem_output_value");
   }

   {
      Vector<ProdigyLsblkRow> rows = {};
      suite.expect(
         prodigyParseLsblkJSON(
            "{\"blockdevices\":[{\"name\":\"nvme0n1\",\"kname\":\"nvme0n1\",\"path\":\"/dev/nvme0n1\",\"type\":\"disk\",\"size\":21474836480,\"model\":\"Amazon Elastic Block Store\",\"serial\":\"vol0123\",\"wwn\":\"eui.abc\",\"rota\":0,\"tran\":\"nvme\",\"log-sec\":512,\"phy-sec\":4096,\"mountpoints\":[null],\"children\":[{\"name\":\"nvme0n1p1\",\"path\":\"/dev/nvme0n1p1\",\"type\":\"part\",\"size\":21473787904,\"mountpoints\":[\"/\"]}]}]}"_ctv,
            rows
         ),
         "parse_lsblk_json"
      );
      suite.expect(rows.size() == 2, "parse_lsblk_json_rows");
      suite.expect(rows[0].name == "nvme0n1"_ctv, "parse_lsblk_json_name");
      suite.expect(rows[0].path == "/dev/nvme0n1"_ctv, "parse_lsblk_json_path");
      suite.expect(rows[0].transport == "nvme"_ctv, "parse_lsblk_json_transport");
      suite.expect(rows[0].wwn == "eui.abc"_ctv, "parse_lsblk_json_wwn");
      suite.expect(rows[0].logicalSectorBytes == 512, "parse_lsblk_json_log_sec");
      suite.expect(rows[0].physicalSectorBytes == 4096, "parse_lsblk_json_phy_sec");
      suite.expect(prodigyParseDiskBus(rows[0].transport, rows[0].name) == MachineDiskBus::pcie, "parse_disk_bus_pcie");
      suite.expect(prodigyParseDiskKind(rows[0]) == MachineDiskKind::nvme, "parse_disk_kind_nvme");
   }

   {
      MachineDiskBenchmarkProfile benchmark = {};
      suite.expect(
         prodigyParseFioBenchmarkJSON(
            "{\"jobs\":[{\"read\":{\"bw_bytes\":104857600},\"write\":{\"bw_bytes\":52428800}}]}"_ctv,
            benchmark,
            true
         ),
         "parse_fio_sequential_output"
      );
      suite.expect(benchmark.sequentialReadMBps == 100, "parse_fio_sequential_read_bw");
      suite.expect(benchmark.sequentialWriteMBps == 50, "parse_fio_sequential_write_bw");

      MachineDiskBenchmarkProfile randomBenchmark = {};
      suite.expect(
         prodigyParseFioBenchmarkJSON(
            "{\"jobs\":[{\"read\":{\"iops\":1024.0,\"clat_ns\":{\"percentile\":{\"50.000000\":1000,\"95.000000\":2000,\"99.000000\":3000,\"99.900000\":4000}}},\"write\":{\"iops\":512.0,\"clat_ns\":{\"percentile\":{\"50.000000\":5000,\"95.000000\":6000,\"99.000000\":7000,\"99.900000\":8000}}}}]}"_ctv,
            randomBenchmark,
            false
         ),
         "parse_fio_random_output"
      );
      suite.expect(randomBenchmark.randomReadIops == 1024, "parse_fio_random_read_iops");
      suite.expect(randomBenchmark.randomWriteIops == 512, "parse_fio_random_write_iops");
      suite.expect(randomBenchmark.randomReadLatencyP99Us == 3, "parse_fio_random_read_p99");
      suite.expect(randomBenchmark.randomWriteLatencyP999Us == 8, "parse_fio_random_write_p999");
   }

   {
      uint32_t sentMbps = 0;
      uint32_t receivedMbps = 0;
      suite.expect(
         prodigyParseIperf3JSON(
            "{\"end\":{\"sum_sent\":{\"bits_per_second\":1234000000.0},\"sum_received\":{\"bits_per_second\":987000000.0}}}"_ctv,
            sentMbps,
            receivedMbps
         ),
         "parse_iperf3_json"
      );
      suite.expect(sentMbps == 1234, "parse_iperf3_sent_mbps");
      suite.expect(receivedMbps == 987, "parse_iperf3_received_mbps");
   }

   {
      uint32_t latencyMs = 0;
      uint32_t downloadMbps = 0;
      uint32_t uploadMbps = 0;
      String serverName = {};
      String interfaceName = {};
      IPAddress sourceAddress = {};
      suite.expect(
         prodigyParseSpeedtestJSON(
            "{\"type\":\"result\",\"timestamp\":\"2026-03-11T02:05:19Z\",\"ping\":{\"jitter\":0.127,\"latency\":4.788,\"low\":4.752,\"high\":5.156},\"download\":{\"bandwidth\":62286607,\"bytes\":906883468,\"elapsed\":15004,\"latency\":{\"iqm\":131.438,\"low\":4.626,\"high\":1847.744,\"jitter\":57.964}},\"upload\":{\"bandwidth\":63986117,\"bytes\":406138155,\"elapsed\":6302,\"latency\":{\"iqm\":6.503,\"low\":4.627,\"high\":15.696,\"jitter\":1.068}},\"packetLoss\":0,\"isp\":\"Cloudflare Warp\",\"interface\":{\"internalIp\":\"2606:4700:cf1:1000::3\",\"name\":\"CloudflareWARP\",\"macAddr\":\"00:00:00:00:00:00\",\"isVpn\":false,\"externalIp\":\"2a09:bac1:7680:1378::3ed:3\"},\"server\":{\"id\":56485,\"host\":\"secaucus.nj.speedtest.frontier.com\",\"port\":8080,\"name\":\"Frontier\",\"location\":\"Secaucus, NJ\",\"country\":\"United States\",\"ip\":\"2001:1960:3780::3\"},\"result\":{\"id\":\"e98feef5-a5ec-420d-a775-e3b9a9ceabc5\",\"url\":\"https://www.speedtest.net/result/c/e98feef5-a5ec-420d-a775-e3b9a9ceabc5\",\"persisted\":true}}"_ctv,
            latencyMs,
            downloadMbps,
            uploadMbps,
            &serverName,
            &interfaceName,
            &sourceAddress
         ),
         "parse_speedtest_json"
      );
      suite.expect(latencyMs == 5, "parse_speedtest_latency_ms");
      suite.expect(downloadMbps == 498, "parse_speedtest_download_mbps");
      suite.expect(uploadMbps == 512, "parse_speedtest_upload_mbps");
      suite.expect(serverName == "Frontier / Secaucus, NJ"_ctv, "parse_speedtest_server_name");
      suite.expect(interfaceName == "CloudflareWARP"_ctv, "parse_speedtest_interface_name");
      suite.expect(sourceAddress.equals(IPAddress("2606:4700:cf1:1000::3", true)), "parse_speedtest_source_address");
   }

   {
      MachineHardwareProfile hardware = {};
      prodigyDeferOptionalMachineHardwareBenchmarks(hardware);
      suite.expect(hardware.benchmarksComplete == false, "defer_optional_hardware_benchmarks_marks_incomplete");
      suite.expect(hardware.benchmarkFailure == "optional hardware benchmarks deferred from boot path"_ctv, "defer_optional_hardware_benchmarks_reason");

      hardware = {};
      hardware.network.internet.attempted = true;
      hardware.network.internet.latencyMs = 7;
      hardware.network.internet.downloadMbps = 900;
      hardware.network.internet.uploadMbps = 800;
      prodigyFinalizeMachineHardwareBenchmarks(hardware);
      suite.expect(hardware.benchmarksComplete, "finalize_optional_hardware_benchmarks_success");
      suite.expect(hardware.benchmarkFailure.size() == 0, "finalize_optional_hardware_benchmarks_clears_failure");

      hardware = {};
      hardware.network.internet.attempted = true;
      hardware.network.internet.failure = "speedtest failed"_ctv;
      prodigyFinalizeMachineHardwareBenchmarks(hardware);
      suite.expect(hardware.benchmarksComplete == false, "finalize_optional_hardware_benchmarks_marks_failure");
      suite.expect(hardware.benchmarkFailure == "one or more optional hardware benchmarks were unavailable or failed"_ctv, "finalize_optional_hardware_benchmarks_reason");
   }

   {
      Vector<MachineNicHardwareProfile> nics = {};
      suite.expect(
         prodigyPopulateNicsFromIpLinkJSON(
            nics,
            "[{\"ifname\":\"ens5\",\"address\":\"0a:11:22:33:44:55\",\"operstate\":\"UP\"},{\"ifname\":\"lo\",\"address\":\"00:00:00:00:00:00\",\"operstate\":\"UNKNOWN\"}]"_ctv
         ),
         "populate_nics_from_ip_link_json"
      );
      suite.expect(nics.size() == 1, "populate_nics_from_ip_link_json_count");
      suite.expect(nics[0].name == "ens5"_ctv, "populate_nics_from_ip_link_json_name");
      suite.expect(nics[0].mac == "0a:11:22:33:44:55"_ctv, "populate_nics_from_ip_link_json_mac");
      suite.expect(nics[0].up, "populate_nics_from_ip_link_json_up");

      prodigyParseEthtoolOutput("Speed: 10000Mb/s\nDuplex: Full\n"_ctv, nics[0]);
      suite.expect(nics[0].linkSpeedMbps == 10000, "parse_ethtool_speed");
      prodigyParseEthtoolDriverInfoOutput("driver: ena\nversion: 1.2.3\nbus-info: 0000:00:05.0\n"_ctv, nics[0]);
      suite.expect(nics[0].driver == "ena"_ctv, "parse_ethtool_driver");
      suite.expect(nics[0].busAddress == "0000:00:05.0"_ctv, "parse_ethtool_bus_info");

      String addressJSON = "[{\"ifname\":\"ens5\",\"addr_info\":[{\"family\":\"inet\",\"local\":\"172.31.15.235\",\"prefixlen\":20},{\"family\":\"inet6\",\"local\":\"2600:1f18:abcd::1\",\"prefixlen\":64}]}]"_ctv;
      String routeJSON = "[{\"dst\":\"default\",\"gateway\":\"172.31.0.1\",\"dev\":\"ens5\"},{\"dst\":\"::/0\",\"gateway\":\"2600:1f18:abcd::ffff\",\"dev\":\"ens5\"}]"_ctv;
      suite.expect(prodigyPopulateNicSubnetsFromJSON(nics, addressJSON, routeJSON), "populate_nic_subnets_from_json");
      suite.expect(nics[0].subnets.size() == 2, "populate_nic_subnets_count");
      suite.expect(nics[0].subnets[0].subnet.cidr == 20, "populate_nic_subnets_ipv4_cidr");
      suite.expect(nics[0].subnets[0].subnet.network.equals(IPAddress("172.31.0.0", false)), "populate_nic_subnets_ipv4_network");
      suite.expect(nics[0].subnets[0].gateway.equals(IPAddress("172.31.0.1", false)), "populate_nic_subnets_ipv4_gateway");
      suite.expect(nics[0].subnets[1].subnet.cidr == 64, "populate_nic_subnets_ipv6_cidr");
      suite.expect(nics[0].subnets[1].gateway.equals(IPAddress("2600:1f18:abcd::ffff", true)), "populate_nic_subnets_ipv6_gateway");

      MachineNetworkHardwareProfile network = {};
      network.nics = nics;
      network.internet.interfaceName = "ens5"_ctv;
      network.internet.sourceAddress = IPAddress("172.31.15.235", false);
      prodigyTagInternetReachableNicSubnets(network);
      suite.expect(network.nics[0].subnets[0].internetReachable, "tag_internet_reachable_nic_subnet_marks_matching_source");
      suite.expect(network.nics[0].subnets[1].internetReachable == false, "tag_internet_reachable_nic_subnet_leaves_other_family_clear");
   }

   {
      MachineHardwareProfile hardware = {};
      hardware.cpu.model = "Intel(R) Xeon(R)"_ctv;
      hardware.cpu.logicalCores = 8;
      hardware.memory.totalMB = 32768;
      hardware.inventoryComplete = true;
      hardware.network.internet.attempted = true;
      hardware.network.internet.latencyMs = 12;
      hardware.network.internet.downloadMbps = 500;
      hardware.network.internet.uploadMbps = 500;
      hardware.network.internet.sourceAddress = IPAddress("10.0.0.10", false);
      hardware.captures.push_back(MachineToolCapture{
         .tool = "lsblk"_ctv,
         .phase = "inventory"_ctv,
         .command = "lsblk -J"_ctv,
         .output = "{\"blockdevices\":[]}"_ctv,
         .attempted = true,
         .succeeded = true
      });

      MachineDiskHardwareProfile disk = {};
      disk.name = "nvme0n1"_ctv;
      disk.sizeMB = 512000;
      disk.benchmark.captures.push_back(MachineToolCapture{
         .tool = "fio"_ctv,
         .phase = "randread"_ctv,
         .output = "{\"jobs\":[]}"_ctv,
         .attempted = true,
         .succeeded = true
      });
      hardware.disks.push_back(disk);

      ClusterMachine clusterMachine = {};
      clusterMachine.ownership.mode = ClusterMachineOwnershipMode::wholeMachine;
      prodigyApplyHardwareProfileToClusterMachine(clusterMachine, hardware);

      suite.expect(prodigyMachineHardwareInventoryReady(clusterMachine.hardware), "cluster_machine_hardware_ready");
      suite.expect(clusterMachine.totalLogicalCores == 8, "cluster_machine_total_cores_from_hardware");
      suite.expect(clusterMachine.totalMemoryMB == 32768, "cluster_machine_total_memory_from_hardware");
      suite.expect(clusterMachine.totalStorageMB == 512000, "cluster_machine_total_storage_from_hardware");
      suite.expect(clusterMachine.ownedLogicalCores == 6, "cluster_machine_owned_cores_reserved");
      suite.expect(clusterMachine.ownedMemoryMB == (32768 - 4096), "cluster_machine_owned_memory_reserved");
      suite.expect(clusterMachine.ownedStorageMB == (512000 - 4096), "cluster_machine_owned_storage_reserved");
      suite.expect(clusterMachine.hardware.captures.size() == 1, "cluster_machine_preserves_global_captures");
      suite.expect(clusterMachine.hardware.disks[0].benchmark.captures.size() == 1, "cluster_machine_preserves_disk_captures");
      suite.expect(clusterMachine.hasInternetAccess, "cluster_machine_has_internet_access_from_hardware");
   }

   {
      MachineHardwareProfile hardware = {};
      hardware.cpu.logicalCores = 16;
      hardware.memory.totalMB = 65536;
      hardware.inventoryComplete = true;

      MachineDiskHardwareProfile disk = {};
      disk.sizeMB = 1024000;
      hardware.disks.push_back(disk);
      hardware.network.internet.attempted = true;
      hardware.network.internet.latencyMs = 9;
      hardware.network.internet.downloadMbps = 800;
      hardware.network.internet.uploadMbps = 700;
      hardware.network.internet.sourceAddress = IPAddress("192.168.1.20", false);

      Machine machine = {};
      machine.ownershipMode = uint8_t(ClusterMachineOwnershipMode::hardCaps);
      machine.ownershipLogicalCoresCap = 4;
      machine.ownershipMemoryMBCap = 8192;
      machine.ownershipStorageMBCap = 204800;
      prodigyApplyHardwareProfileToMachine(machine, hardware);

      suite.expect(machine.totalLogicalCores == 16, "machine_total_cores_from_hardware");
      suite.expect(machine.totalMemoryMB == 65536, "machine_total_memory_from_hardware");
      suite.expect(machine.totalStorageMB == 1024000, "machine_total_storage_from_hardware");
      suite.expect(machine.ownedLogicalCores == 4, "machine_owned_cores_hardcap");
      suite.expect(machine.ownedMemoryMB == 8192, "machine_owned_memory_hardcap");
      suite.expect(machine.ownedStorageMB == 204800, "machine_owned_storage_hardcap");
      suite.expect(machine.hasInternetAccess, "machine_has_internet_access_from_hardware");
   }

   {
      Machine machine = {};
      machine.totalLogicalCores = 2;
      machine.totalMemoryMB = 8192;
      machine.totalStorageMB = 51200;
      machine.ownedLogicalCores = 0;
      machine.ownedMemoryMB = 4096;
      machine.ownedStorageMB = 47104;

      suite.expect(prodigyMachineReadyResourcesAvailable(machine), "machine_ready_resources_use_total_cores_when_owned_zero");
   }

   {
      ClusterStatusReport report = {};
      MachineStatusReport& machine = report.machineReports.emplace_back();
      machine.cloud.schema = "aws-brain-vm"_ctv;
      machine.state = "healthy"_ctv;
      machine.isBrain = true;
      machine.cloud.cloudID = "i-0abc"_ctv;
      machine.ssh.address = "54.0.0.10"_ctv;
      machine.ssh.port = 22;
      prodigyAppendUniqueClusterMachineAddress(machine.addresses.publicAddresses, "54.0.0.10"_ctv, 24, "54.0.0.1"_ctv);
      prodigyAppendUniqueClusterMachineAddress(machine.addresses.privateAddresses, "10.0.0.10"_ctv, 24, "10.0.0.1"_ctv);
      machine.deployedContainers.push_back("c-1"_ctv);
      machine.applicationNames.push_back("radar"_ctv);
      machine.deploymentIDs.push_back("101"_ctv);
      machine.shardGroups.push_back("7"_ctv);
      machine.activeContainers = 1;
      machine.activeIsolatedLogicalCores = 2;
      machine.activeMemoryMB = 2048;
      machine.activeStorageMB = 8192;
      machine.reservedContainers = 1;
      machine.reservedIsolatedLogicalCores = 2;
      machine.reservedSharedCPUMillis = 500;
      machine.reservedMemoryMB = 1024;
      machine.reservedStorageMB = 4096;
      machine.approvedBundleSHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"_ctv;
      machine.updateStage = "idle"_ctv;
      machine.hardware.inventoryComplete = true;
      machine.hardware.cpu.model = "Intel(R) Xeon(R)"_ctv;
      machine.hardware.cpu.logicalCores = 8;
      machine.hardware.memory.totalMB = 32768;
      machine.hardware.network.internet.latencyMs = 12;
      machine.hardware.network.internet.downloadMbps = 940;
      machine.hardware.network.internet.uploadMbps = 880;
      machine.hardware.network.internet.serverName = "Example Fiber / Ashburn, VA"_ctv;
      machine.hardware.captures.push_back(MachineToolCapture{
         .tool = "lsblk"_ctv,
         .phase = "inventory"_ctv,
         .output = "{\"blockdevices\":[]}"_ctv,
         .attempted = true,
         .succeeded = true
      });

      String text = {};
      report.stringify(text);
      suite.expect(stringContains(text, "Machine: state=healthy role=brain cloudSchema=aws-brain-vm"), "cluster_report_includes_machine_schema");
      suite.expect(stringContains(text, "role=brain"), "cluster_report_includes_machine_role");
      suite.expect(stringContains(text, "placement containers=c-1 applications=radar deploymentIDs=101 shardGroups=7"), "cluster_report_includes_placement");
      suite.expect(stringContains(text, "capacity active containers=1 isolatedLogicalCores=2 sharedCPUMillis=0 memoryMB=2048 storageMB=8192 reserved containers=1 isolatedLogicalCores=2 sharedCPUMillis=500 memoryMB=1024 storageMB=4096"), "cluster_report_includes_capacity");
      suite.expect(stringContains(text, "maintenance runningProdigyVersion= approvedBundleSHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa updateStage=idle stagedBundleSHA256="), "cluster_report_includes_maintenance");
      suite.expect(stringContains(text, "tool=lsblk phase=inventory"), "cluster_report_includes_tool_capture");
      suite.expect(stringContains(text, "{\"blockdevices\":[]}"), "cluster_report_includes_tool_output");
      suite.expect(stringContains(text, "internet latencyMs=12 downloadMbps=940 uploadMbps=880 server=Example Fiber / Ashburn, VA"), "cluster_report_includes_internet_benchmark");
   }

   {
      ClusterStatusReport report = {};
      report.hasTopology = true;

      ClusterMachine& topologyMachine = report.topology.machines.emplace_back();
      topologyMachine.hardware.inventoryComplete = true;
      topologyMachine.hardware.cpu.model = "topology-cpu"_ctv;
      topologyMachine.hardware.captures.push_back(MachineToolCapture{
         .tool = "lspci"_ctv,
         .phase = "inventory"_ctv,
         .output = "topology-capture"_ctv,
         .attempted = true,
         .succeeded = true
      });
      MachineDiskHardwareProfile topologyDisk = {};
      topologyDisk.name = "nvme-topology"_ctv;
      topologyDisk.benchmark.captures.push_back(MachineToolCapture{
         .tool = "fio"_ctv,
         .phase = "benchmark"_ctv,
         .output = "topology-disk-capture"_ctv,
         .attempted = true,
         .succeeded = true
      });
      topologyMachine.hardware.disks.push_back(topologyDisk);

      MachineStatusReport& machine = report.machineReports.emplace_back();
      machine.hardware.inventoryComplete = true;
      machine.hardware.cpu.model = "machine-cpu"_ctv;
      machine.hardware.network.internet.downloadMbps = 1234;
      machine.hardware.captures.push_back(MachineToolCapture{
         .tool = "dmidecode"_ctv,
         .phase = "inventory"_ctv,
         .output = "machine-capture"_ctv,
         .attempted = true,
         .succeeded = true
      });
      MachineDiskHardwareProfile machineDisk = {};
      machineDisk.name = "nvme-machine"_ctv;
      machineDisk.benchmark.captures.push_back(MachineToolCapture{
         .tool = "fio"_ctv,
         .phase = "benchmark"_ctv,
         .output = "machine-disk-capture"_ctv,
         .attempted = true,
         .succeeded = true
      });
      machine.hardware.disks.push_back(machineDisk);

      prodigyPrepareClusterStatusReportForTransport(report);

      suite.expect(report.topology.machines[0].hardware.captures.size() == 0, "cluster_report_transport_strips_topology_global_captures");
      suite.expect(report.topology.machines[0].hardware.disks[0].benchmark.captures.size() == 0, "cluster_report_transport_strips_topology_disk_captures");
      suite.expect(report.machineReports[0].hardware.captures.size() == 0, "cluster_report_transport_strips_machine_global_captures");
      suite.expect(report.machineReports[0].hardware.disks[0].benchmark.captures.size() == 0, "cluster_report_transport_strips_machine_disk_captures");
      suite.expect(report.topology.machines[0].hardware.cpu.model == "topology-cpu"_ctv, "cluster_report_transport_keeps_topology_summary");
      suite.expect(report.machineReports[0].hardware.cpu.model == "machine-cpu"_ctv, "cluster_report_transport_keeps_machine_summary");
      suite.expect(report.machineReports[0].hardware.network.internet.downloadMbps == 1234, "cluster_report_transport_keeps_machine_internet_summary");

      String serialized = {};
      BitseryEngine::serialize(serialized, report);
      ClusterStatusReport roundtrip = {};
      suite.expect(BitseryEngine::deserializeSafe(serialized, roundtrip), "cluster_report_transport_roundtrip");
      suite.expect(roundtrip.topology.machines.size() == 1, "cluster_report_transport_roundtrip_topology_machine_count");
      suite.expect(roundtrip.machineReports.size() == 1, "cluster_report_transport_roundtrip_machine_report_count");
      suite.expect(roundtrip.topology.machines[0].hardware.captures.size() == 0, "cluster_report_transport_roundtrip_topology_captures_cleared");
      suite.expect(roundtrip.machineReports[0].hardware.captures.size() == 0, "cluster_report_transport_roundtrip_machine_captures_cleared");
   }

   {
      ClusterTopology topology = {};
      ClusterMachine& machine = topology.machines.emplace_back();
      machine.hardware.inventoryComplete = true;
      machine.hardware.cpu.model = "topology-cpu"_ctv;
      machine.hardware.cpu.logicalCores = 12;
      machine.hardware.memory.totalMB = 65536;
      machine.hardware.network.internet.downloadMbps = 1500;
      machine.hardware.captures.push_back(MachineToolCapture{
         .tool = "dmidecode"_ctv,
         .phase = "inventory"_ctv,
         .output = "global-capture"_ctv,
         .attempted = true,
         .succeeded = true
      });
      machine.hardware.cpu.captures.push_back(MachineToolCapture{
         .tool = "lscpu"_ctv,
         .phase = "inventory"_ctv,
         .output = "cpu-capture"_ctv,
         .attempted = true,
         .succeeded = true
      });
      MachineDiskHardwareProfile disk = {};
      disk.name = "nvme-authoritative"_ctv;
      disk.sizeMB = 2048000;
      disk.benchmark.captures.push_back(MachineToolCapture{
         .tool = "fio"_ctv,
         .phase = "benchmark"_ctv,
         .output = "disk-capture"_ctv,
         .attempted = true,
         .succeeded = true
      });
      machine.hardware.disks.push_back(disk);

      String dirty = {};
      BitseryEngine::serialize(dirty, topology);

      prodigyStripMachineHardwareCapturesFromClusterTopology(topology);

      String clean = {};
      BitseryEngine::serialize(clean, topology);

      suite.expect(topology.machines[0].hardware.captures.empty(), "authoritative_topology_transport_strips_global_captures");
      suite.expect(topology.machines[0].hardware.cpu.captures.empty(), "authoritative_topology_transport_strips_cpu_captures");
      suite.expect(topology.machines[0].hardware.disks[0].benchmark.captures.empty(), "authoritative_topology_transport_strips_disk_captures");
      suite.expect(topology.machines[0].hardware.cpu.model == "topology-cpu"_ctv, "authoritative_topology_transport_keeps_cpu_summary");
      suite.expect(topology.machines[0].hardware.cpu.logicalCores == 12, "authoritative_topology_transport_keeps_core_summary");
      suite.expect(topology.machines[0].hardware.memory.totalMB == 65536, "authoritative_topology_transport_keeps_memory_summary");
      suite.expect(topology.machines[0].hardware.network.internet.downloadMbps == 1500, "authoritative_topology_transport_keeps_network_summary");
      suite.expect(clean.size() < dirty.size(), "authoritative_topology_transport_shrinks_serialized_payload");
   }

   return suite.failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
