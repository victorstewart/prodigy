if(NOT DEFINED PRODIGY_ROOT)
   message(FATAL_ERROR "PRODIGY_ROOT is required")
endif()

set(_harness "${PRODIGY_ROOT}/prodigy/dev/tests/prodigy_dev_netns_harness.sh")
set(_launcher "${PRODIGY_ROOT}/prodigy/dev/tests/prodigy_dev_test_cluster.sh")
set(_provider "${PRODIGY_ROOT}/prodigy/mothership/mothership.virtual.datacenter.provider.sh")
set(_mothership "${PRODIGY_ROOT}/prodigy/mothership/mothership.cpp")
set(_mothership_cluster_test "${PRODIGY_ROOT}/prodigy/mothership/mothership.cluster.test.h")
file(READ "${_harness}" _source)
file(READ "${_launcher}" _launcher_source)
file(READ "${_provider}" _provider_source)
file(READ "${_mothership}" _mothership_source)
file(READ "${_mothership_cluster_test}" _mothership_cluster_test_source)

foreach(_forbidden IN ITEMS
   "configureTestCluster"
   "ip netns"
   "unshare"
   "mkfs.btrfs"
   "/sys/fs/cgroup"
   "cgroup.procs"
   "mount -"
   "mount --"
   "tc filter"
   "tar --zstd -xf"
   "PRODIGY_DEV_PREATTACH_SWITCHBOARD_BALANCER"
   "SWITCHBOARD_USE_PREATTACHED_XDP"
   "configure_dev_switchboard_balancer"
   "attach_dev_switchboard_balancer"
   "bpftool map update"
   "bpftool map delete"
   "rootfs/logs/stdout.log"
   "rootfs/logs/stderr.log"
   "container exec"
   "container run")
   string(FIND "${_source}" "${_forbidden}" _position)
   if(NOT _position EQUAL -1)
      message(FATAL_ERROR "Prodigy harness assumes a runtime-owned responsibility: ${_forbidden}")
   endif()
endforeach()

set(_virtual_datacenter_test_helper [=[static inline bool mothershipClusterUsesVirtualDatacenter(const MothershipProdigyCluster& cluster)
{
  return cluster.deploymentMode == MothershipClusterDeploymentMode::test;
}]=])
string(FIND "${_mothership_cluster_test_source}" "${_virtual_datacenter_test_helper}" _virtual_datacenter_test_helper_position)
if(_virtual_datacenter_test_helper_position EQUAL -1)
   message(FATAL_ERROR "the virtual-datacenter ownership helper must select deploymentMode=test exactly")
endif()

string(FIND "${_mothership_source}" "bool startVirtualDatacenter" _virtual_datacenter_start)
string(FIND "${_mothership_source}" "if (mothershipClusterUsesVirtualDatacenter(cluster) == false)" _virtual_datacenter_start_gate)
string(FIND "${_mothership_source}" "mothershipStartVirtualDatacenterProvider(cluster, &failure)" _virtual_datacenter_start_provider)
string(FIND "${_mothership_source}" "bool stopVirtualDatacenter" _virtual_datacenter_stop)
if(_virtual_datacenter_start EQUAL -1 OR _virtual_datacenter_start_gate LESS _virtual_datacenter_start OR
   _virtual_datacenter_start_provider LESS _virtual_datacenter_start_gate OR
   _virtual_datacenter_start_provider GREATER _virtual_datacenter_stop)
   message(FATAL_ERROR "starting the synthetic virtual-datacenter provider must remain limited to test clusters")
endif()

string(SUBSTRING "${_mothership_source}" ${_virtual_datacenter_stop} -1 _virtual_datacenter_stop_source)
string(FIND "${_virtual_datacenter_stop_source}" "if (mothershipClusterUsesVirtualDatacenter(cluster) == false)" _virtual_datacenter_stop_gate)
string(FIND "${_virtual_datacenter_stop_source}" "mothershipStopVirtualDatacenterProvider(cluster, &failure)" _virtual_datacenter_stop_provider)
if(_virtual_datacenter_stop_gate EQUAL -1 OR _virtual_datacenter_stop_provider LESS _virtual_datacenter_stop_gate)
   message(FATAL_ERROR "stopping the synthetic virtual-datacenter provider must remain limited to test clusters")
endif()

foreach(_required IN ITEMS
   "\${machine_root}/var/log/prodigy"
   "mount --bind \"\${machine_root}/var/log/prodigy\" /var/log/prodigy")
   string(FIND "${_provider_source}" "${_required}" _position)
   if(_position EQUAL -1)
      message(FATAL_ERROR "virtual datacenter machines must isolate Prodigy logs: ${_required}")
   endif()
endforeach()

foreach(_required IN ITEMS
   "public_ingress_mtu=1500"
   "ip route replace 198.18.0.0/16 via 172.31.0.2 dev \"\${host_edge}\" mtu \"\${public_ingress_mtu}\""
   "ip netns exec \"\${parent_ns}\" ip route replace 198.18.0.0/16 via 10.0.0.10 dev vdcbr0 src 10.0.0.1 mtu \"\${public_ingress_mtu}\""
   "ip route del 198.18.0.0/16 via 172.31.0.2 dev \"\${host_edge}\""
   "iptables -t nat -A POSTROUTING ! -s 172.31.0.0/30 -d 198.18.0.0/16 -o \"\${host_edge}\" -j SNAT --to-source 172.31.0.1"
   "iptables -t nat -D POSTROUTING ! -s 172.31.0.0/30 -d 198.18.0.0/16 -o \"\${host_edge}\" -j SNAT --to-source 172.31.0.1")
   string(FIND "${_provider_source}" "${_required}" _position)
   if(_position EQUAL -1)
      message(FATAL_ERROR "virtual datacenter external boundary contract missing: ${_required}")
   endif()
endforeach()

foreach(_required IN ITEMS
   "Darwin)"
   "container exec"
   [["${launcher}" ensure "${instance}"]]
   [["${launcher}" stop "${instance}"]]
   [[/usr/bin/sudo /sbin/route -n add -net "${apple_route_prefix}" "${apple_guest_ipv4}"]]
   [[/usr/bin/sudo /sbin/route -n delete -net "${apple_route_prefix}" "${apple_guest_ipv4}"]]
   "PRODIGY_DEV_TEST_BOUNDARY=apple-container"
   "prodigy-disposable-linux-v1")
   string(FIND "${_launcher_source}" "${_required}" _position)
   if(_position EQUAL -1)
      message(FATAL_ERROR "Prodigy test-cluster host launcher contract missing: ${_required}")
   endif()
endforeach()

string(FIND "${_launcher_source}" "   Darwin)" _darwin_branch)
string(FIND "${_launcher_source}" "/usr/bin/sudo /sbin/route -n add -net \"\${apple_route_prefix}\" \"\${apple_guest_ipv4}\"" _darwin_route_add)
string(FIND "${_launcher_source}" "/usr/bin/sudo /sbin/route -n delete -net \"\${apple_route_prefix}\" \"\${apple_guest_ipv4}\"" _darwin_route_delete)
string(FIND "${_launcher_source}" "trap cleanup_apple_container EXIT" _darwin_cleanup_trap)
string(FIND "${_launcher_source}" "\"\${launcher}\" stop \"\${instance}\"" _darwin_container_stop)
string(FIND "${_launcher_source}" "   Linux)" _linux_branch)
if(_darwin_branch EQUAL -1 OR _linux_branch EQUAL -1 OR
   _darwin_cleanup_trap EQUAL -1 OR
   _darwin_route_add LESS _darwin_branch OR _darwin_route_add GREATER _linux_branch OR
   _darwin_route_delete LESS _darwin_branch OR _darwin_route_delete GREATER _linux_branch OR
   _darwin_cleanup_trap GREATER _darwin_route_add OR _darwin_route_delete GREATER _darwin_container_stop)
   message(FATAL_ERROR "Apple host route setup and teardown must remain confined to the Darwin launcher branch")
endif()

file(GLOB _scenario_scripts "${PRODIGY_ROOT}/prodigy/dev/tests/*.sh")
foreach(_scenario IN LISTS _scenario_scripts)
   file(READ "${_scenario}" _scenario_source)
   if(_scenario_source MATCHES "createCluster|prodigy_dev_netns_harness\\.sh")
      foreach(_forbidden IN ITEMS
         "configureTestCluster"
         "PRODIGY_DEV_CONTAINER_STORAGE_MOUNTS="
         "mkfs.ext4"
         "losetup"
         "ip netns add"
         "bpftool map update"
         "bpftool map delete")
         string(FIND "${_scenario_source}" "${_forbidden}" _position)
         if(NOT _position EQUAL -1)
            message(FATAL_ERROR "${_scenario}: test-cluster scenario assumes provider ownership: ${_forbidden}")
         endif()
      endforeach()
   endif()
endforeach()

if(_source MATCHES "ip link set[^\n]*bond0[^\n]*(xdp|xdpgeneric)[^\n]*obj" OR
   _source MATCHES "ip link set[^\n]*bond0[^\n]*xdp off")
   message(FATAL_ERROR "Prodigy harness must not attach, replace, or detach the runtime switchboard program")
endif()

foreach(_required IN ITEMS
   "\${mothership_bin}\" createCluster"
   "\${mothership_bin}\" removeCluster"
   "\${mothership_bin}\" reserveApplicationID"
   "\${mothership_bin}\" reserveServiceID"
   "\${mothership_bin}\" deploy"
   "\${mothership_bin}\" clusterReport"
   "\${mothership_bin}\" applicationReport"
   "\${mothership_bin}\" containerLogs")
   string(FIND "${_source}" "${_required}" _position)
   if(_position EQUAL -1)
      message(FATAL_ERROR "Prodigy harness Mothership-only control contract missing: ${_required}")
   endif()
endforeach()
