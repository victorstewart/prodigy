if(NOT DEFINED PRODIGY_ROOT)
   message(FATAL_ERROR "PRODIGY_ROOT is required")
endif()

set(_harness "${PRODIGY_ROOT}/prodigy/dev/tests/prodigy_dev_netns_harness.sh")
set(_launcher "${PRODIGY_ROOT}/prodigy/dev/tests/prodigy_dev_test_cluster.sh")
set(_provider "${PRODIGY_ROOT}/prodigy/mothership/mothership.virtual.datacenter.provider.sh")
file(READ "${_harness}" _source)
file(READ "${_launcher}" _launcher_source)
file(READ "${_provider}" _provider_source)

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

foreach(_required IN ITEMS
   "\${machine_root}/var/log/prodigy"
   "mount --bind \"\${machine_root}/var/log/prodigy\" /var/log/prodigy")
   string(FIND "${_provider_source}" "${_required}" _position)
   if(_position EQUAL -1)
      message(FATAL_ERROR "virtual datacenter machines must isolate Prodigy logs: ${_required}")
   endif()
endforeach()

foreach(_required IN ITEMS
   "Darwin)"
   "container exec"
   "container stop"
   "container delete --force"
   "PRODIGY_DEV_TEST_BOUNDARY=apple-container"
   "prodigy-disposable-linux-v1")
   string(FIND "${_launcher_source}" "${_required}" _position)
   if(_position EQUAL -1)
      message(FATAL_ERROR "Prodigy test-cluster host launcher contract missing: ${_required}")
   endif()
endforeach()

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
