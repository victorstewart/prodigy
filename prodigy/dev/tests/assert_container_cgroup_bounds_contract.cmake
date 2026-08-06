file(READ "${PRODIGY_ROOT}/prodigy/neuron/containers.h" CONTAINERS)
file(READ "${PRODIGY_ROOT}/prodigy/mothership/mothership.virtual.datacenter.provider.sh" VIRTUAL_DATACENTER_PROVIDER)

foreach(REQUIRED IN ITEMS
   "static int create_cgroupv2(Container *container, String *failureReport = nullptr)"
   "requireCgroupSetting(\"cgroup.max.descendants\"_ctv, cgroupBound)"
   "requireCgroupSetting(\"cgroup.max.depth\"_ctv, \"1\"_ctv)"
   "requireCgroupSetting(\"pids.max\"_ctv, maxPids_string)"
   "requireCgroupSetting(\"cpu.max\"_ctv, cpuMax)"
   "container->cgroup = create_cgroupv2(container, &cgroupFailure)")
   string(FIND "${CONTAINERS}" "${REQUIRED}" POSITION)
   if(POSITION EQUAL -1)
      message(FATAL_ERROR "container cgroup bounds must fail closed: missing ${REQUIRED}")
   endif()
endforeach()

foreach(REQUIRED IN ITEMS
   "const char *overcommit = getenv(\"PRODIGY_DEV_TEST_OVERCOMMIT_CPUS\")")
   string(FIND "${CONTAINERS}" "${REQUIRED}" POSITION)
   if(POSITION EQUAL -1)
      message(FATAL_ERROR "test-cluster CPU overcommit must preserve production cpuset partitions: missing ${REQUIRED}")
   endif()
endforeach()

foreach(REQUIRED IN ITEMS
   "(prodigyTestClusterOvercommitsCPUs() == false &&"
   "if (container->plan.usesIsolatedCPUs() && prodigyTestClusterOvercommitsCPUs() == false)")
   string(FIND "${CONTAINERS}" "${REQUIRED}" POSITION)
   if(POSITION EQUAL -1)
      message(FATAL_ERROR "cpuset partition roots must preserve production isolation and shared CPU semantics: missing ${REQUIRED}")
   endif()
endforeach()

string(FIND "${VIRTUAL_DATACENTER_PROVIDER}" "PRODIGY_DEV_TEST_OVERCOMMIT_CPUS=1" POSITION)
if(POSITION EQUAL -1)
   message(FATAL_ERROR "virtual datacenter provider must opt fake machines into test-only CPU overcommit")
endif()

foreach(REQUIRED IN ITEMS
   [[printf '1\n' > "${machine_cgroup}/cgroup.kill"]]
   [[find "${machine_cgroup}" -mindepth 1 -depth -type d -exec rmdir {} \;]]
   [[child="$(find "${machine_cgroup}" -mindepth 1 -maxdepth 1 -type d -print -quit)"]]
   [=[if [[ -z "${child}" && ! -s "${machine_cgroup}/cgroup.procs" ]]]=]
   [[for controller in cpuset cpu memory pids]]
   [[printf -- '-%s\n' "${controller}" > "${machine_cgroup}/cgroup.subtree_control"]])
   string(FIND "${VIRTUAL_DATACENTER_PROVIDER}" "${REQUIRED}" POSITION)
   if(POSITION EQUAL -1)
      message(FATAL_ERROR "fake-machine restart must fully reset its cgroup: missing ${REQUIRED}")
   endif()
endforeach()

string(FIND "${VIRTUAL_DATACENTER_PROVIDER}" [[         reset_machine_cgroup "${index}"]] RESET_POSITION)
string(FIND "${VIRTUAL_DATACENTER_PROVIDER}" [[         start_machine "${index}"]] RESTART_POSITION REVERSE)
if(RESET_POSITION EQUAL -1 OR RESTART_POSITION EQUAL -1 OR RESET_POSITION GREATER RESTART_POSITION)
   message(FATAL_ERROR "fake-machine restart must reset its cgroup before starting the replacement process")
endif()
