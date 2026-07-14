file(READ "${PRODIGY_ROOT}/prodigy/neuron/containers.h" CONTAINERS)
file(READ "${PRODIGY_ROOT}/prodigy/mothership/mothership.virtual.datacenter.provider.sh" VIRTUAL_DATACENTER_PROVIDER)

foreach(REQUIRED IN ITEMS
   "static int create_cgroupv2(Container *container, String *failureReport = nullptr)"
   "requireCgroupSetting(\"cgroup.max.descendants\"_ctv, cgroupBound)"
   "requireCgroupSetting(\"cgroup.max.depth\"_ctv, \"1\"_ctv)"
   "requireCgroupSetting(\"pids.max\"_ctv, maxPids_string)"
   "requireCgroupSetting(\"cpu.max\"_ctv, cpuMax)"
   "container->cgroup = create_cgroupv2(container, &cgroupFailure)"
   "container->plan.config.isolatedChildMemoryMB != 0 || cgroupFailure.size() > 0")
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
   "if (prodigyTestClusterOvercommitsCPUs() == false)"
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
