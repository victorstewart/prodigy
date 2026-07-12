file(READ "${PRODIGY_ROOT}/prodigy/neuron/containers.h" CONTAINERS)

foreach(REQUIRED IN ITEMS
   "static int create_cgroupv2(Container *container, String *failureReport = nullptr)"
   "requireCgroupSetting(\"cgroup.max.descendants\"_ctv, cgroupBound)"
   "requireCgroupSetting(\"cgroup.max.depth\"_ctv, \"1\"_ctv)"
   "requireCgroupSetting(\"pids.max\"_ctv, maxPids_string)"
   "container->cgroup = create_cgroupv2(container, &cgroupFailure)"
   "container->plan.config.isolatedChildMemoryMB != 0 || cgroupFailure.size() > 0")
   string(FIND "${CONTAINERS}" "${REQUIRED}" POSITION)
   if(POSITION EQUAL -1)
      message(FATAL_ERROR "container cgroup bounds must fail closed: missing ${REQUIRED}")
   endif()
endforeach()

