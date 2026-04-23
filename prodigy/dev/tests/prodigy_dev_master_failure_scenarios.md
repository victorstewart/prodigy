# Prodigy Dev Master-Assignment Failure Scenarios

This catalog is scoped to dev-mode bring-up in isolated network namespaces.

## Automated in `prodigy_dev_master_failure_matrix.sh`

1. `baseline_master1`
2. `follower2_transient_partition_heals_master1`
3. `follower3_transient_partition_heals_master1`
4. `follower2_permanent_partition_master1`
5. `master_transient_partition_requires_failover_master1`
6. `master_permanent_partition_requires_failover_master1`
7. `master_transient_crash_requires_failover_master1`
8. `follower2_transient_crash_recovers_master1`
9. `follower3_transient_crash_recovers_master1`
10. `master_permanent_crash_requires_failover_master1`
11. `master_transient_partition_requires_failover_master2`
12. `master_transient_partition_requires_failover_master3`
13. `no_majority_partition_1_2_master1`
14. `no_majority_partition_1_3_master1`
15. `no_majority_partition_2_3_master1`
16. `no_majority_partition_1_2_then_heal_master1`
17. `no_majority_crash_1_2_master1`
18. `follower2_flap_heals_master1`
19. `master_flap_recovers_quorum_master1`

Each case asserts one or more of:
- quorum master availability after fault
- leadership stability or change
- leadership change during fault window
- peer-mesh recovery after healing a transient partition

## Automated in `prodigy_dev_master_upgrade_sim.sh`

1. `mothership_update_prodigy_handover_master1`

## Not Yet Automated (tracked gaps)

1. Simultaneous follower upgrades:
   Expected flow: never lose majority while upgrades are staggered.
2. Long-running repeated partition flapping with randomized jitter:
   Expected flow: no split-brain and eventual convergence after flap ends.
3. Mothership disconnect/reconnect while cluster is healthy:
   Expected flow: control-plane reconnect without unsafe reconfiguration.

## Current Full-Matrix Status (latest run)

- Total cases: 19
- Passed: 17
- Failed:
  - `master_transient_crash_requires_failover_master1`
  - `follower3_transient_partition_heals_master1`

## Current Upgrade-Sim Status (latest run)

- Total cases: 1
- Passed: 1
- Failed: none
- `mothership_update_prodigy_handover_master1`: update dispatched and master handover observed
