#pragma once

#include <cstdint>

// Compile-time timing knobs for brain bootstrap, recovery, and remediation.
// Override any of these with -D<NAME>=... to retune control-plane timing
// without editing the runtime logic itself.

// Dev mode runs inside slower local environments, so it keeps a larger retry
// budget and a shorter keepalive interval.
#ifndef PRODIGY_BRAIN_DEV_CONTROL_PLANE_CONNECT_TIMEOUT_MS
#define PRODIGY_BRAIN_DEV_CONTROL_PLANE_CONNECT_TIMEOUT_MS 100u
#endif

#ifndef PRODIGY_BRAIN_DEV_CONTROL_PLANE_CONNECT_ATTEMPTS
#define PRODIGY_BRAIN_DEV_CONTROL_PLANE_CONNECT_ATTEMPTS 20u
#endif

#ifndef PRODIGY_BRAIN_DEV_PEER_KEEPALIVE_SECONDS
#define PRODIGY_BRAIN_DEV_PEER_KEEPALIVE_SECONDS 6u
#endif

// Production control-plane traffic is same-datacenter east-west traffic. Keep
// each connect attempt short and let repeated retries plus creation-aware grace
// cover bootstrapping instead of multi-second socket hangs.
#ifndef PRODIGY_BRAIN_CONTROL_PLANE_CONNECT_TIMEOUT_MS
#define PRODIGY_BRAIN_CONTROL_PLANE_CONNECT_TIMEOUT_MS 250u
#endif

#ifndef PRODIGY_BRAIN_CONTROL_PLANE_CONNECT_ATTEMPTS
#define PRODIGY_BRAIN_CONTROL_PLANE_CONNECT_ATTEMPTS 3u
#endif

#ifndef PRODIGY_BRAIN_CONTROL_PLANE_SOFT_ESCALATION_FLOOR_MS
#define PRODIGY_BRAIN_CONTROL_PLANE_SOFT_ESCALATION_FLOOR_MS 1000u
#endif

#ifndef PRODIGY_BRAIN_PEER_KEEPALIVE_SECONDS
#define PRODIGY_BRAIN_PEER_KEEPALIVE_SECONDS 15u
#endif

// Remote bootstrap waits on a local Unix control socket after restarting the
// service on the target machine. Successful boots exit on the first connect;
// these knobs only bound how long we wait before surfacing diagnostics on a
// broken boot. Fresh cloud boots arm the listener within a couple seconds, so
// keep the failure budget short.
#ifndef PRODIGY_REMOTE_BOOTSTRAP_SSH_RETRY_SLEEP_MS
#define PRODIGY_REMOTE_BOOTSTRAP_SSH_RETRY_SLEEP_MS 250u
#endif

#ifndef PRODIGY_REMOTE_BOOTSTRAP_CONTROL_SOCKET_WAIT_SECONDS
#define PRODIGY_REMOTE_BOOTSTRAP_CONTROL_SOCKET_WAIT_SECONDS 5u
#endif

#ifndef PRODIGY_REMOTE_BOOTSTRAP_CONTROL_SOCKET_PROBE_TIMEOUT_MS
#define PRODIGY_REMOTE_BOOTSTRAP_CONTROL_SOCKET_PROBE_TIMEOUT_MS 200u
#endif

#ifndef PRODIGY_REMOTE_BOOTSTRAP_CONTROL_SOCKET_PROBE_SLEEP_MS
#define PRODIGY_REMOTE_BOOTSTRAP_CONTROL_SOCKET_PROBE_SLEEP_MS 100u
#endif

#ifndef PRODIGY_REMOTE_BOOTSTRAP_SOCKET_DIAGNOSTICS_TIMEOUT_SECONDS
#define PRODIGY_REMOTE_BOOTSTRAP_SOCKET_DIAGNOSTICS_TIMEOUT_SECONDS 10u
#endif

// Keep provider-side readiness polling tight enough to discover new machines
// quickly without shrinking the overall provisioning window. This upper bound
// covers cloud-controlled create latency, not healthy-path Prodigy runtime
// bootstrap after the machine is already reachable over SSH.
#ifndef PRODIGY_MACHINE_PROVISIONING_POLL_SLEEP_MS
#define PRODIGY_MACHINE_PROVISIONING_POLL_SLEEP_MS 500u
#endif

#ifndef PRODIGY_MACHINE_PROVISIONING_TIMEOUT_MS
#define PRODIGY_MACHINE_PROVISIONING_TIMEOUT_MS 600000u
#endif

// Neuron hardware inventory runs off the pre-listen critical path. Poll the
// completed result frequently enough to forward it quickly without turning
// control-socket readiness into a blocking wait.
#ifndef PRODIGY_NEURON_DEFERRED_HARDWARE_POLL_MS
#define PRODIGY_NEURON_DEFERRED_HARDWARE_POLL_MS 25u
#endif

// Recovery and watchdog timing.
#ifndef PRODIGY_BRAIN_POST_IGNITION_RECOVERY_TIMEOUT_MS
#define PRODIGY_BRAIN_POST_IGNITION_RECOVERY_TIMEOUT_MS 1000u
#endif

#ifndef PRODIGY_BRAIN_CONNECT_FAILURE_LOG_INTERVAL_MS
#define PRODIGY_BRAIN_CONNECT_FAILURE_LOG_INTERVAL_MS 5000u
#endif

#ifndef PRODIGY_BRAIN_PEER_RECOVERY_RECONNECT_MIN_MS
#define PRODIGY_BRAIN_PEER_RECOVERY_RECONNECT_MIN_MS 12000u
#endif

#ifndef PRODIGY_BRAIN_PEER_PERSISTENT_RECONNECT_MIN_MS
#define PRODIGY_BRAIN_PEER_PERSISTENT_RECONNECT_MIN_MS 30000u
#endif

#ifndef PRODIGY_BRAIN_PEER_INBOUND_MISSING_SLACK_MS
#define PRODIGY_BRAIN_PEER_INBOUND_MISSING_SLACK_MS 5u
#endif

#ifndef PRODIGY_BRAIN_HARD_REBOOT_WATCHDOG_MS
#define PRODIGY_BRAIN_HARD_REBOOT_WATCHDOG_MS 30000u
#endif

#ifndef PRODIGY_BRAIN_HARD_REBOOT_RECONNECT_WINDOW_MS
#define PRODIGY_BRAIN_HARD_REBOOT_RECONNECT_WINDOW_MS 29000u
#endif

#ifndef PRODIGY_BRAIN_SPOT_DECOMMISSION_CHECK_INTERVAL_MS
#define PRODIGY_BRAIN_SPOT_DECOMMISSION_CHECK_INTERVAL_MS 90000u
#endif

#ifndef PRODIGY_BRAIN_FAILED_DEPLOYMENT_CLEANER_INTERVAL_MS
#define PRODIGY_BRAIN_FAILED_DEPLOYMENT_CLEANER_INTERVAL_MS 90000u
#endif

// Local maintenance intervals.
#ifndef PRODIGY_BRAIN_METRIC_RETENTION_MS
#define PRODIGY_BRAIN_METRIC_RETENTION_MS (6ull * 60ull * 60ull * 1000ull)
#endif

#ifndef PRODIGY_BRAIN_METRIC_TRIM_MIN_INTERVAL_MS
#define PRODIGY_BRAIN_METRIC_TRIM_MIN_INTERVAL_MS 1000u
#endif

#ifndef PRODIGY_BRAIN_METRIC_PERSIST_MIN_INTERVAL_MS
#define PRODIGY_BRAIN_METRIC_PERSIST_MIN_INTERVAL_MS 1000u
#endif

#ifndef PRODIGY_BRAIN_AUTOSCALE_INTERVAL_MS
#define PRODIGY_BRAIN_AUTOSCALE_INTERVAL_MS 60000u
#endif

inline constexpr uint32_t prodigyBrainDevControlPlaneConnectTimeoutMs = PRODIGY_BRAIN_DEV_CONTROL_PLANE_CONNECT_TIMEOUT_MS;
inline constexpr uint32_t prodigyBrainDevControlPlaneConnectAttempts = PRODIGY_BRAIN_DEV_CONTROL_PLANE_CONNECT_ATTEMPTS;
inline constexpr uint32_t prodigyBrainDevPeerKeepaliveSeconds = PRODIGY_BRAIN_DEV_PEER_KEEPALIVE_SECONDS;

inline constexpr uint32_t prodigyBrainControlPlaneConnectTimeoutMs = PRODIGY_BRAIN_CONTROL_PLANE_CONNECT_TIMEOUT_MS;
inline constexpr uint32_t prodigyBrainControlPlaneConnectAttempts = PRODIGY_BRAIN_CONTROL_PLANE_CONNECT_ATTEMPTS;
inline constexpr uint32_t prodigyBrainControlPlaneSoftEscalationFloorMs = PRODIGY_BRAIN_CONTROL_PLANE_SOFT_ESCALATION_FLOOR_MS;
inline constexpr uint32_t prodigyBrainPeerKeepaliveSeconds = PRODIGY_BRAIN_PEER_KEEPALIVE_SECONDS;
inline constexpr uint32_t prodigyRemoteBootstrapSSHRetrySleepMs = PRODIGY_REMOTE_BOOTSTRAP_SSH_RETRY_SLEEP_MS;
inline constexpr uint32_t prodigyRemoteBootstrapControlSocketWaitSeconds = PRODIGY_REMOTE_BOOTSTRAP_CONTROL_SOCKET_WAIT_SECONDS;
inline constexpr uint32_t prodigyRemoteBootstrapControlSocketProbeTimeoutMs = PRODIGY_REMOTE_BOOTSTRAP_CONTROL_SOCKET_PROBE_TIMEOUT_MS;
inline constexpr uint32_t prodigyRemoteBootstrapControlSocketProbeSleepMs = PRODIGY_REMOTE_BOOTSTRAP_CONTROL_SOCKET_PROBE_SLEEP_MS;
inline constexpr uint32_t prodigyRemoteBootstrapSocketDiagnosticsTimeoutSeconds = PRODIGY_REMOTE_BOOTSTRAP_SOCKET_DIAGNOSTICS_TIMEOUT_SECONDS;
inline constexpr uint32_t prodigyMachineProvisioningPollSleepMs = PRODIGY_MACHINE_PROVISIONING_POLL_SLEEP_MS;
inline constexpr uint32_t prodigyMachineProvisioningTimeoutMs = PRODIGY_MACHINE_PROVISIONING_TIMEOUT_MS;
inline constexpr uint32_t prodigyNeuronDeferredHardwarePollMs = PRODIGY_NEURON_DEFERRED_HARDWARE_POLL_MS;

inline constexpr uint32_t prodigyBrainPostIgnitionRecoveryTimeoutMs = PRODIGY_BRAIN_POST_IGNITION_RECOVERY_TIMEOUT_MS;
inline constexpr uint32_t prodigyBrainConnectFailureLogIntervalMs = PRODIGY_BRAIN_CONNECT_FAILURE_LOG_INTERVAL_MS;
inline constexpr uint32_t prodigyBrainPeerRecoveryReconnectMinMs = PRODIGY_BRAIN_PEER_RECOVERY_RECONNECT_MIN_MS;
inline constexpr uint32_t prodigyBrainPeerPersistentReconnectMinMs = PRODIGY_BRAIN_PEER_PERSISTENT_RECONNECT_MIN_MS;
inline constexpr uint32_t prodigyBrainPeerInboundMissingSlackMs = PRODIGY_BRAIN_PEER_INBOUND_MISSING_SLACK_MS;
inline constexpr uint32_t prodigyBrainHardRebootWatchdogMs = PRODIGY_BRAIN_HARD_REBOOT_WATCHDOG_MS;
inline constexpr uint32_t prodigyBrainHardRebootReconnectWindowMs = PRODIGY_BRAIN_HARD_REBOOT_RECONNECT_WINDOW_MS;
inline constexpr uint32_t prodigyBrainSpotDecommissionCheckIntervalMs = PRODIGY_BRAIN_SPOT_DECOMMISSION_CHECK_INTERVAL_MS;
inline constexpr uint32_t prodigyBrainFailedDeploymentCleanerIntervalMs = PRODIGY_BRAIN_FAILED_DEPLOYMENT_CLEANER_INTERVAL_MS;

inline constexpr uint64_t prodigyBrainMetricRetentionMs = PRODIGY_BRAIN_METRIC_RETENTION_MS;
inline constexpr uint32_t prodigyBrainMetricTrimMinIntervalMs = PRODIGY_BRAIN_METRIC_TRIM_MIN_INTERVAL_MS;
inline constexpr uint32_t prodigyBrainMetricPersistMinIntervalMs = PRODIGY_BRAIN_METRIC_PERSIST_MIN_INTERVAL_MS;
inline constexpr uint32_t prodigyBrainAutoscaleIntervalMs = PRODIGY_BRAIN_AUTOSCALE_INTERVAL_MS;

static_assert(prodigyBrainControlPlaneConnectAttempts > 0, "production control-plane connect attempts must be non-zero");
static_assert(prodigyBrainDevControlPlaneConnectAttempts > 0, "dev control-plane connect attempts must be non-zero");
static_assert(prodigyRemoteBootstrapSSHRetrySleepMs > 0, "remote bootstrap ssh retry sleep must be non-zero");
static_assert(prodigyRemoteBootstrapControlSocketWaitSeconds > 0, "remote bootstrap control socket wait seconds must be non-zero");
static_assert(prodigyRemoteBootstrapControlSocketProbeTimeoutMs > 0, "remote bootstrap control socket probe timeout must be non-zero");
static_assert(prodigyRemoteBootstrapControlSocketProbeSleepMs > 0, "remote bootstrap control socket probe sleep must be non-zero");
static_assert(prodigyRemoteBootstrapSocketDiagnosticsTimeoutSeconds > 0, "remote bootstrap socket diagnostics timeout must be non-zero");
static_assert(prodigyMachineProvisioningPollSleepMs > 0, "machine provisioning poll sleep must be non-zero");
static_assert(prodigyMachineProvisioningTimeoutMs >= prodigyMachineProvisioningPollSleepMs, "machine provisioning timeout must cover at least one poll interval");
static_assert(prodigyNeuronDeferredHardwarePollMs > 0, "deferred neuron hardware poll must be non-zero");
static_assert(
   prodigyBrainControlPlaneSoftEscalationFloorMs >= (prodigyBrainControlPlaneConnectTimeoutMs * prodigyBrainControlPlaneConnectAttempts),
   "soft escalation floor must cover the full production control-plane reconnect window");
static_assert(
   prodigyBrainHardRebootReconnectWindowMs < prodigyBrainHardRebootWatchdogMs,
   "hard reboot reconnect window must expire before the hard reboot watchdog");
