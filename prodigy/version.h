#pragma once

// Unified binary version for both Brain and Neuron.
// Bump this when shipping a new prodigy binary.
constexpr inline uint64_t ProdigyBinaryVersion = 61;
constexpr inline uint64_t ProdigyStatefulDataAuthorityMinimumVersion = 27;

// Versions 19 and 20 reject unknown Brain topics. This floor chooses the wire
// vocabulary only; an authenticated, current-connection acknowledgement is
// still required before capability-dependent operations may activate.
constexpr inline uint64_t ProdigyBrainUpgradeCapabilityProtocolMinimumVersion = 21;

constexpr inline uint64_t ProdigyStatelessDeploymentAdmissionCapabilityMinimumVersion = 22;
constexpr inline uint64_t ProdigyPairedSourceRetirementCapabilityMinimumVersion = 23;
static_assert(ProdigyBinaryVersion >= ProdigyPairedSourceRetirementCapabilityMinimumVersion);

constexpr inline uint64_t ProdigyStatelessDeploymentRetirementCapabilityMinimumVersion = 44;
constexpr inline uint64_t ProdigyStatelessDeploymentRetirementCapability = 1048576;

// Generation selection changes durable authority and native launch framing.
// Activation also requires a fresh capability acknowledgement on this stream.
constexpr inline uint64_t ProdigyStatefulStoreGenerationMinimumVersion = 60;
constexpr inline uint64_t ProdigyStatefulStoreGenerationCapability = 2097152;

constexpr inline uint64_t ProdigyNativeMemberRepairMinimumVersion = 61;
constexpr inline uint64_t ProdigyNativeMemberRepairCapability = 4194304;
