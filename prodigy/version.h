#pragma once

// Unified binary version for both Brain and Neuron.
// Bump this when shipping a new prodigy binary.
constexpr inline uint64_t ProdigyBinaryVersion = 24;

// Versions 19 and 20 reject unknown Brain topics. This floor chooses the wire
// vocabulary only; an authenticated, current-connection acknowledgement is
// still required before capability-dependent operations may activate.
constexpr inline uint64_t ProdigyBrainUpgradeCapabilityProtocolMinimumVersion = 21;

constexpr inline uint64_t ProdigyStatelessDeploymentAdmissionCapabilityMinimumVersion = 22;
constexpr inline uint64_t ProdigyPairedSourceRetirementCapabilityMinimumVersion = 23;
static_assert(ProdigyBinaryVersion >= ProdigyPairedSourceRetirementCapabilityMinimumVersion);
