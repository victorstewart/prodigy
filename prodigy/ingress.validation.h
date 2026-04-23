#include <networking/includes.h>
#include <services/prodigy.h>
#include <prodigy/types.h>
#include <prodigy/wire.h>

#pragma once

namespace ProdigyIngressValidation
{
	static constexpr uint32_t maxMetricPairsPerFrame = 1024;
	static constexpr uint32_t maxContainerMessagePayloadBytes = 1U << 20;

	template <typename T>
	static bool extractFixed(uint8_t *&cursor, uint8_t *terminal, T& value)
	{
		static_assert(std::is_trivially_copyable_v<T>);

		constexpr uintptr_t alignmentMask = uintptr_t(alignof(T) - 1);
		uintptr_t aligned = (reinterpret_cast<uintptr_t>(cursor) + alignmentMask) & ~alignmentMask;
		uint8_t *alignedCursor = reinterpret_cast<uint8_t *>(aligned);

		if (alignedCursor > terminal)
		{
			return false;
		}

		if ((terminal - alignedCursor) < ptrdiff_t(sizeof(T)))
		{
			return false;
		}

		memcpy(&value, alignedCursor, sizeof(T));
		cursor = alignedCursor + sizeof(T);
		return true;
	}

	template <typename LengthType = uint32_t>
	static bool consumeVariable(uint8_t *&cursor, uint8_t *terminal)
	{
		LengthType rawLength = 0;
		if (extractFixed(cursor, terminal, rawLength) == false)
		{
			return false;
		}

		if constexpr (std::is_signed_v<LengthType>)
		{
			if (rawLength < 0)
			{
				return false;
			}
		}

		uint64_t payloadLength = uint64_t(rawLength);
		constexpr uintptr_t alignmentMask = uintptr_t(Alignment::eight) - 1;
		uintptr_t aligned = (reinterpret_cast<uintptr_t>(cursor) + alignmentMask) & ~alignmentMask;
		uint8_t *alignedCursor = reinterpret_cast<uint8_t *>(aligned);

		if (alignedCursor > terminal)
		{
			return false;
		}

		if (payloadLength > uint64_t(terminal - alignedCursor))
		{
			return false;
		}

		cursor = alignedCursor + payloadLength;
		return true;
	}

	template <typename LengthType = uint32_t>
	static bool consumeVariableBounded(uint8_t *&cursor, uint8_t *terminal, uint64_t maxPayloadLength)
	{
		LengthType rawLength = 0;
		if (extractFixed(cursor, terminal, rawLength) == false)
		{
			return false;
		}

		if constexpr (std::is_signed_v<LengthType>)
		{
			if (rawLength < 0)
			{
				return false;
			}
		}

		uint64_t payloadLength = uint64_t(rawLength);
		if (payloadLength > maxPayloadLength)
		{
			return false;
		}

		constexpr uintptr_t alignmentMask = uintptr_t(Alignment::eight) - 1;
		uintptr_t aligned = (reinterpret_cast<uintptr_t>(cursor) + alignmentMask) & ~alignmentMask;
		uint8_t *alignedCursor = reinterpret_cast<uint8_t *>(aligned);

		if (alignedCursor > terminal)
		{
			return false;
		}

		if (payloadLength > uint64_t(terminal - alignedCursor))
		{
			return false;
		}

		cursor = alignedCursor + payloadLength;
		return true;
	}

	static bool consumeMetricPairs(uint8_t *&cursor, uint8_t *terminal, uint32_t maxPairs = maxMetricPairsPerFrame)
	{
		uint32_t nPairs = 0;
		while (cursor < terminal)
		{
			uint64_t metricKey = 0;
			uint64_t metricValue = 0;

			if (nPairs >= maxPairs)
			{
				return false;
			}

			if (extractFixed(cursor, terminal, metricKey) == false)
			{
				return false;
			}

			if (extractFixed(cursor, terminal, metricValue) == false)
			{
				return false;
			}

			nPairs += 1;
		}

		return (cursor == terminal);
	}

	static bool consumeBytes(uint8_t *&cursor, uint8_t *terminal, uint64_t length)
	{
		if (length > uint64_t(terminal - cursor))
		{
			return false;
		}

		cursor += length;
		return true;
	}

	static bool consumeContainerPairingPayload(uint8_t *&cursor, uint8_t *terminal, bool includesPort)
	{
		if (cursor == nullptr || terminal == nullptr || cursor > terminal)
		{
			return false;
		}

		uint128_t secret = 0;
		uint128_t address = 0;
		uint64_t service = 0;
		uint16_t applicationID = 0;
		bool activate = false;
		bool ok = false;

		if (includesPort)
		{
			uint16_t port = 0;
			ok = ProdigyWire::deserializeSubscriptionPairingPayloadAuto(
				cursor,
				uint64_t(terminal - cursor),
				secret,
				address,
				service,
				port,
				applicationID,
				activate);
		}
		else
		{
			ok = ProdigyWire::deserializeAdvertisementPairingPayloadAuto(
				cursor,
				uint64_t(terminal - cursor),
				secret,
				address,
				service,
				applicationID,
				activate);
		}

		if (ok == false)
		{
			return false;
		}

		cursor = terminal;
		return true;
	}

	static bool validateMothershipPayload(uint16_t rawTopic, uint8_t *args, uint8_t *terminal)
	{
		if (args == nullptr || terminal == nullptr || args > terminal)
		{
			return false;
		}

		uint8_t *cursor = args;

		switch (MothershipTopic(rawTopic))
		{
			case MothershipTopic::configure:
			case MothershipTopic::upsertMachineSchemas:
			case MothershipTopic::deltaMachineBudget:
			case MothershipTopic::deleteMachineSchema:
			case MothershipTopic::updateProdigy:
			case MothershipTopic::measureApplication:
			case MothershipTopic::addMachines:
			case MothershipTopic::reserveApplicationID:
			case MothershipTopic::reserveServiceID:
			case MothershipTopic::upsertTlsVaultFactory:
			case MothershipTopic::upsertApiCredentialSet:
			case MothershipTopic::mintClientTlsIdentity:
			case MothershipTopic::registerRoutableSubnet:
			case MothershipTopic::unregisterRoutableSubnet:
         case MothershipTopic::registerRoutableAddress:
         case MothershipTopic::unregisterRoutableAddress:
			{
				return consumeVariable(cursor, terminal) && cursor == terminal;
			}
			case MothershipTopic::spinApplication:
			{
				uint16_t applicationID = 0;
				if (extractFixed(cursor, terminal, applicationID) == false) return false;
				if (consumeVariable(cursor, terminal) == false) return false;
				if (consumeVariable(cursor, terminal) == false) return false;
				return (cursor == terminal);
			}
			case MothershipTopic::destroyApplication:
			case MothershipTopic::pullApplicationReport:
			{
				uint16_t applicationID = 0;
				if (extractFixed(cursor, terminal, applicationID) == false) return false;
				return (cursor == terminal);
			}
			case MothershipTopic::pullClusterReport:
			case MothershipTopic::pullRoutableSubnets:
         case MothershipTopic::pullRoutableAddresses:
			{
				return (cursor == terminal);
			}
			default:
			{
				return false;
			}
		}
	}

	static bool validateBrainPayload(uint16_t rawTopic, uint8_t *args, uint8_t *terminal)
	{
		if (args == nullptr || terminal == nullptr || args > terminal)
		{
			return false;
		}

		uint8_t *cursor = args;

		switch (BrainTopic(rawTopic))
		{
			case BrainTopic::replicateMetricsAppend:
			{
				uint64_t deploymentID = 0;
				uint128_t containerUUID = 0;
				int64_t sampleTimeMs = 0;
				uint64_t metricKey = 0;
				uint64_t metricValue = 0;

				if (extractFixed(cursor, terminal, deploymentID) == false) return false;
				if (extractFixed(cursor, terminal, containerUUID) == false) return false;
				if (extractFixed(cursor, terminal, sampleTimeMs) == false) return false;
				if (extractFixed(cursor, terminal, metricKey) == false) return false;
				if (extractFixed(cursor, terminal, metricValue) == false) return false;
				return (cursor == terminal);
			}
         case BrainTopic::replicateContainerHealthy:
         case BrainTopic::replicateContainerRuntimeReady:
         {
            uint128_t containerUUID = 0;
            if (extractFixed(cursor, terminal, containerUUID) == false) return false;
            return (cursor == terminal);
         }
			case BrainTopic::replicateDeployment:
			{
				if ((terminal - args) == ptrdiff_t(sizeof(uint64_t)))
				{
					uint64_t deploymentID = 0;
					if (extractFixed(cursor, terminal, deploymentID) == false) return false;
					return (cursor == terminal);
				}

				if (consumeVariable(cursor, terminal) == false) return false;
				if (consumeVariable(cursor, terminal) == false) return false;
				return (cursor == terminal);
			}
			case BrainTopic::cullDeployment:
			{
				uint64_t deploymentID = 0;
				if (extractFixed(cursor, terminal, deploymentID) == false) return false;
				return (cursor == terminal);
			}
			case BrainTopic::reconcileState:
			{
				while (cursor < terminal)
				{
					uint64_t deploymentID = 0;
					if (extractFixed(cursor, terminal, deploymentID) == false) return false;
				}

				return (cursor == terminal);
			}
			case BrainTopic::registration:
			{
				uint128_t uuid = 0;
				int64_t boottimens = 0;
				uint64_t version = 0;
				uint128_t existingMasterUUID = 0;

				if (extractFixed(cursor, terminal, uuid) == false) return false;
				if (extractFixed(cursor, terminal, boottimens) == false) return false;
				if (extractFixed(cursor, terminal, version) == false) return false;
				if (extractFixed(cursor, terminal, existingMasterUUID) == false) return false;
				return (cursor == terminal);
			}
         case BrainTopic::peerAddressCandidates:
         {
            if (consumeVariable(cursor, terminal) == false) return false;
            return (cursor == terminal);
         }
			case BrainTopic::masterMissing:
			{
				if (cursor == terminal)
				{
					return true;
				}

				bool isMissing = false;
				if (extractFixed(cursor, terminal, isMissing) == false) return false;
				return (cursor == terminal);
			}
			case BrainTopic::updateBundle:
			{
				if (cursor == terminal)
				{
					return true;
				}

				if (consumeVariable(cursor, terminal) == false) return false;
				return (cursor == terminal);
			}
			case BrainTopic::transitionToNewBundle:
			{
				if (cursor == terminal)
				{
					return true;
				}

				uint8_t marker = 0;
				if (extractFixed(cursor, terminal, marker) == false) return false;
				return (cursor == terminal);
			}
			case BrainTopic::relinquishMasterStatus:
			{
				if (cursor == terminal)
				{
					return true;
				}

				uint8_t marker = 0;
				if (extractFixed(cursor, terminal, marker) == false) return false;

				if (cursor == terminal)
				{
					return true;
				}

				uint128_t designatedMasterUUID = 0;
				if (extractFixed(cursor, terminal, designatedMasterUUID) == false) return false;
				return (cursor == terminal);
			}
			case BrainTopic::replicateBrainConfig:
			case BrainTopic::replicateClusterTopology:
         case BrainTopic::replicateMasterAuthorityState:
         case BrainTopic::replicateMetricsSnapshot:
			case BrainTopic::replicateApplicationServiceReservation:
			case BrainTopic::replicateTlsVaultFactory:
			case BrainTopic::replicateApiCredentialSet:
			{
				if (consumeVariable(cursor, terminal) == false) return false;
				return (cursor == terminal);
			}
			case BrainTopic::replicateApplicationIDReservation:
			{
				uint16_t applicationID = 0;
				if (extractFixed(cursor, terminal, applicationID) == false) return false;
				if (consumeVariable(cursor, terminal) == false) return false;
				return (cursor == terminal);
			}
			case BrainTopic::reconcileMetrics:
			case BrainTopic::reconcileTd:
			case BrainTopic::replicateTdAppend:
			{
				return true;
			}
			default:
			{
				return false;
			}
		}
	}

	static bool validateNeuronPayloadForBrain(uint16_t rawTopic, uint8_t *args, uint8_t *terminal)
	{
		if (args == nullptr || terminal == nullptr || args > terminal)
		{
			return false;
		}

		uint8_t *cursor = args;

		switch (NeuronTopic(rawTopic))
		{
			case NeuronTopic::registration:
			{
				int64_t bootTimeMs = 0;
				bool haveData = false;

				if (extractFixed(cursor, terminal, bootTimeMs) == false) return false;
				if (consumeVariable(cursor, terminal) == false) return false;
				if (extractFixed(cursor, terminal, haveData) == false) return false;
				return (cursor == terminal);
			}
			case NeuronTopic::machineHardwareProfile:
			{
				return consumeVariable(cursor, terminal) && cursor == terminal;
			}
			case NeuronTopic::stateUpload:
			{
				uint32_t fragment = 0;
				if (extractFixed(cursor, terminal, fragment) == false) return false;

				while (cursor < terminal)
				{
					if (consumeVariable(cursor, terminal) == false) return false;
				}

				return (cursor == terminal);
			}
			case NeuronTopic::hardwareFailure:
			{
				if (consumeVariable(cursor, terminal) == false) return false;
				return (cursor == terminal);
			}
			case NeuronTopic::containerHealthy:
			case NeuronTopic::containerRuntimeReady:
			case NeuronTopic::killContainer:
			{
				uint128_t containerUUID = 0;
				if (extractFixed(cursor, terminal, containerUUID) == false) return false;
				return (cursor == terminal);
			}
				case NeuronTopic::containerStatistics:
				{
				uint64_t deploymentID = 0;
				uint128_t containerUUID = 0;
				int64_t sampleTimeMs = 0;

				if (extractFixed(cursor, terminal, deploymentID) == false) return false;
				if (extractFixed(cursor, terminal, containerUUID) == false) return false;
				if (extractFixed(cursor, terminal, sampleTimeMs) == false) return false;
					return consumeMetricPairs(cursor, terminal);
				}
			case NeuronTopic::containerFailed:
			{
				uint128_t containerUUID = 0;
				int64_t approxTimeMs = 0;
				int signal = 0;
				bool restarted = false;

				if (extractFixed(cursor, terminal, containerUUID) == false) return false;
				if (extractFixed(cursor, terminal, approxTimeMs) == false) return false;
				if (extractFixed(cursor, terminal, signal) == false) return false;
				if (consumeVariable(cursor, terminal) == false) return false;
				if (extractFixed(cursor, terminal, restarted) == false) return false;
				return (cursor == terminal);
			}
			case NeuronTopic::requestContainerBlob:
			{
				uint64_t deploymentID = 0;
				if (extractFixed(cursor, terminal, deploymentID) == false) return false;
				return (cursor == terminal);
			}
			case NeuronTopic::refreshContainerCredentials:
			{
				uint128_t containerUUID = 0;
				if (extractFixed(cursor, terminal, containerUUID) == false) return false;
				return (cursor == terminal);
			}
			case NeuronTopic::spotTerminationImminent:
			case NeuronTopic::ping:
			case NeuronTopic::pong:
			{
				return (cursor == terminal);
			}
			default:
			{
				return false;
			}
		}
	}

	static bool validateNeuronPayloadForNeuron(uint16_t rawTopic, uint8_t *args, uint8_t *terminal)
	{
		if (args == nullptr || terminal == nullptr || args > terminal)
		{
			return false;
		}

		uint8_t *cursor = args;

		switch (NeuronTopic(rawTopic))
		{
			case NeuronTopic::registration:
			{
				bool requiresState = false;
				if (extractFixed(cursor, terminal, requiresState) == false) return false;
				return (cursor == terminal);
			}
			case NeuronTopic::stateUpload:
			{
				uint32_t fragment = 0;
				if (extractFixed(cursor, terminal, fragment) == false) return false;

				while (cursor < terminal)
				{
					if (consumeVariable(cursor, terminal) == false) return false;
				}

				return (cursor == terminal);
			}
			case NeuronTopic::assignFragment:
			{
				uint32_t fragment = 0;
				if (extractFixed(cursor, terminal, fragment) == false) return false;
				return (cursor == terminal);
			}
			case NeuronTopic::requestContainerBlob:
			{
				uint64_t deploymentID = 0;
				if (extractFixed(cursor, terminal, deploymentID) == false) return false;
				if (consumeVariable(cursor, terminal) == false) return false;
				return (cursor == terminal);
			}
			case NeuronTopic::spinContainer:
			{
				uint128_t replaceContainerUUID = 0;
				if (extractFixed(cursor, terminal, replaceContainerUUID) == false) return false;
				if (consumeVariable(cursor, terminal) == false) return false;
				return (cursor == terminal);
			}
			case NeuronTopic::adjustContainerResources:
			{
				uint128_t containerUUID = 0;
				uint16_t nLogicalCores = 0;
				uint32_t memoryMB = 0;
				uint32_t storageMB = 0;
				if (extractFixed(cursor, terminal, containerUUID) == false) return false;
				if (extractFixed(cursor, terminal, nLogicalCores) == false) return false;
				if (extractFixed(cursor, terminal, memoryMB) == false) return false;
				if (extractFixed(cursor, terminal, storageMB) == false) return false;

				if (cursor == terminal)
				{
					return true;
				}

				bool isDownscale = false;
				if (extractFixed(cursor, terminal, isDownscale) == false) return false;

				if (cursor == terminal)
				{
					return true;
				}

				uint32_t graceSeconds = 0;
				if (extractFixed(cursor, terminal, graceSeconds) == false) return false;
				return (cursor == terminal);
			}
			case NeuronTopic::changeContainerLifetime:
			{
				uint128_t containerUUID = 0;
				ApplicationLifetime lifetime = ApplicationLifetime::base;
				if (extractFixed(cursor, terminal, containerUUID) == false) return false;
				if (extractFixed(cursor, terminal, lifetime) == false) return false;
				return (cursor == terminal);
			}
			case NeuronTopic::killContainer:
			{
				uint128_t containerUUID = 0;
				if (extractFixed(cursor, terminal, containerUUID) == false) return false;
				return (cursor == terminal);
			}
			case NeuronTopic::advertisementPairing:
			{
				uint128_t containerUUID = 0;
				if (extractFixed(cursor, terminal, containerUUID) == false) return false;
				return consumeContainerPairingPayload(cursor, terminal, false);
			}
			case NeuronTopic::subscriptionPairing:
			{
				uint128_t containerUUID = 0;
				if (extractFixed(cursor, terminal, containerUUID) == false) return false;
				return consumeContainerPairingPayload(cursor, terminal, true);
			}
			case NeuronTopic::resetSwitchboardState:
			{
				return (cursor == terminal);
			}
			case NeuronTopic::configureRuntimeEnvironment:
			{
				return consumeVariable(cursor, terminal) && cursor == terminal;
			}
			case NeuronTopic::configureSwitchboardRoutableSubnets:
         case NeuronTopic::configureSwitchboardHostedIngressPrefixes:
			{
				return consumeVariable(cursor, terminal) && cursor == terminal;
			}
			case NeuronTopic::configureSwitchboardOverlayRoutes:
			{
				return consumeVariable(cursor, terminal) && cursor == terminal;
			}
			case NeuronTopic::openSwitchboardWormholes:
			{
				uint32_t containerID = 0;
				if (extractFixed(cursor, terminal, containerID) == false) return false;
				return consumeVariable(cursor, terminal) && cursor == terminal;
			}
			case NeuronTopic::refreshContainerWormholes:
			case NeuronTopic::refreshContainerCredentials:
			{
				uint128_t containerUUID = 0;
				if (extractFixed(cursor, terminal, containerUUID) == false) return false;
				return consumeVariable(cursor, terminal) && cursor == terminal;
			}
			case NeuronTopic::closeSwitchboardWormholesToContainer:
			{
				uint32_t containerID = 0;
				if (extractFixed(cursor, terminal, containerID) == false) return false;
				return (cursor == terminal);
			}
			case NeuronTopic::openSwitchboardWhiteholes:
			{
				uint32_t containerID = 0;
				if (extractFixed(cursor, terminal, containerID) == false) return false;

				while (cursor < terminal)
				{
					uint16_t sourcePort = 0;
					bool isIPv6 = false;
					ExternalAddressTransport transport = ExternalAddressTransport::tcp;
					uint64_t bindingNonce = 0;

					if (extractFixed(cursor, terminal, sourcePort) == false) return false;
					if (consumeBytes(cursor, terminal, 16) == false) return false;
					if (extractFixed(cursor, terminal, isIPv6) == false) return false;
					if (extractFixed(cursor, terminal, transport) == false) return false;
					if (extractFixed(cursor, terminal, bindingNonce) == false) return false;
				}

				return (cursor == terminal);
			}
			case NeuronTopic::closeSwitchboardWhiteholesToContainer:
			{
				uint32_t containerID = 0;
				if (extractFixed(cursor, terminal, containerID) == false) return false;
				return (cursor == terminal);
			}
			default:
			{
				return false;
			}
		}
	}

	static bool validateContainerPayloadForNeuron(uint16_t rawTopic, uint8_t *args, uint8_t *terminal)
	{
		if (args == nullptr || terminal == nullptr || args > terminal)
		{
			return false;
		}

		uint8_t *cursor = args;

		switch (ContainerTopic(rawTopic))
		{
			case ContainerTopic::ping:
			case ContainerTopic::pong:
			case ContainerTopic::healthy:
			case ContainerTopic::runtimeReady:
			{
				return (cursor == terminal);
			}
			case ContainerTopic::statistics:
			{
				return consumeMetricPairs(cursor, terminal);
			}
			case ContainerTopic::resourceDeltaAck:
			{
				bool accepted = false;
				if (extractFixed(cursor, terminal, accepted) == false) return false;
				return (cursor == terminal);
			}
			case ContainerTopic::credentialsRefresh:
			{
				return (cursor == terminal);
			}
			default:
			{
				return false;
			}
		}
	}

	static bool validateContainerPayloadForHub(uint16_t rawTopic, uint8_t *args, uint8_t *terminal)
	{
		if (args == nullptr || terminal == nullptr || args > terminal)
		{
			return false;
		}

		uint8_t *cursor = args;

		switch (ContainerTopic(rawTopic))
		{
			case ContainerTopic::none:
			case ContainerTopic::ping:
			case ContainerTopic::pong:
			case ContainerTopic::healthy:
			case ContainerTopic::stop:
			{
				return (cursor == terminal);
			}
			case ContainerTopic::resourceDelta:
			{
				uint16_t nLogicalCores = 0;
				uint32_t memoryMB = 0;
				uint32_t storageMB = 0;
				bool isDownscale = false;
				uint32_t graceSeconds = 0;
				return ProdigyWire::deserializeResourceDeltaPayloadAuto(
					args,
					uint64_t(terminal - args),
					nLogicalCores,
					memoryMB,
					storageMB,
					isDownscale,
					graceSeconds);
			}
			case ContainerTopic::advertisementPairing:
			{
				uint128_t secret = 0;
				uint128_t address = 0;
				uint64_t service = 0;
				uint16_t applicationID = 0;
				bool activate = false;
				return ProdigyWire::deserializeAdvertisementPairingPayloadAuto(
					args,
					uint64_t(terminal - args),
					secret,
					address,
					service,
					applicationID,
					activate);
			}
			case ContainerTopic::subscriptionPairing:
			{
				uint128_t secret = 0;
				uint128_t address = 0;
				uint64_t service = 0;
				uint16_t port = 0;
				uint16_t applicationID = 0;
				bool activate = false;
				return ProdigyWire::deserializeSubscriptionPairingPayloadAuto(
					args,
					uint64_t(terminal - args),
					secret,
					address,
					service,
					port,
					applicationID,
					activate);
			}
			case ContainerTopic::datacenterUniqueTag:
			{
				uint8_t datacenterUniqueTag = 0;
				if (extractFixed(cursor, terminal, datacenterUniqueTag) == false) return false;
				return (cursor == terminal);
			}
			case ContainerTopic::statistics:
			{
				return consumeMetricPairs(cursor, terminal);
			}
			case ContainerTopic::resourceDeltaAck:
			{
				bool accepted = false;
				if (extractFixed(cursor, terminal, accepted) == false) return false;
				return (cursor == terminal);
			}
			case ContainerTopic::credentialsRefresh:
			{
				if (cursor == terminal)
				{
					return true;
				}

				CredentialDelta delta;
				return ProdigyWire::deserializeCredentialDeltaFramePayloadAuto(args, uint64_t(terminal - args), delta);
			}
			case ContainerTopic::message:
			{
				return (uint32_t(terminal - args) <= maxContainerMessagePayloadBytes);
			}
			case ContainerTopic::wormholesRefresh:
			{
				return consumeVariableBounded(cursor, terminal, maxContainerMessagePayloadBytes);
			}
			default:
			{
				return false;
			}
		}
	}
}
