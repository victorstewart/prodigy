#pragma once

#include <netinet/tcp.h>

#include <networking/includes.h>
#include <services/bitsery.h>
#include <networking/ip.h>
#include <types/types.containers.h>

enum class ProdigyEnvironmentKind : uint8_t
{
   unknown = 0,
   dev = 1,
   gcp = 2,
   aws = 3,
   azure = 4,
   vultr = 5
};

static constexpr uint32_t prodigyRuntimeTestInterContainerMTUDefault = 9000u;
static constexpr uint32_t prodigyRuntimeTestInterContainerMTUMin = 1280u;
static constexpr uint32_t prodigyRuntimeTestInterContainerMTUMax = 65535u;
static constexpr uint32_t prodigyTCPHeaderBytes = 20u;
static constexpr uint32_t prodigyIPv4HeaderBytes = 20u;
static constexpr uint32_t prodigyIPv6HeaderBytes = 40u;

static inline uint32_t prodigyTCPMaxSegmentSizeForMTU(uint32_t mtu, int family)
{
   const uint32_t ipHeaderBytes =
      family == AF_INET ? prodigyIPv4HeaderBytes
      : family == AF_INET6 ? prodigyIPv6HeaderBytes
      : 0u;
   if (ipHeaderBytes == 0 || mtu <= (ipHeaderBytes + prodigyTCPHeaderBytes))
   {
      return 0;
   }

   return mtu - ipHeaderBytes - prodigyTCPHeaderBytes;
}

static inline bool prodigySetTCPMaxSegmentSize(int fd, uint32_t maxSegmentSize)
{
   if (fd < 0 || maxSegmentSize == 0)
   {
      return false;
   }

   const int maxSeg = int(maxSegmentSize);
   return ::setsockopt(fd, IPPROTO_TCP, TCP_MAXSEG, &maxSeg, sizeof(maxSeg)) == 0;
}

class NeuronBGPPeerConfig
{
public:

   uint16_t peerASN = 0;
   IPAddress peerAddress;
   IPAddress sourceAddress;
   String md5Password;
   uint8_t hopLimit = 0;

   bool operator==(const NeuronBGPPeerConfig& other) const
   {
      return peerASN == other.peerASN
         && peerAddress.equals(other.peerAddress)
         && sourceAddress.equals(other.sourceAddress)
         && md5Password.equals(other.md5Password)
         && hopLimit == other.hopLimit;
   }

   bool operator!=(const NeuronBGPPeerConfig& other) const
   {
      return (*this == other) == false;
   }
};

template <typename S>
static void serialize(S&& serializer, NeuronBGPPeerConfig& config)
{
   serializer.value2b(config.peerASN);
   serializer.object(config.peerAddress);
   serializer.object(config.sourceAddress);
   serializer.text1b(config.md5Password, UINT32_MAX);
   serializer.value1b(config.hopLimit);
}

class NeuronBGPConfig
{
public:

   bool enabled = false;
   uint32_t ourBGPID = 0;
   uint32_t community = 0;
   IPAddress nextHop4;
   IPAddress nextHop6;
   Vector<NeuronBGPPeerConfig> peers;

   bool configured(void) const
   {
      return enabled
         || ourBGPID != 0
         || community != 0
         || nextHop4.isNull() == false
         || nextHop6.isNull() == false
         || peers.empty() == false;
   }

   bool operator==(const NeuronBGPConfig& other) const
   {
      if (enabled != other.enabled
         || ourBGPID != other.ourBGPID
         || community != other.community
         || nextHop4.equals(other.nextHop4) == false
         || nextHop6.equals(other.nextHop6) == false
         || peers.size() != other.peers.size())
      {
         return false;
      }

      for (uint32_t index = 0; index < peers.size(); ++index)
      {
         if (peers[index] != other.peers[index])
         {
            return false;
         }
      }

      return true;
   }

   bool operator!=(const NeuronBGPConfig& other) const
   {
      return (*this == other) == false;
   }
};

template <typename S>
static void serialize(S&& serializer, NeuronBGPConfig& config)
{
   serializer.value1b(config.enabled);
   serializer.value4b(config.ourBGPID);
   serializer.value4b(config.community);
   serializer.object(config.nextHop4);
   serializer.object(config.nextHop6);
   serializer.container(config.peers, UINT32_MAX);
}

class ProdigyEnvironmentBGPConfig
{
public:

   bool specified = false;
   NeuronBGPConfig config;

   bool configured(void) const
   {
      return specified || config.configured();
   }

   bool operator==(const ProdigyEnvironmentBGPConfig& other) const
   {
      return specified == other.specified
         && config == other.config;
   }

   bool operator!=(const ProdigyEnvironmentBGPConfig& other) const
   {
      return (*this == other) == false;
   }
};

template <typename S>
static void serialize(S&& serializer, ProdigyEnvironmentBGPConfig& config)
{
   serializer.value1b(config.specified);
   serializer.object(config.config);
}

static inline const char *prodigyEnvironmentKindName(ProdigyEnvironmentKind environment)
{
   switch (environment)
   {
      case ProdigyEnvironmentKind::unknown:
      {
         return "unknown";
      }
      case ProdigyEnvironmentKind::dev:
      {
         return "dev";
      }
      case ProdigyEnvironmentKind::gcp:
      {
         return "gcp";
      }
      case ProdigyEnvironmentKind::aws:
      {
         return "aws";
      }
      case ProdigyEnvironmentKind::azure:
      {
         return "azure";
      }
      case ProdigyEnvironmentKind::vultr:
      {
         return "vultr";
      }
   }

   return "unknown";
}

static inline bool parseProdigyEnvironmentKind(const String& value, ProdigyEnvironmentKind& environment)
{
   if (value.equal("unknown"_ctv) || value.equal("ProdigyEnvironmentKind::unknown"_ctv))
   {
      environment = ProdigyEnvironmentKind::unknown;
      return true;
   }

   if (value.equal("dev"_ctv) || value.equal("ProdigyEnvironmentKind::dev"_ctv))
   {
      environment = ProdigyEnvironmentKind::dev;
      return true;
   }

   if (value.equal("gcp"_ctv) || value.equal("ProdigyEnvironmentKind::gcp"_ctv))
   {
      environment = ProdigyEnvironmentKind::gcp;
      return true;
   }

   if (value.equal("aws"_ctv) || value.equal("ProdigyEnvironmentKind::aws"_ctv))
   {
      environment = ProdigyEnvironmentKind::aws;
      return true;
   }

   if (value.equal("azure"_ctv) || value.equal("ProdigyEnvironmentKind::azure"_ctv))
   {
      environment = ProdigyEnvironmentKind::azure;
      return true;
   }

   if (value.equal("vultr"_ctv) || value.equal("ProdigyEnvironmentKind::vultr"_ctv))
   {
      environment = ProdigyEnvironmentKind::vultr;
      return true;
   }

   return false;
}

class ProdigyRuntimeEnvironmentConfig
{
public:

   class TestConfig
   {
   public:

      bool enabled = false;
      bool enableFakeIpv4Boundary = false;
      uint32_t interContainerMTU = 0;
      IPPrefix fakePublicSubnet4 = {};
      IPPrefix fakePublicSubnet6 = {};

      bool configured(void) const
      {
         return enabled
            || enableFakeIpv4Boundary
            || interContainerMTU != 0
            || fakePublicSubnet4.network.isNull() == false
            || fakePublicSubnet6.network.isNull() == false;
      }

      bool operator==(const TestConfig& other) const
      {
         return enabled == other.enabled
            && enableFakeIpv4Boundary == other.enableFakeIpv4Boundary
            && interContainerMTU == other.interContainerMTU
            && fakePublicSubnet4.equals(other.fakePublicSubnet4)
            && fakePublicSubnet6.equals(other.fakePublicSubnet6);
      }

      bool operator!=(const TestConfig& other) const
      {
         return (*this == other) == false;
      }
   };

   class AwsConfig
   {
   public:

      String bootstrapLaunchTemplateName;
      String bootstrapLaunchTemplateVersion;
      String bootstrapCredentialRefreshCommand;
      String bootstrapCredentialRefreshFailureHint;
      String instanceProfileName;
      String instanceProfileArn;

      bool configured(void) const
      {
         return bootstrapLaunchTemplateName.size() > 0
            || bootstrapLaunchTemplateVersion.size() > 0
            || bootstrapCredentialRefreshCommand.size() > 0
            || bootstrapCredentialRefreshFailureHint.size() > 0
            || instanceProfileName.size() > 0
            || instanceProfileArn.size() > 0;
      }

      bool operator==(const AwsConfig& other) const
      {
         return bootstrapLaunchTemplateName.equals(other.bootstrapLaunchTemplateName)
            && bootstrapLaunchTemplateVersion.equals(other.bootstrapLaunchTemplateVersion)
            && bootstrapCredentialRefreshCommand.equals(other.bootstrapCredentialRefreshCommand)
            && bootstrapCredentialRefreshFailureHint.equals(other.bootstrapCredentialRefreshFailureHint)
            && instanceProfileName.equals(other.instanceProfileName)
            && instanceProfileArn.equals(other.instanceProfileArn);
      }

      bool operator!=(const AwsConfig& other) const
      {
         return (*this == other) == false;
      }
   };

   class GcpConfig
   {
   public:

      String bootstrapAccessTokenRefreshCommand;
      String bootstrapAccessTokenRefreshFailureHint;

      bool configured(void) const
      {
         return bootstrapAccessTokenRefreshCommand.size() > 0
            || bootstrapAccessTokenRefreshFailureHint.size() > 0;
      }

      bool operator==(const GcpConfig& other) const
      {
         return bootstrapAccessTokenRefreshCommand.equals(other.bootstrapAccessTokenRefreshCommand)
            && bootstrapAccessTokenRefreshFailureHint.equals(other.bootstrapAccessTokenRefreshFailureHint);
      }

      bool operator!=(const GcpConfig& other) const
      {
         return (*this == other) == false;
      }
   };

   class AzureConfig
   {
   public:

      String bootstrapAccessTokenRefreshCommand;
      String bootstrapAccessTokenRefreshFailureHint;
      String managedIdentityResourceID;

      bool configured(void) const
      {
         return bootstrapAccessTokenRefreshCommand.size() > 0
            || bootstrapAccessTokenRefreshFailureHint.size() > 0
            || managedIdentityResourceID.size() > 0;
      }

      bool operator==(const AzureConfig& other) const
      {
         return bootstrapAccessTokenRefreshCommand.equals(other.bootstrapAccessTokenRefreshCommand)
            && bootstrapAccessTokenRefreshFailureHint.equals(other.bootstrapAccessTokenRefreshFailureHint)
            && managedIdentityResourceID.equals(other.managedIdentityResourceID);
      }

      bool operator!=(const AzureConfig& other) const
      {
         return (*this == other) == false;
      }
   };

   ProdigyEnvironmentKind kind = ProdigyEnvironmentKind::unknown;
   String providerScope;
   String providerCredentialMaterial;
   AwsConfig aws;
   GcpConfig gcp;
   AzureConfig azure;
   ProdigyEnvironmentBGPConfig bgp;
   TestConfig test;

   bool configured(void) const
   {
      return kind != ProdigyEnvironmentKind::unknown
         || providerScope.size() > 0
         || providerCredentialMaterial.size() > 0
         || aws.configured()
         || gcp.configured()
         || azure.configured()
         || bgp.configured()
         || test.configured();
   }

   bool operator==(const ProdigyRuntimeEnvironmentConfig& other) const
   {
      return kind == other.kind
         && providerScope.equals(other.providerScope)
         && providerCredentialMaterial.equals(other.providerCredentialMaterial)
         && aws == other.aws
         && gcp == other.gcp
         && azure == other.azure
         && bgp == other.bgp
         && test == other.test;
   }

   bool operator!=(const ProdigyRuntimeEnvironmentConfig& other) const
   {
      return (*this == other) == false;
   }
};

static inline bool prodigyResolveProviderScopeRegion(const String& scope, String& region)
{
   region.clear();
   if (scope.size() == 0)
   {
      return false;
   }

   int64_t slash = scope.rfindChar('/');
   if (slash >= 0 && uint64_t(slash + 1) < scope.size())
   {
      region.assign(scope.substr(uint64_t(slash + 1), scope.size() - uint64_t(slash + 1), Copy::yes));
      return region.size() > 0;
   }

   region.assign(scope);
   return region.size() > 0;
}

static inline void prodigyApplyInternalRuntimeEnvironmentDefaults(ProdigyRuntimeEnvironmentConfig& config)
{
   if (config.test.enabled)
   {
      if (config.test.interContainerMTU == 0)
      {
         config.test.interContainerMTU = prodigyRuntimeTestInterContainerMTUDefault;
      }

      if (config.test.fakePublicSubnet4.network.isNull() && config.test.enableFakeIpv4Boundary)
      {
         config.test.fakePublicSubnet4.network = IPAddress("198.18.0.0", false);
         config.test.fakePublicSubnet4.cidr = 16;
      }

      if (config.test.fakePublicSubnet6.network.isNull())
      {
         config.test.fakePublicSubnet6.network = IPAddress("2602:fac0:0:12ab:34cd::", true);
         config.test.fakePublicSubnet6.cidr = 88;
      }

      config.test.fakePublicSubnet4.canonicalize();
      config.test.fakePublicSubnet6.canonicalize();
   }

   if (config.kind == ProdigyEnvironmentKind::aws)
   {
      if (config.aws.bootstrapLaunchTemplateVersion.size() == 0)
      {
         config.aws.bootstrapLaunchTemplateVersion.assign("$Default"_ctv);
      }

      if (config.aws.bootstrapLaunchTemplateName.size() == 0)
      {
         String region = {};
         if (prodigyResolveProviderScopeRegion(config.providerScope, region) && region.size() > 0)
         {
            config.aws.bootstrapLaunchTemplateName.snprintf<"prodigy-bootstrap-{}"_ctv>(region);
         }
         else
         {
            config.aws.bootstrapLaunchTemplateName.assign("prodigy-bootstrap"_ctv);
         }
      }
   }
}

static inline bool prodigyRuntimeEnvironmentUsesManagedCloudNativeIdentity(const ProdigyRuntimeEnvironmentConfig& config)
{
   if (config.kind == ProdigyEnvironmentKind::gcp)
   {
      return true;
   }

   if (config.kind == ProdigyEnvironmentKind::aws)
   {
      return config.aws.instanceProfileName.size() > 0
         || config.aws.instanceProfileArn.size() > 0;
   }

   if (config.kind == ProdigyEnvironmentKind::azure)
   {
      return config.azure.managedIdentityResourceID.size() > 0;
   }

   return false;
}

static inline void prodigyStripManagedCloudBootstrapCredentials(ProdigyRuntimeEnvironmentConfig& config)
{
   if (prodigyRuntimeEnvironmentUsesManagedCloudNativeIdentity(config) == false)
   {
      return;
   }

   config.providerCredentialMaterial.reset();

   if (config.kind == ProdigyEnvironmentKind::aws)
   {
      config.aws.bootstrapCredentialRefreshCommand.reset();
      config.aws.bootstrapCredentialRefreshFailureHint.reset();
   }
   else if (config.kind == ProdigyEnvironmentKind::gcp)
   {
      config.gcp.bootstrapAccessTokenRefreshCommand.reset();
      config.gcp.bootstrapAccessTokenRefreshFailureHint.reset();
   }
   else if (config.kind == ProdigyEnvironmentKind::azure)
   {
      config.azure.bootstrapAccessTokenRefreshCommand.reset();
      config.azure.bootstrapAccessTokenRefreshFailureHint.reset();
   }
}

static inline void prodigyOwnRuntimeEnvironmentConfig(const ProdigyRuntimeEnvironmentConfig& source, ProdigyRuntimeEnvironmentConfig& owned)
{
   owned = {};
   owned.kind = source.kind;
   owned.providerScope.assign(source.providerScope);
   owned.providerCredentialMaterial.assign(source.providerCredentialMaterial);
   owned.aws.bootstrapLaunchTemplateName.assign(source.aws.bootstrapLaunchTemplateName);
   owned.aws.bootstrapLaunchTemplateVersion.assign(source.aws.bootstrapLaunchTemplateVersion);
   owned.aws.bootstrapCredentialRefreshCommand.assign(source.aws.bootstrapCredentialRefreshCommand);
   owned.aws.bootstrapCredentialRefreshFailureHint.assign(source.aws.bootstrapCredentialRefreshFailureHint);
   owned.aws.instanceProfileName.assign(source.aws.instanceProfileName);
   owned.aws.instanceProfileArn.assign(source.aws.instanceProfileArn);
   owned.gcp.bootstrapAccessTokenRefreshCommand.assign(source.gcp.bootstrapAccessTokenRefreshCommand);
   owned.gcp.bootstrapAccessTokenRefreshFailureHint.assign(source.gcp.bootstrapAccessTokenRefreshFailureHint);
   owned.azure.bootstrapAccessTokenRefreshCommand.assign(source.azure.bootstrapAccessTokenRefreshCommand);
   owned.azure.bootstrapAccessTokenRefreshFailureHint.assign(source.azure.bootstrapAccessTokenRefreshFailureHint);
   owned.azure.managedIdentityResourceID.assign(source.azure.managedIdentityResourceID);
   owned.bgp.specified = source.bgp.specified;
   owned.bgp.config.enabled = source.bgp.config.enabled;
   owned.bgp.config.ourBGPID = source.bgp.config.ourBGPID;
   owned.bgp.config.community = source.bgp.config.community;
   owned.bgp.config.nextHop4 = source.bgp.config.nextHop4;
   owned.bgp.config.nextHop6 = source.bgp.config.nextHop6;
   for (const NeuronBGPPeerConfig& sourcePeer : source.bgp.config.peers)
   {
      NeuronBGPPeerConfig ownedPeer = {};
      ownedPeer.peerASN = sourcePeer.peerASN;
      ownedPeer.peerAddress = sourcePeer.peerAddress;
      ownedPeer.sourceAddress = sourcePeer.sourceAddress;
      ownedPeer.md5Password.assign(sourcePeer.md5Password);
      ownedPeer.hopLimit = sourcePeer.hopLimit;
      owned.bgp.config.peers.push_back(std::move(ownedPeer));
   }
   owned.test = source.test;
}

template <typename S>
static void serialize(S&& serializer, ProdigyRuntimeEnvironmentConfig::AwsConfig& config)
{
   serializer.text1b(config.bootstrapLaunchTemplateName, UINT32_MAX);
   serializer.text1b(config.bootstrapLaunchTemplateVersion, UINT32_MAX);
   serializer.text1b(config.bootstrapCredentialRefreshCommand, UINT32_MAX);
   serializer.text1b(config.bootstrapCredentialRefreshFailureHint, UINT32_MAX);
   serializer.text1b(config.instanceProfileName, UINT32_MAX);
   serializer.text1b(config.instanceProfileArn, UINT32_MAX);
}

template <typename S>
static void serialize(S&& serializer, ProdigyRuntimeEnvironmentConfig::GcpConfig& config)
{
   serializer.text1b(config.bootstrapAccessTokenRefreshCommand, UINT32_MAX);
   serializer.text1b(config.bootstrapAccessTokenRefreshFailureHint, UINT32_MAX);
}

template <typename S>
static void serialize(S&& serializer, ProdigyRuntimeEnvironmentConfig::AzureConfig& config)
{
   serializer.text1b(config.bootstrapAccessTokenRefreshCommand, UINT32_MAX);
   serializer.text1b(config.bootstrapAccessTokenRefreshFailureHint, UINT32_MAX);
   serializer.text1b(config.managedIdentityResourceID, UINT32_MAX);
}

template <typename S>
static void serialize(S&& serializer, ProdigyRuntimeEnvironmentConfig::TestConfig& config)
{
   serializer.value1b(config.enabled);
   serializer.value1b(config.enableFakeIpv4Boundary);
   serializer.value4b(config.interContainerMTU);
   serializer.object(config.fakePublicSubnet4);
   serializer.object(config.fakePublicSubnet6);
}

template <typename S>
static void serialize(S&& serializer, ProdigyRuntimeEnvironmentConfig& config)
{
   serializer.value1b(config.kind);
   serializer.text1b(config.providerScope, UINT32_MAX);
   serializer.text1b(config.providerCredentialMaterial, UINT32_MAX);
   serializer.object(config.aws);
   serializer.object(config.gcp);
   serializer.object(config.azure);
   serializer.object(config.bgp);
   serializer.object(config.test);
}

static inline bool prodigyParseIPAddressText(const String& value, IPAddress& address)
{
   address = {};
   if (value.size() == 0)
   {
      return false;
   }

   String text = {};
   text.assign(value);

   uint32_t parsed4 = 0;
   if (inet_pton(AF_INET, text.c_str(), &parsed4) == 1)
   {
      address.is6 = false;
      address.v4 = parsed4;
      return true;
   }

   IPAddress parsed6 = {};
   if (inet_pton(AF_INET6, text.c_str(), parsed6.v6) == 1)
   {
      parsed6.is6 = true;
      address = parsed6;
      return true;
   }

   return false;
}

static inline bool prodigyRenderIPAddressText(const IPAddress& address, String& text)
{
   text.clear();
   if (address.isNull())
   {
      return false;
   }

   char buffer[INET6_ADDRSTRLEN] = {0};
   if (address.is6)
   {
      if (inet_ntop(AF_INET6, address.v6, buffer, sizeof(buffer)) == nullptr)
      {
         return false;
      }
   }
   else
   {
      if (inet_ntop(AF_INET, &address.v4, buffer, sizeof(buffer)) == nullptr)
      {
         return false;
      }
   }

   text.assign(buffer);
   return true;
}

static inline bool prodigyParseBGPIDText(const String& value, uint32_t& bgpID)
{
   bgpID = 0;
   if (value.size() == 0)
   {
      return false;
   }

   String text = {};
   text.assign(value);
   return inet_pton(AF_INET, text.c_str(), &bgpID) == 1;
}

static inline bool prodigyRenderBGPIDText(uint32_t bgpID, String& text)
{
   text.clear();
   if (bgpID == 0)
   {
      return false;
   }

   char buffer[INET_ADDRSTRLEN] = {0};
   struct in_addr address = {};
   address.s_addr = bgpID;
   if (inet_ntop(AF_INET, &address, buffer, sizeof(buffer)) == nullptr)
   {
      return false;
   }

   text.assign(buffer);
   return true;
}

static inline bool prodigyResolveEffectiveNeuronBGPID(const NeuronBGPConfig& config, const IPAddress& private4, uint32_t& bgpID)
{
   if (config.ourBGPID != 0)
   {
      bgpID = config.ourBGPID;
      return true;
   }

   if (private4.is6 == false && private4.v4 != 0)
   {
      bgpID = private4.v4;
      return true;
   }

   for (const NeuronBGPPeerConfig& peer : config.peers)
   {
      if (peer.sourceAddress.is6 == false && peer.sourceAddress.v4 != 0)
      {
         bgpID = peer.sourceAddress.v4;
         return true;
      }
   }

   bgpID = 0;
   return false;
}

static inline bool prodigyResolveRuntimeEnvironmentBGPOverride(const ProdigyRuntimeEnvironmentConfig& environment, const IPAddress& private4, NeuronBGPConfig& config)
{
   if (environment.bgp.configured() == false)
   {
      return false;
   }

   config = environment.bgp.config;
   if (config.enabled)
   {
      (void)prodigyResolveEffectiveNeuronBGPID(config, private4, config.ourBGPID);
   }

   return true;
}
