#pragma once

#include <algorithm>

#include <networking/includes.h>
#include <services/prodigy.h>
#include <prodigy/types.h>
#include <simdjson.h>

enum class ProdigyBootstrapNodeRole : uint8_t
{
   neuron = 0,
   brain = 1
};

class ProdigyBootstrapConfig
{
public:

   class BootstrapPeer
   {
   public:

      bool isBrain = true;
      Vector<ClusterMachinePeerAddress> addresses;

      bool operator==(const BootstrapPeer& other) const
      {
         if (isBrain != other.isBrain || addresses.size() != other.addresses.size())
         {
            return false;
         }

         for (uint32_t index = 0; index < addresses.size(); ++index)
         {
            if (addresses[index] != other.addresses[index])
            {
               return false;
            }
         }

         return true;
      }

      bool operator!=(const BootstrapPeer& other) const
      {
         return (*this == other) == false;
      }
   };

   Vector<BootstrapPeer> bootstrapPeers;
   ProdigyBootstrapNodeRole nodeRole = ProdigyBootstrapNodeRole::neuron;
   String controlSocketPath;

   bool operator==(const ProdigyBootstrapConfig& other) const
   {
      if (nodeRole != other.nodeRole
         || controlSocketPath.equals(other.controlSocketPath) == false
         || bootstrapPeers.size() != other.bootstrapPeers.size())
      {
         return false;
      }

      for (uint32_t index = 0; index < bootstrapPeers.size(); ++index)
      {
         if (bootstrapPeers[index] != other.bootstrapPeers[index])
         {
            return false;
         }
      }

      return true;
   }

   bool operator!=(const ProdigyBootstrapConfig& other) const
   {
      return (*this == other) == false;
   }
};

static inline bool prodigyBootstrapPeerComesBefore(const ProdigyBootstrapConfig::BootstrapPeer& lhs, const ProdigyBootstrapConfig::BootstrapPeer& rhs)
{
   if (lhs.isBrain != rhs.isBrain)
   {
      return lhs.isBrain > rhs.isBrain;
   }

   uint32_t compareCount = lhs.addresses.size() < rhs.addresses.size() ? lhs.addresses.size() : rhs.addresses.size();
   for (uint32_t index = 0; index < compareCount; ++index)
   {
      if (lhs.addresses[index].address.equals(rhs.addresses[index].address) == false)
      {
         return std::lexicographical_compare(lhs.addresses[index].address.data(), lhs.addresses[index].address.data() + lhs.addresses[index].address.size(),
            rhs.addresses[index].address.data(), rhs.addresses[index].address.data() + rhs.addresses[index].address.size());
      }

      if (lhs.addresses[index].cidr != rhs.addresses[index].cidr)
      {
         return lhs.addresses[index].cidr < rhs.addresses[index].cidr;
      }
   }

   return lhs.addresses.size() < rhs.addresses.size();
}

static inline void prodigyAppendUniqueBootstrapPeer(Vector<ProdigyBootstrapConfig::BootstrapPeer>& peers, const ProdigyBootstrapConfig::BootstrapPeer& peer)
{
   if (peer.addresses.empty())
   {
      return;
   }

   for (const ProdigyBootstrapConfig::BootstrapPeer& existing : peers)
   {
      if (existing == peer)
      {
         return;
      }
   }

   peers.push_back(peer);
}

template <typename S>
static void serialize(S&& serializer, ProdigyBootstrapConfig::BootstrapPeer& peer)
{
   serializer.value1b(peer.isBrain);
   serializer.container(peer.addresses, UINT32_MAX);
}

template <typename S>
static void serialize(S&& serializer, ProdigyBootstrapConfig& config)
{
   serializer.container(config.bootstrapPeers, UINT32_MAX);
   serializer.value1b(config.nodeRole);
   serializer.text1b(config.controlSocketPath, UINT32_MAX);
}

static inline const char *prodigyBootstrapNodeRoleName(ProdigyBootstrapNodeRole role)
{
   switch (role)
   {
      case ProdigyBootstrapNodeRole::neuron:
      {
         return "neuron";
      }
      case ProdigyBootstrapNodeRole::brain:
      {
         return "brain";
      }
   }

   return "neuron";
}

static inline bool parseProdigyBootstrapNodeRole(const String& value, ProdigyBootstrapNodeRole& role)
{
   if (value.equal("neuron"_ctv))
   {
      role = ProdigyBootstrapNodeRole::neuron;
      return true;
   }

   if (value.equal("brain"_ctv))
   {
      role = ProdigyBootstrapNodeRole::brain;
      return true;
   }

   return false;
}

static inline const char *defaultProdigyControlSocketPath(void)
{
   return "/tmp/prodigy-mothership.sock";
}

static inline void resolveProdigyControlSocketPathFromProcess(String& path)
{
   if (const char *overridePath = getenv("PRODIGY_MOTHERSHIP_SOCKET"); overridePath && overridePath[0] != '\0')
   {
      path.assign(overridePath);
      return;
   }

   path.assign(defaultProdigyControlSocketPath());
}

static inline void appendEscapedJSONString(String& json, const String& value)
{
   json.append('"');

   for (uint64_t index = 0; index < value.size(); ++index)
   {
      uint8_t byte = value[index];

      switch (byte)
      {
         case '\\':
         {
            json.append("\\\\"_ctv);
            break;
         }
         case '"':
         {
            json.append("\\\""_ctv);
            break;
         }
         case '\n':
         {
            json.append("\\n"_ctv);
            break;
         }
         case '\r':
         {
            json.append("\\r"_ctv);
            break;
         }
         case '\t':
         {
            json.append("\\t"_ctv);
            break;
         }
         default:
         {
            json.append(byte);
            break;
         }
      }
   }

   json.append('"');
}

static inline void renderProdigyBootstrapPeerJSON(const ProdigyBootstrapConfig::BootstrapPeer& peer, String& json)
{
   json.append("{\"isBrain\":"_ctv);
   if (peer.isBrain)
   {
      json.append("true"_ctv);
   }
   else
   {
      json.append("false"_ctv);
   }
   json.append(",\"addresses\":["_ctv);

   for (uint64_t index = 0; index < peer.addresses.size(); ++index)
   {
      if (index > 0)
      {
         json.append(","_ctv);
      }

      json.append("{\"address\":"_ctv);
      appendEscapedJSONString(json, peer.addresses[index].address);
      json.append(",\"cidr\":"_ctv);
      String cidrText = {};
      cidrText.snprintf<"{itoa}"_ctv>(unsigned(peer.addresses[index].cidr));
      json.append(cidrText);
      json.append("}"_ctv);
   }

   json.append("]}"_ctv);
}

static inline void renderProdigyBootstrapConfig(const ProdigyBootstrapConfig& config, String& json)
{
   json.clear();
   json.append("{\"bootstrapPeers\":["_ctv);

   for (uint64_t index = 0; index < config.bootstrapPeers.size(); ++index)
   {
      if (index > 0)
      {
         json.append(","_ctv);
      }

      renderProdigyBootstrapPeerJSON(config.bootstrapPeers[index], json);
   }

   json.append("],\"nodeRole\":"_ctv);
   String roleName;
   roleName.assign(prodigyBootstrapNodeRoleName(config.nodeRole));
   appendEscapedJSONString(json, roleName);
   json.append(",\"controlSocketPath\":"_ctv);
   appendEscapedJSONString(json, config.controlSocketPath);
   json.append("}"_ctv);
}

static inline bool parseProdigyBootstrapPeerJSONElement(simdjson::dom::element element, ProdigyBootstrapConfig::BootstrapPeer& peer, String *failure = nullptr)
{
   if (element.type() != simdjson::dom::element_type::OBJECT)
   {
      if (failure) failure->assign("bootstrapPeers requires peer objects");
      return false;
   }

   ProdigyBootstrapConfig::BootstrapPeer parsed = {};
   bool sawAddresses = false;

   for (auto field : element.get_object())
   {
      String key;
      key.setInvariant(field.key.data(), field.key.size());

      if (key.equal("isBrain"_ctv))
      {
         if (field.value.type() != simdjson::dom::element_type::BOOL)
         {
            if (failure) failure->assign("bootstrapPeers isBrain requires bool");
            return false;
         }

         bool value = false;
         if (field.value.get(value) != simdjson::SUCCESS)
         {
            if (failure) failure->assign("bootstrapPeers isBrain invalid");
            return false;
         }

         parsed.isBrain = value;
      }
      else if (key.equal("addresses"_ctv))
      {
         if (field.value.type() != simdjson::dom::element_type::ARRAY)
         {
            if (failure) failure->assign("bootstrapPeers addresses requires array");
            return false;
         }

         sawAddresses = true;
         for (auto candidateElement : field.value.get_array())
         {
            if (candidateElement.type() != simdjson::dom::element_type::OBJECT)
            {
               if (failure) failure->assign("bootstrapPeers addresses requires candidate objects");
               return false;
            }

            ClusterMachinePeerAddress candidate = {};
            bool sawAddress = false;
            bool sawCidr = false;

            for (auto candidateField : candidateElement.get_object())
            {
               String candidateKey;
               candidateKey.setInvariant(candidateField.key.data(), candidateField.key.size());

               if (candidateKey.equal("address"_ctv))
               {
                  if (candidateField.value.type() != simdjson::dom::element_type::STRING)
                  {
                     if (failure) failure->assign("bootstrapPeers address requires string");
                     return false;
                  }

                  candidate.address.assign(candidateField.value.get_c_str());
                  sawAddress = true;
               }
               else if (candidateKey.equal("cidr"_ctv))
               {
                  if (candidateField.value.type() != simdjson::dom::element_type::INT64
                     && candidateField.value.type() != simdjson::dom::element_type::UINT64)
                  {
                     if (failure) failure->assign("bootstrapPeers cidr requires integer");
                     return false;
                  }

                  uint64_t parsedCidr = 0;
                  if (candidateField.value.type() == simdjson::dom::element_type::INT64)
                  {
                     int64_t signedCidr = 0;
                     if (candidateField.value.get_int64().get(signedCidr) || signedCidr < 0)
                     {
                        if (failure) failure->assign("bootstrapPeers cidr invalid");
                        return false;
                     }

                     parsedCidr = uint64_t(signedCidr);
                  }
                  else if (candidateField.value.get_uint64().get(parsedCidr))
                  {
                     if (failure) failure->assign("bootstrapPeers cidr invalid");
                     return false;
                  }

                  if (parsedCidr > 255ull)
                  {
                     if (failure) failure->assign("bootstrapPeers cidr invalid");
                     return false;
                  }

                  candidate.cidr = uint8_t(parsedCidr);
                  sawCidr = true;
               }
               else
               {
                  if (failure) failure->assign("invalid bootstrap peer candidate field");
                  return false;
               }
            }

            if (sawAddress == false)
            {
               if (failure) failure->assign("bootstrapPeers candidate address required");
               return false;
            }

            if (sawCidr == false)
            {
               candidate.cidr = 0;
            }

            prodigyAppendUniqueClusterMachinePeerAddress(parsed.addresses, candidate);
         }
      }
      else
      {
         if (failure) failure->assign("invalid bootstrap peer field");
         return false;
      }
   }

   if (sawAddresses == false)
   {
      if (failure) failure->assign("bootstrapPeers addresses required");
      return false;
   }

   if (parsed.addresses.empty())
   {
      if (failure) failure->assign("bootstrapPeers addresses cannot be empty");
      return false;
   }

   peer = std::move(parsed);
   return true;
}

static inline bool parseProdigyBootstrapConfigJSON(const String& json, ProdigyBootstrapConfig& config, String *failure = nullptr)
{
   simdjson::dom::parser parser;
   simdjson::dom::element doc;
   if (parser.parse(json.data(), json.size()).get(doc))
   {
      if (failure) failure->assign("invalid bootstrap json");
      return false;
   }

   if (doc.type() != simdjson::dom::element_type::OBJECT)
   {
      if (failure) failure->assign("bootstrap config must be an object");
      return false;
   }

   ProdigyBootstrapConfig parsed = {};
   bool sawBootstrapPeers = false;
   bool sawNodeRole = false;
   bool sawControlSocketPath = false;

   for (auto field : doc.get_object())
   {
      String key;
      key.setInvariant(field.key.data(), field.key.size());

      if (key.equal("bootstrapPeers"_ctv))
      {
         if (field.value.type() != simdjson::dom::element_type::ARRAY)
         {
            if (failure) failure->assign("bootstrapPeers requires array");
            return false;
         }

         sawBootstrapPeers = true;
         for (auto peer : field.value.get_array())
         {
            ProdigyBootstrapConfig::BootstrapPeer parsedPeer = {};
            if (parseProdigyBootstrapPeerJSONElement(peer, parsedPeer, failure) == false)
            {
               return false;
            }

            parsed.bootstrapPeers.push_back(parsedPeer);
         }
      }
      else if (key.equal("nodeRole"_ctv))
      {
         if (field.value.type() != simdjson::dom::element_type::STRING)
         {
            if (failure) failure->assign("nodeRole requires string");
            return false;
         }

         String value(field.value.get_c_str());
         if (parseProdigyBootstrapNodeRole(value, parsed.nodeRole) == false)
         {
            if (failure) failure->assign("nodeRole invalid");
            return false;
         }

         sawNodeRole = true;
      }
      else if (key.equal("controlSocketPath"_ctv))
      {
         if (field.value.type() != simdjson::dom::element_type::STRING)
         {
            if (failure) failure->assign("controlSocketPath requires string");
            return false;
         }

         parsed.controlSocketPath.assign(field.value.get_c_str());
         sawControlSocketPath = true;
      }
      else
      {
         if (failure) failure->assign("invalid bootstrap config field");
         return false;
      }
   }

   if (sawBootstrapPeers == false)
   {
      if (failure) failure->assign("bootstrapPeers required");
      return false;
   }

   if (sawNodeRole == false)
   {
      if (failure) failure->assign("nodeRole required");
      return false;
   }

   if (sawControlSocketPath == false || parsed.controlSocketPath.size() == 0)
   {
      if (failure) failure->assign("controlSocketPath required");
      return false;
   }

   config = std::move(parsed);
   if (failure) failure->clear();
   return true;
}
