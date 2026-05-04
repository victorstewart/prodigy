#include <prodigy/bootstrap.config.h>
#include <services/debug.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <algorithm>

class TestSuite
{
public:

   int failed = 0;

   void expect(bool condition, const char *name)
   {
      if (condition)
      {
         basics_log("PASS: %s\n", name);
      }
      else
      {
         basics_log("FAIL: %s\n", name);
         failed += 1;
      }
   }
};

static bool stringContains(const String& haystack, const char *needle)
{
   size_t needleLength = std::strlen(needle);
   if (needleLength == 0)
   {
      return true;
   }

   return std::search(haystack.data(),
      haystack.data() + haystack.size(),
      needle,
      needle + needleLength) != (haystack.data() + haystack.size());
}

static bool equalBootstrapConfigs(const ProdigyBootstrapConfig& lhs, const ProdigyBootstrapConfig& rhs)
{
   return lhs == rhs;
}

static ProdigyBootstrapConfig::BootstrapPeer makeBootstrapPeer(const char *address, uint8_t cidr, bool isBrain = true)
{
   ProdigyBootstrapConfig::BootstrapPeer peer = {};
   peer.isBrain = isBrain;
   ClusterMachinePeerAddress candidate = {};
   candidate.address.assign(address);
   candidate.cidr = cidr;
   peer.addresses.push_back(candidate);
   return peer;
}

int main(void)
{
   TestSuite suite;

   ProdigyBootstrapConfig config = {};
   config.bootstrapPeers.push_back(makeBootstrapPeer("10.0.0.30", 24));
   config.bootstrapPeers.push_back(makeBootstrapPeer("fd00:10::29", 64));
   config.nodeRole = ProdigyBootstrapNodeRole::brain;
   config.controlSocketPath = "/run/prodigy/control.sock"_ctv;

   String json;
   renderProdigyBootstrapConfig(config, json);
   suite.expect(json.size() > 0, "render_nonempty");
   suite.expect(stringContains(json, "\"isBrain\":true"), "render_peer_role_true");

   ProdigyBootstrapConfig parsed = {};
   String failure;
   suite.expect(parseProdigyBootstrapConfigJSON(json, parsed, &failure), "parse_rendered_json");
   suite.expect(equalBootstrapConfigs(config, parsed), "parse_roundtrip_equal");

   String mixedJson = "{\"bootstrapPeers\":[{\"isBrain\":true,\"addresses\":[{\"address\":\"10.0.0.30\",\"cidr\":24}]},{\"isBrain\":false,\"addresses\":[{\"address\":\"10.0.0.31\",\"cidr\":24}]}],\"nodeRole\":\"brain\",\"controlSocketPath\":\"/tmp/x.sock\"}"_ctv;
   suite.expect(parseProdigyBootstrapConfigJSON(mixedJson, parsed, &failure), "parse_peer_roles");
   suite.expect(parsed.bootstrapPeers.size() == 2, "parse_peer_roles_count");
   suite.expect(parsed.bootstrapPeers[0].isBrain, "parse_peer_role_brain");
   suite.expect(parsed.bootstrapPeers[1].isBrain == false, "parse_peer_role_neuron");

   String invalidJson = "{\"bootstrapPeers\":[],\"controlSocketPath\":\"/tmp/x.sock\"}"_ctv;
   suite.expect(parseProdigyBootstrapConfigJSON(invalidJson, parsed, &failure) == false, "parse_rejects_missing_nodeRole");
   suite.expect(failure == "nodeRole required"_ctv, "parse_missing_nodeRole_failure");

   invalidJson = "{\"bootstrapPeers\":[],\"nodeRole\":\"brain\",\"controlSocketPath\":\"/tmp/x.sock\",\"extra\":1}"_ctv;
   suite.expect(parseProdigyBootstrapConfigJSON(invalidJson, parsed, &failure) == false, "parse_rejects_extra_field");

   unsetenv("PRODIGY_MOTHERSHIP_SOCKET");
   String path;
   resolveProdigyControlSocketPathFromProcess(path);
   suite.expect(path == "/tmp/prodigy-mothership.sock"_ctv, "default_control_socket_path");

   setenv("PRODIGY_MOTHERSHIP_SOCKET", "/tmp/prodigy-bootstrap-test.sock", 1);
   resolveProdigyControlSocketPathFromProcess(path);
   suite.expect(path == "/tmp/prodigy-bootstrap-test.sock"_ctv, "override_control_socket_path");
   unsetenv("PRODIGY_MOTHERSHIP_SOCKET");

   if (suite.failed != 0)
   {
      basics_log("bootstrap_config_unit failed=%d\n", suite.failed);
      return EXIT_FAILURE;
   }

   basics_log("bootstrap_config_unit ok\n");
   return EXIT_SUCCESS;
}
