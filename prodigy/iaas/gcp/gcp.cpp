#include <prodigy/iaas/gcp/gcp.h>

uint32_t gcpHashRackIdentity(std::string_view s)
{
  uint32_t u = 0;
  for (char c : s)
  {
    u = (u * 131u) + uint8_t(c);
  }

  return u;
}

bool gcpGetNestedElement(simdjson::dom::element root, std::initializer_list<std::string_view> path, simdjson::dom::element& value)
{
  value = root;
  for (std::string_view key : path)
  {
    simdjson::dom::object object = {};
    if (value.get_object().get(object) != simdjson::SUCCESS)
    {
      return false;
    }

    simdjson::dom::element next = {};
    if (object.at_key(key).get(next) != simdjson::SUCCESS)
    {
      return false;
    }

    value = next;
  }

  return true;
}

bool gcpExtractZoneName(const String& zoneURL, String& zoneText)
{
  zoneText.clear();
  if (zoneURL.size() == 0)
  {
    return false;
  }

  uint64_t start = 0;
  for (uint64_t index = 0; index < zoneURL.size(); ++index)
  {
    if (zoneURL[index] == '/')
    {
      start = index + 1;
    }
  }

  if (start >= zoneURL.size())
  {
    return false;
  }

  zoneText.assign(zoneURL.data() + start, zoneURL.size() - start);
  return zoneText.size() > 0;
}

uint32_t gcpExtractRackUUID(simdjson::dom::element inst, const String& zoneText)
{
  std::string_view physicalHost = {};
  simdjson::dom::element value = {};
  if (gcpGetNestedElement(inst, {"resourceStatus", "physicalHost"}, value) && !value.get(physicalHost) && physicalHost.size() > 0)
  {
    return gcpHashRackIdentity(physicalHost);
  }

  if (!inst["physicalHost"].get(physicalHost) && physicalHost.size() > 0)
  {
    return gcpHashRackIdentity(physicalHost);
  }

  std::string_view cluster = {};
  std::string_view block = {};
  std::string_view subblock = {};
  bool hasCluster = gcpGetNestedElement(inst, {"resourceStatus", "physicalHostTopology", "cluster"}, value) && !value.get(cluster) && cluster.size() > 0;
  bool hasBlock = gcpGetNestedElement(inst, {"resourceStatus", "physicalHostTopology", "block"}, value) && !value.get(block) && block.size() > 0;
  bool hasSubblock = gcpGetNestedElement(inst, {"resourceStatus", "physicalHostTopology", "subblock"}, value) && !value.get(subblock) && subblock.size() > 0;
  if (hasCluster || hasBlock || hasSubblock)
  {
    String topology = {};
    topology.snprintf<"{}/{}/{}"_ctv>(String(cluster), String(block), String(subblock));
    return gcpHashRackIdentity(std::string_view(topology.c_str(), topology.size()));
  }

  if (zoneText.size() > 0)
  {
    return gcpHashRackIdentity(std::string_view(reinterpret_cast<const char *>(zoneText.data()), size_t(zoneText.size())));
  }

  std::string_view id = {};
  if (!inst["id"].get(id) && id.size() > 0)
  {
    return gcpHashRackIdentity(id);
  }

  return 0;
}
