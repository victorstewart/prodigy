#pragma once

#include <prodigy/iaas/gcp/gcp.managed.template.h>
#include <prodigy/mothership/mothership.cluster.types.h>

class MothershipGcpManagedTemplatePlan final
{
public:

  Vector<GcpManagedTemplateTransaction::Spec> specs;

  std::chrono::minutes timeout(void) const
  {
    return specs.size() == 1 ? std::chrono::minutes(25) : std::chrono::minutes(45);
  }

  static bool build(const MothershipProdigyCluster& cluster,
                    MothershipGcpManagedTemplatePlan& plan,
                    String& failure)
  {
    plan = {};
    failure.clear();
    const MothershipProdigyClusterMachineSchema *standard = nullptr;
    const MothershipProdigyClusterMachineSchema *spot = nullptr;
    for (const MothershipProdigyClusterMachineSchema& schema : cluster.machineSchemas)
    {
      if (schema.budget == 0)
      {
        continue;
      }
      if (schema.lifetime == MachineLifetime::spot)
      {
        if (spot == nullptr)
        {
          spot = &schema;
        }
      }
      else if (standard == nullptr)
      {
        standard = &schema;
      }
    }
    if (standard == nullptr && spot == nullptr)
    {
      failure.assign("gcp managed template plan requires an active machine schema"_ctv);
      return false;
    }

    MothershipGcpManagedTemplatePlan built = {};
    built.specs.reserve(2);
    auto append = [&](const MothershipProdigyClusterMachineSchema *schema, bool isSpot) -> bool {
      if (schema == nullptr)
      {
        return true;
      }
      MachineConfig config = {};
      mothershipBuildMachineConfigFromSchema(*schema, config);
      GcpManagedTemplateTransaction::Spec spec = {};
      const String& name = isSpot ? schema->gcpInstanceTemplateSpot : schema->gcpInstanceTemplate;
      if (GcpManagedTemplateTransaction::buildSpec(name,
                                                   cluster.gcp.serviceAccountEmail,
                                                   cluster.gcp.network,
                                                   cluster.gcp.subnetwork,
                                                   config,
                                                   isSpot,
                                                   spec,
                                                   failure) == false)
      {
        return false;
      }
      built.specs.push_back(std::move(spec));
      return true;
    };
    if (append(standard, false) == false || append(spot, true) == false)
    {
      return false;
    }
    plan = std::move(built);
    return true;
  }
};
