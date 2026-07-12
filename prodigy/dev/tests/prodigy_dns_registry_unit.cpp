#include <networking/includes.h>
#include <services/prodigy.h>

#include <cstdlib>

static_assert(MeshRegistry::DNS::applicationID == 1);
static_assert(MeshRegistry::DNS::resolver == MeshServices::generateStatelessService(1, 1));

int main(void)
{
  auto service = MeshRegistry::serviceMappings.find("MeshRegistry::DNS::resolver"_ctv);
  auto application = MeshRegistry::applicationIDMappings.find("DNS"_ctv);
  auto name = MeshRegistry::applicationNameMappings.find(MeshRegistry::DNS::applicationID);

  return service != MeshRegistry::serviceMappings.end() && service->second == MeshRegistry::DNS::resolver &&
      application != MeshRegistry::applicationIDMappings.end() && application->second == MeshRegistry::DNS::applicationID &&
      name != MeshRegistry::applicationNameMappings.end() && name->second == "DNS"_ctv
    ? EXIT_SUCCESS
    : EXIT_FAILURE;
}
