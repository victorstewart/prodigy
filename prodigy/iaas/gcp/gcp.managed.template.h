#pragma once

#include <prodigy/iaas/gcp/gcp.compute.transaction.h>
#include <prodigy/json.h>
#include <prodigy/types.h>

class GcpManagedTemplateTransaction final
{
public:

  class Spec
  {
  public:

    String name;
    String body;
  };

  constexpr static size_t responseBytes = 1024 * 1024;
  constexpr static uint32_t maximumPolls = 1200;
  constexpr static uint64_t pollDelayUs = 500 * 1000;
  constexpr static std::chrono::minutes pollTimeout = std::chrono::minutes(10);

private:

  ProdigyHostHttpOperation::Submission http;
  ProdigyHostDelayOperation::Submission delay;
  String project;
  String token;
  MultiCurlClient::TimePoint deadline;

  static void assignRequestFailure(const MultiCurlClient::Result& result,
                                   const char *operation,
                                   String& failure)
  {
    if (GcpComputeTransaction::parseApiFailure(result.body, failure))
    {
      return;
    }
    if (result.status == MultiCurlClient::Status::deadlineExceeded)
    {
      failure.assign("gcp managed template deadline exceeded"_ctv);
    }
    else if (result.status == MultiCurlClient::Status::responseTooLarge)
    {
      failure.assign("gcp managed template response exceeds 1 MiB"_ctv);
    }
    else if (result.status == MultiCurlClient::Status::success)
    {
      failure.snprintf<"{} failed with HTTP {itoa}"_ctv>(String(operation), uint32_t(result.statusCode));
    }
    else
    {
      failure.assign(operation);
      failure.append(" transport failed"_ctv);
    }
  }

  MultiCurlClient::Request request(MultiCurlClient::Method method,
                                   String url,
                                   const String *body = nullptr,
                                   MultiCurlClient::TimePoint operationDeadline = MultiCurlClient::TimePoint::max()) const
  {
    const MultiCurlClient::TimePoint requestDeadline =
        operationDeadline < deadline ? operationDeadline : deadline;
    return GcpComputeTransaction::request(method,
                                          std::move(url),
                                          body,
                                          token,
                                          requestDeadline,
                                          responseBytes);
  }

  String templatesUrl(const String *name = nullptr) const
  {
    String url = {};
    url.assign("https://compute.googleapis.com/compute/v1/projects/"_ctv);
    GcpComputeTransaction::appendPercentEncoded(url, project);
    url.append("/global/instanceTemplates"_ctv);
    if (name)
    {
      url.append('/');
      GcpComputeTransaction::appendPercentEncoded(url, *name);
    }
    return url;
  }

  String operationUrl(const String& name) const
  {
    String url = {};
    url.assign("https://compute.googleapis.com/compute/v1/projects/"_ctv);
    GcpComputeTransaction::appendPercentEncoded(url, project);
    url.append("/global/operations/"_ctv);
    GcpComputeTransaction::appendPercentEncoded(url, name);
    url.append("?fields=status,error,httpErrorStatusCode,httpErrorMessage,statusMessage"_ctv);
    return url;
  }

  void poll(CoroutineStack *coro, const String& operationName, String& failure)
  {
    MultiCurlClient::TimePoint pollDeadline = MultiCurlClient::Clock::now() + pollTimeout;
    if (deadline < pollDeadline)
    {
      pollDeadline = deadline;
    }
    for (uint32_t observation = 0; observation < maximumPolls; ++observation)
    {
      if (MultiCurlClient::Clock::now() >= pollDeadline)
      {
        failure.assign("gcp managed template operation deadline exceeded"_ctv);
        co_return;
      }
      MultiCurlClient::Result result = {};
      bool complete = false;
      if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
            GcpComputeTransaction::submit(
                http,
                coro,
                request(MultiCurlClient::Method::get,
                        operationUrl(operationName),
                        nullptr,
                        pollDeadline),
                result,
                complete);
          }))
      {
        co_await coro->suspendAtIndex(suspendIndex);
      }
      if (complete == false)
      {
        failure.assign("gcp managed template operation poll submission failed"_ctv);
        co_return;
      }
      if (result.status != MultiCurlClient::Status::success ||
          result.statusCode < 200 || result.statusCode >= 300)
      {
        assignRequestFailure(result, "gcp managed template operation poll", failure);
        co_return;
      }
      const GcpComputeTransaction::OperationState state =
          GcpComputeTransaction::parseOperation(result.body, failure);
      if (state != GcpComputeTransaction::OperationState::pending)
      {
        co_return;
      }
      if (observation + 1 >= maximumPolls)
      {
        break;
      }
      MultiCurlClient::TimePoint now = MultiCurlClient::Clock::now();
      if (now >= pollDeadline || pollDeadline - now < std::chrono::microseconds(pollDelayUs))
      {
        failure.assign("gcp managed template operation deadline exceeded"_ctv);
        co_return;
      }
      bool delayComplete = false;
      if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
            GcpComputeTransaction::wait(delay, coro, pollDelayUs, delayComplete);
          }))
      {
        co_await coro->suspendAtIndex(suspendIndex);
      }
      if (delayComplete == false)
      {
        failure.assign("gcp managed template operation delay failed"_ctv);
        co_return;
      }
    }
    failure.assign("gcp managed template operation poll limit exceeded"_ctv);
  }

  void mutate(CoroutineStack *coro,
              MultiCurlClient::Method method,
              String url,
              const String *body,
              bool tolerateNotFound,
              bool& mutationAccepted,
              String& failure)
  {
    MultiCurlClient::Result result = {};
    bool complete = false;
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          GcpComputeTransaction::submit(http,
                                        coro,
                                        request(method, std::move(url), body),
                                        result,
                                        complete);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    if (complete && result.status == MultiCurlClient::Status::success &&
        tolerateNotFound && result.statusCode == 404)
    {
      co_return;
    }
    if (complete == false)
    {
      if (method == MultiCurlClient::Method::delete_)
      {
        failure.assign("gcp managed template delete submission failed"_ctv);
      }
      else
      {
        failure.assign("gcp managed template create submission failed"_ctv);
      }
      co_return;
    }
    if (result.status != MultiCurlClient::Status::success ||
        result.statusCode < 200 || result.statusCode >= 300)
    {
      assignRequestFailure(result, method == MultiCurlClient::Method::delete_
                                       ? "gcp managed template delete"
                                       : "gcp managed template create",
                           failure);
      co_return;
    }
    mutationAccepted = true;
    String operationName = {};
    if (GcpComputeTransaction::parseOperationName(result.body, operationName, failure) == false)
    {
      co_return;
    }
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          poll(coro, operationName, failure);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
  }

  void replace(CoroutineStack *coro,
               const Spec& spec,
               bool& mutationAccepted,
               String& failure)
  {
    MultiCurlClient::Result probe = {};
    bool complete = false;
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          GcpComputeTransaction::submit(
              http,
              coro,
              request(MultiCurlClient::Method::get, templatesUrl(&spec.name)),
              probe,
              complete);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    if (complete == false)
    {
      failure.assign("gcp managed template probe submission failed"_ctv);
      co_return;
    }
    if (probe.status != MultiCurlClient::Status::success)
    {
      assignRequestFailure(probe, "gcp managed template probe", failure);
      co_return;
    }
    if (probe.statusCode == 404)
    {
    }
    else if (probe.statusCode >= 200 && probe.statusCode < 300)
    {
      if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
            mutate(coro,
                   MultiCurlClient::Method::delete_,
                   templatesUrl(&spec.name),
                   nullptr,
                   true,
                   mutationAccepted,
                   failure);
          }))
      {
        co_await coro->suspendAtIndex(suspendIndex);
      }
      if (failure.size() > 0)
      {
        co_return;
      }
    }
    else
    {
      assignRequestFailure(probe, "gcp managed template probe", failure);
      co_return;
    }
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          mutate(coro,
                 MultiCurlClient::Method::post,
                 templatesUrl(),
                 &spec.body,
                 false,
                 mutationAccepted,
                 failure);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
  }

public:

  GcpManagedTemplateTransaction(ProdigyHostHttpOperation::Submission http,
                                ProdigyHostDelayOperation::Submission delay,
                                String project,
                                String token,
                                MultiCurlClient::TimePoint deadline)
      : http(http),
        delay(delay),
        deadline(deadline)
  {
    this->project.assign(project);
    this->token.assign(token);
  }

  static bool buildSpec(const String& name,
                        const String& serviceAccountEmail,
                        const String& network,
                        const String& subnetwork,
                        const MachineConfig& config,
                        bool spot,
                        Spec& spec,
                        String& failure)
  {
    failure.clear();
    if (name.empty())
    {
      failure.assign("gcp managed instance template name required"_ctv);
      return false;
    }
    if (serviceAccountEmail.empty())
    {
      failure.assign("gcp managed instance template requires serviceAccountEmail"_ctv);
      return false;
    }
    if (config.providerMachineType.empty())
    {
      failure.assign("gcp managed instance template requires providerMachineType"_ctv);
      return false;
    }
    if (config.vmImageURI.empty())
    {
      failure.assign("gcp managed instance template requires vmImageURI"_ctv);
      return false;
    }

    spec.name.assign(name);
    String& body = spec.body;
    body.clear();
    body.append("{\"name\":"_ctv);
    prodigyAppendEscapedJSONStringLiteral(body, name);
    body.append(",\"properties\":{\"machineType\":"_ctv);
    prodigyAppendEscapedJSONStringLiteral(body, config.providerMachineType);
    if (config.cpu.cpuPlatform.size() > 0)
    {
      body.append(",\"minCpuPlatform\":"_ctv);
      prodigyAppendEscapedJSONStringLiteral(body, config.cpu.cpuPlatform);
    }
    body.append(",\"labels\":{\"app\":\"prodigy\",\"brain\":\"false\"}"_ctv);
    body.append(",\"tags\":{\"items\":[\"prodigy\"]}"_ctv);
    body.append(",\"metadata\":{\"items\":[{\"key\":\"brain\",\"value\":\"false\"}]}"_ctv);
    body.append(",\"serviceAccounts\":[{\"email\":"_ctv);
    prodigyAppendEscapedJSONStringLiteral(body, serviceAccountEmail);
    body.append(",\"scopes\":[\"https://www.googleapis.com/auth/cloud-platform\"]}]"_ctv);
    body.append(",\"networkInterfaces\":[{\"network\":"_ctv);
    prodigyAppendEscapedJSONStringLiteral(body, network);
    if (subnetwork.size() > 0)
    {
      body.append(",\"subnetwork\":"_ctv);
      prodigyAppendEscapedJSONStringLiteral(body, subnetwork);
    }
    body.append(",\"accessConfigs\":[{\"name\":\"External NAT\",\"type\":\"ONE_TO_ONE_NAT\"}]}]"_ctv);
    body.append(",\"disks\":[{\"boot\":true,\"autoDelete\":true,\"type\":\"PERSISTENT\",\"initializeParams\":{\"sourceImage\":"_ctv);
    prodigyAppendEscapedJSONStringLiteral(body, config.vmImageURI);
    body.append(",\"diskSizeGb\":20}}]"_ctv);
    if (spot)
    {
      body.append(",\"scheduling\":{\"provisioningModel\":\"SPOT\",\"instanceTerminationAction\":\"DELETE\",\"automaticRestart\":false}"_ctv);
    }
    body.append("}}"_ctv);
    return true;
  }

  void run(CoroutineStack *coro, const Vector<Spec>& specs, String& failure)
  {
    failure.clear();
    if (coro == nullptr || http.submit == nullptr || http.cancel == nullptr ||
        delay.queue == nullptr || delay.cancel == nullptr)
    {
      failure.assign("gcp managed template runtime unavailable"_ctv);
      co_return;
    }
    if (project.empty() || token.empty())
    {
      failure.assign("gcp managed template identity unavailable"_ctv);
      co_return;
    }
    if (specs.empty() || specs.size() > 2)
    {
      failure.assign("gcp managed template transaction requires one or two templates"_ctv);
      co_return;
    }
    for (const Spec& spec : specs)
    {
      if (spec.name.empty() || spec.body.empty())
      {
        failure.assign("gcp managed template transaction contains invalid template"_ctv);
        co_return;
      }
    }
    if (specs.size() == 2 && specs[0].name.equals(specs[1].name))
    {
      failure.assign("gcp managed template transaction requires distinct template names"_ctv);
      co_return;
    }
    for (uint32_t index = 0; index < specs.size(); ++index)
    {
      bool mutationAccepted = false;
      if (MultiCurlClient::Clock::now() >= deadline)
      {
        failure.assign("gcp managed template deadline exceeded"_ctv);
      }
      else
      {
        if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
              replace(coro, specs[index], mutationAccepted, failure);
            }))
        {
          co_await coro->suspendAtIndex(suspendIndex);
        }
      }
      if (failure.size() > 0)
      {
        if (mutationAccepted)
        {
          String detail = std::move(failure);
          failure.assign("gcp managed template cloud state may be partial after accepted mutation of '"_ctv);
          failure.append(specs[index].name);
          failure.append("': "_ctv);
          failure.append(detail);
        }
        else if (index > 0)
        {
          String detail = std::move(failure);
          failure.assign("gcp managed template cloud state is partial after prior template completion: "_ctv);
          failure.append(detail);
        }
        co_return;
      }
    }
  }
};
