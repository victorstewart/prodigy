#include <prodigy/mothership/mothership.addmachines.progress.h>
#include <services/debug.h>
#include <prodigy/brain/brain.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/socket.h>

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

static String serializeAddMachines(const AddMachines& response)
{
   String serialized = {};
   BitseryEngine::serialize(serialized, response);
   return serialized;
}

static MachineProvisioningProgress makeProvisioningProgress(const String& cloudID, const String& providerName, const String& status, const String& publicAddress, const String& privateAddress, const String& sshAddress)
{
   MachineProvisioningProgress progress = {};
   progress.cloud.schema = "aws-brain-vm"_ctv;
   progress.cloud.providerMachineType = "c7i-flex.large"_ctv;
   progress.cloud.cloudID = cloudID;
   progress.providerName = providerName;
   progress.status = status;
   progress.ssh.address = sshAddress;
   if (sshAddress.size() > 0)
   {
      progress.ssh.port = 22;
      progress.ssh.user = "root"_ctv;
      progress.ssh.privateKeyPath = "/tmp/test-key"_ctv;
   }
   prodigyAppendUniqueClusterMachineAddress(progress.addresses.publicAddresses, publicAddress);
   prodigyAppendUniqueClusterMachineAddress(progress.addresses.privateAddresses, privateAddress);
   return progress;
}

int main(void)
{
   TestSuite suite;

   {
      Vector<String> serializedResponses = {};

      AddMachines progressA = {};
      progressA.isProgress = true;
      progressA.provisioningProgress.push_back(makeProvisioningProgress("i-0seed"_ctv, "seed-0"_ctv, "launch-submitted"_ctv, {}, {}, {}));
      serializedResponses.push_back(serializeAddMachines(progressA));

      AddMachines progressB = {};
      progressB.isProgress = true;
      progressB.provisioningProgress.push_back(makeProvisioningProgress("i-0seed"_ctv, "seed-0"_ctv, "running"_ctv, "3.1.2.3"_ctv, "172.31.0.10"_ctv, "3.1.2.3"_ctv));
      serializedResponses.push_back(serializeAddMachines(progressB));

      AddMachines finalResponse = {};
      finalResponse.success = true;
      finalResponse.hasTopology = true;
      finalResponse.topology.version = 0x1234;
      serializedResponses.push_back(serializeAddMachines(finalResponse));

      uint32_t nextIndex = 0;
      uint32_t progressCalls = 0;
      String lastStatus = {};
      AddMachines response = {};
      String failure = {};

      bool ok = mothershipAwaitAddMachinesResponse(
         [&] (String& serializedResponse, String& receiveFailure) -> bool {
            if (nextIndex >= serializedResponses.size())
            {
               receiveFailure.assign("unexpected end"_ctv);
               return false;
            }

            serializedResponse = serializedResponses[nextIndex++];
            return true;
         },
         [&] (const Vector<MachineProvisioningProgress>& progress) -> void {
            progressCalls += 1;
            if (!progress.empty())
            {
               lastStatus = progress[0].status;
            }
         },
         response,
         failure
      );

      suite.expect(ok, "await_addmachines_progress_then_success_ok");
      suite.expect(failure.size() == 0, "await_addmachines_progress_then_success_no_failure");
      suite.expect(progressCalls == 2, "await_addmachines_progress_then_success_progress_calls");
      suite.expect(lastStatus == "running"_ctv, "await_addmachines_progress_then_success_last_status");
      suite.expect(response.success, "await_addmachines_progress_then_success_final_success");
      suite.expect(response.hasTopology, "await_addmachines_progress_then_success_has_topology");
      suite.expect(response.topology.version == 0x1234, "await_addmachines_progress_then_success_topology_version");
   }

   {
      AddMachines response = {};
      String failure = {};

      bool ok = mothershipAwaitAddMachinesResponse(
         [&] (String& serializedResponse, String& receiveFailure) -> bool {
            (void)serializedResponse;
            receiveFailure.assign("timed out waiting for addMachines response"_ctv);
            return false;
         },
         [&] (const Vector<MachineProvisioningProgress>& progress) -> void {
            (void)progress;
         },
         response,
         failure
      );

      suite.expect(ok == false, "await_addmachines_receive_failure_rejected");
      suite.expect(failure == "timed out waiting for addMachines response"_ctv, "await_addmachines_receive_failure_reason");
   }

   {
      AddMachines response = {};
      String failure = {};

      bool ok = mothershipAwaitAddMachinesResponse(
         [&] (String& serializedResponse, String& receiveFailure) -> bool {
            (void)receiveFailure;
            serializedResponse.assign("not-bitsery"_ctv);
            return true;
         },
         [&] (const Vector<MachineProvisioningProgress>& progress) -> void {
            (void)progress;
         },
         response,
         failure
      );

      suite.expect(ok == false, "await_addmachines_decode_failure_rejected");
      suite.expect(failure == "addMachines response decode failed"_ctv, "await_addmachines_decode_failure_reason");
   }

   {
      AddMachines finalResponse = {};
      finalResponse.success = false;
      finalResponse.failure = "provider provisioning failed"_ctv;

      AddMachines response = {};
      String failure = {};

      bool ok = mothershipAwaitAddMachinesResponse(
         [&] (String& serializedResponse, String& receiveFailure) -> bool {
            (void)receiveFailure;
            serializedResponse = serializeAddMachines(finalResponse);
            return true;
         },
         [&] (const Vector<MachineProvisioningProgress>& progress) -> void {
            (void)progress;
         },
         response,
         failure
      );

      suite.expect(ok == false, "await_addmachines_final_failure_rejected");
      suite.expect(mothershipFailureIsNonRetryable(failure), "await_addmachines_final_failure_marked_non_retryable");
      mothershipStripNonRetryableFailurePrefix(failure);
      suite.expect(failure == "provider provisioning failed"_ctv, "await_addmachines_final_failure_reason");
   }

   {
      Vector<String> serializedResponses = {};

      AddMachines progress = {};
      progress.isProgress = true;
      progress.provisioningProgress.push_back(makeProvisioningProgress("i-0seed"_ctv, "seed-0"_ctv, "running"_ctv, "3.1.2.3"_ctv, "172.31.0.10"_ctv, "3.1.2.3"_ctv));
      serializedResponses.push_back(serializeAddMachines(progress));

      AddMachines finalResponse = {};
      finalResponse.success = true;
      finalResponse.hasTopology = true;
      finalResponse.topology.version = 0x55;
      serializedResponses.push_back(serializeAddMachines(finalResponse));

      AddMachines trailingProgress = {};
      trailingProgress.isProgress = true;
      trailingProgress.provisioningProgress.push_back(makeProvisioningProgress("i-ignored"_ctv, "seed-1"_ctv, "should-not-print"_ctv, {}, {}, {}));
      serializedResponses.push_back(serializeAddMachines(trailingProgress));

      uint32_t nextIndex = 0;
      uint32_t progressCalls = 0;
      uint32_t receiveCalls = 0;
      AddMachines response = {};
      String failure = {};

      bool ok = mothershipAwaitAddMachinesResponse(
         [&] (String& serializedResponse, String& receiveFailure) -> bool {
            receiveCalls += 1;
            if (nextIndex >= serializedResponses.size())
            {
               receiveFailure.assign("unexpected end"_ctv);
               return false;
            }

            serializedResponse = serializedResponses[nextIndex++];
            return true;
         },
         [&] (const Vector<MachineProvisioningProgress>& receivedProgress) -> void {
            (void)receivedProgress;
            progressCalls += 1;
         },
         response,
         failure
      );

      suite.expect(ok, "await_addmachines_final_success_stops_progress_ok");
      suite.expect(failure.size() == 0, "await_addmachines_final_success_stops_progress_no_failure");
      suite.expect(progressCalls == 1, "await_addmachines_final_success_stops_progress_progress_calls");
      suite.expect(receiveCalls == 2, "await_addmachines_final_success_stops_progress_receive_calls");
      suite.expect(nextIndex == 2, "await_addmachines_final_success_stops_progress_stops_before_trailing_progress");
      suite.expect(response.success, "await_addmachines_final_success_stops_progress_final_success");
      suite.expect(response.topology.version == 0x55, "await_addmachines_final_success_stops_progress_topology_version");
   }

   {
      Vector<String> serializedResponses = {};

      AddMachines progress = {};
      progress.isProgress = true;
      progress.provisioningProgress.push_back(makeProvisioningProgress("i-0seed"_ctv, "seed-0"_ctv, "waiting-for-running"_ctv, {}, {}, {}));
      serializedResponses.push_back(serializeAddMachines(progress));

      AddMachines finalFailure = {};
      finalFailure.success = false;
      finalFailure.failure = "provider provisioning failed"_ctv;
      serializedResponses.push_back(serializeAddMachines(finalFailure));

      AddMachines trailingProgress = {};
      trailingProgress.isProgress = true;
      trailingProgress.provisioningProgress.push_back(makeProvisioningProgress("i-ignored"_ctv, "seed-1"_ctv, "should-not-print"_ctv, {}, {}, {}));
      serializedResponses.push_back(serializeAddMachines(trailingProgress));

      uint32_t nextIndex = 0;
      uint32_t progressCalls = 0;
      uint32_t receiveCalls = 0;
      AddMachines response = {};
      String failure = {};

      bool ok = mothershipAwaitAddMachinesResponse(
         [&] (String& serializedResponse, String& receiveFailure) -> bool {
            receiveCalls += 1;
            if (nextIndex >= serializedResponses.size())
            {
               receiveFailure.assign("unexpected end"_ctv);
               return false;
            }

            serializedResponse = serializedResponses[nextIndex++];
            return true;
         },
         [&] (const Vector<MachineProvisioningProgress>& receivedProgress) -> void {
            (void)receivedProgress;
            progressCalls += 1;
         },
         response,
         failure
      );

      suite.expect(ok == false, "await_addmachines_final_failure_stops_progress_rejected");
      suite.expect(mothershipFailureIsNonRetryable(failure), "await_addmachines_final_failure_stops_progress_marked_non_retryable");
      mothershipStripNonRetryableFailurePrefix(failure);
      suite.expect(failure == "provider provisioning failed"_ctv, "await_addmachines_final_failure_stops_progress_reason");
      suite.expect(progressCalls == 1, "await_addmachines_final_failure_stops_progress_progress_calls");
      suite.expect(receiveCalls == 2, "await_addmachines_final_failure_stops_progress_receive_calls");
      suite.expect(nextIndex == 2, "await_addmachines_final_failure_stops_progress_stops_before_trailing_progress");
   }

   return suite.failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
