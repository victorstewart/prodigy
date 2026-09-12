#include <includes.h>
#include <prodigy/mothership/mothership.neuron.checkpoint.h>
#include <services/bitsery.h>
#include <networking/message.h>

class TestSuite {
public:
  int failed = 0;
  void expect(bool value, const char *name)
  {
    basics_log("%s: %s\n", value ? "PASS" : "FAIL", name);
    failed += value ? 0 : 1;
  }
};

int main()
{
  TestSuite suite;
  ContainerPlan original = {};
  original.uuid = 71;
  original.fragment = 4;
  original.runtimeReady = true;
  original.hasCredentialBundle = true;
  original.credentialBundle.bundleGeneration = 19;
  original.subscriptionPairings.push_back(SubscriptionPairing(0x1111, 0x2222, 37, 8080));
  original.advertisementPairings.push_back(AdvertisementPairing(0x3333, 0x4444, 37));
  ContainerPlan second = original;
  second.uuid = 72;
  second.credentialBundle.bundleGeneration = 20;
  second.subscriptionPairings[0].secret = 0x5555;

  String serialized = {}, serializedSecond = {};
  BitseryEngine::serialize(serialized, original);
  BitseryEngine::serialize(serializedSecond, second);
  struct local_container_subnet6 fragment = {};
  fragment.dpfx = 17;
  fragment.mpfx[0] = 1;
  fragment.mpfx[1] = 2;
  fragment.mpfx[2] = 3;
  String frame = {};
  uint32_t header = Message::appendHeader(frame, NeuronTopic::stateUpload);
  Message::appendAlignedBuffer<Alignment::one>(frame, reinterpret_cast<uint8_t *>(&fragment), sizeof(fragment));
  Message::appendValue(frame, serialized);
  Message::appendValue(frame, serializedSecond);
  Message::finish(frame, header);

  ProdigyLocalContainerCheckpoint checkpoint = {};
  String failure = {};
  suite.expect(mothershipNeuronCheckpointDecodeStateUpload(frame, checkpoint, &failure), "decodes_live_state_upload");
  suite.expect(checkpoint.datacenterFragment == 17 && checkpoint.machineFragment == 0x010203, "preserves_fragment");
  String decodedFirst = {}, decodedSecond = {};
  if (checkpoint.plans.size() == 2)
  {
    BitseryEngine::serialize(decodedFirst, checkpoint.plans[0]);
    BitseryEngine::serialize(decodedSecond, checkpoint.plans[1]);
  }
  suite.expect(checkpoint.plans.size() == 2 && decodedFirst == serialized && decodedSecond == serializedSecond,
               "preserves_exact_live_pairings_credentials_and_multiple_plans");

  String malformed = frame;
  malformed.resize(sizeof(Message));
  failure.clear();
  suite.expect(mothershipNeuronCheckpointDecodeStateUpload(malformed, checkpoint, &failure) == false && failure.empty() == false,
               "rejects_truncated_state_upload");
  return suite.failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
