#include <networking/includes.h>
#include <services/debug.h>
#include <services/bitsery.h>
#include <services/filesystem.h>
#include <networking/message.h>
#include <services/prodigy.h>
#include <prodigy/types.h>

#include <cstdio>
#include <cstdlib>
#include <vector>

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

template <typename... Args>
static String makeMessage(Args&&... args)
{
   String message;
   Message::construct(message, uint16_t(1), std::forward<Args>(args)...);
   return message;
}

static uint64_t nextRand(uint64_t& state)
{
   // xorshift64*
   state ^= (state >> 12);
   state ^= (state << 25);
   state ^= (state >> 27);
   return state * 2685821657736338717ULL;
}

int main()
{
   TestSuite suite;

   {
      ContainerPlan plan;
      AdvertisementPairing expected(0x11, 0x22, 0x33);
      String payload = makeMessage(expected.secret, expected.address, expected.service, true);
      Message *message = reinterpret_cast<Message *>(payload.data());
      uint8_t *args = message->args;
      uint8_t *terminal = message->terminal();

      plan.updateAdvertisement(args, terminal);
      suite.expect(plan.advertisementPairings.hasEntryFor(expected.service, expected), "advertisement_pairing_valid_activate");

      String deactivatePayload = makeMessage(expected.secret, expected.address, expected.service, false);
      message = reinterpret_cast<Message *>(deactivatePayload.data());
      args = message->args;
      terminal = message->terminal();
      plan.updateAdvertisement(args, terminal);
      suite.expect(plan.advertisementPairings.hasEntryFor(expected.service, expected) == false, "advertisement_pairing_valid_deactivate");
   }

   {
      ContainerPlan plan;
      AdvertisementPairing expected(0xA1, 0xB2, 0xC3);
      String payload = makeMessage(expected.secret, expected.address, expected.service, uint16_t(77), true);
      Message *message = reinterpret_cast<Message *>(payload.data());
      uint8_t *args = message->args;
      uint8_t *terminal = message->terminal();

      plan.updateAdvertisement(args, terminal);
      suite.expect(plan.advertisementPairings.hasEntryFor(expected.service, expected), "advertisement_pairing_with_application_id");
   }

   {
      ContainerPlan plan;
      SubscriptionPairing expected(0x51, 0x61, 0x71, 1900);
      String payload = makeMessage(expected.secret, expected.address, expected.service, expected.port, true);
      Message *message = reinterpret_cast<Message *>(payload.data());
      uint8_t *args = message->args;
      uint8_t *terminal = message->terminal();

      plan.updateSubscription(args, terminal);
      suite.expect(plan.subscriptionPairings.hasEntryFor(expected.service, expected), "subscription_pairing_valid_activate");

      String deactivatePayload = makeMessage(expected.secret, expected.address, expected.service, expected.port, false);
      message = reinterpret_cast<Message *>(deactivatePayload.data());
      args = message->args;
      terminal = message->terminal();
      plan.updateSubscription(args, terminal);
      suite.expect(plan.subscriptionPairings.hasEntryFor(expected.service, expected) == false, "subscription_pairing_valid_deactivate");
   }

   {
      String validAdvertisementPayload = makeMessage(uint128_t(1), uint128_t(2), uint64_t(3), true);
      Message *message = reinterpret_cast<Message *>(validAdvertisementPayload.data());
      bool allEmptyAfterTruncation = true;
      ptrdiff_t payloadSize = message->terminal() - message->args;

      for (ptrdiff_t length = 0; length < payloadSize; ++length)
      {
         ContainerPlan plan;
         uint8_t *args = message->args;
         uint8_t *terminal = message->args + length;
         plan.updateAdvertisement(args, terminal);

         if (!plan.advertisementPairings.isEmpty())
         {
            allEmptyAfterTruncation = false;
            break;
         }
      }

      suite.expect(allEmptyAfterTruncation, "advertisement_truncated_payload_fails_closed");
   }

   {
      String validSubscriptionPayload = makeMessage(uint128_t(1), uint128_t(2), uint64_t(3), uint16_t(4), true);
      Message *message = reinterpret_cast<Message *>(validSubscriptionPayload.data());
      bool allEmptyAfterTruncation = true;
      ptrdiff_t payloadSize = message->terminal() - message->args;

      for (ptrdiff_t length = 0; length < payloadSize; ++length)
      {
         ContainerPlan plan;
         uint8_t *args = message->args;
         uint8_t *terminal = message->args + length;
         plan.updateSubscription(args, terminal);

         if (!plan.subscriptionPairings.isEmpty())
         {
            allEmptyAfterTruncation = false;
            break;
         }
      }

      suite.expect(allEmptyAfterTruncation, "subscription_truncated_payload_fails_closed");
   }

   {
      // Non-standard alignment should fail closed.
      ContainerPlan plan;
      AdvertisementPairing expected(0x1111, 0x2222, 0x3333);
      String alignedPayload = makeMessage(expected.secret, expected.address, expected.service, true);
      Message *message = reinterpret_cast<Message *>(alignedPayload.data());
      std::vector<uint8_t> payload(message->args, message->terminal());
      payload.insert(payload.begin(), uint8_t(0xAB));

      uint8_t *args = payload.data() + 1;
      uint8_t *terminal = payload.data() + payload.size();
      plan.updateAdvertisement(args, terminal);
      suite.expect(plan.advertisementPairings.hasEntryFor(expected.service, expected) == false, "advertisement_nonstandard_alignment_fails_closed");
   }

   {
      // Adversarial random corpus smoke: this is a crash-safety check over malformed control-plane bytes.
      uint64_t state = 0xD00DCAFE12345678ULL;
      for (uint32_t i = 0; i < 25000; ++i)
      {
         size_t size = size_t(nextRand(state) % 96ULL);
         std::vector<uint8_t> bytes(size);
         for (size_t j = 0; j < size; ++j)
         {
            bytes[j] = static_cast<uint8_t>(nextRand(state) & 0xFFU);
         }

         ContainerPlan plan;
         uint8_t *args = bytes.empty() ? nullptr : bytes.data();
         uint8_t *terminal = bytes.empty() ? nullptr : bytes.data() + bytes.size();

         plan.updateAdvertisement(args, terminal);
         args = bytes.empty() ? nullptr : bytes.data();
         terminal = bytes.empty() ? nullptr : bytes.data() + bytes.size();
         plan.updateSubscription(args, terminal);
      }

      suite.expect(true, "pairing_parser_random_adversarial_corpus_survives");
   }

   if (suite.failed != 0)
   {
      basics_log("FAILED: %d cases\n", suite.failed);
      return EXIT_FAILURE;
   }

   basics_log("PASS: prodigy pairing parser adversarial unit\n");
   return EXIT_SUCCESS;
}
