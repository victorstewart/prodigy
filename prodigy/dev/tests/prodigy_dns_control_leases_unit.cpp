#include <prodigy/dns/control.leases.h>
#include <prodigy/persistent.state.h>

class TestSuite
{
public:

   int failed = 0;

   void expect(bool condition, const char *name)
   {
      basics_log("%s: %s\n", condition ? "PASS" : "FAIL", name);
      failed += condition ? 0 : 1;
   }
};

class Hooks
{
public:

   Vector<uint8_t> events;
   bool persistSucceeds = true;
   bool pairSucceeds = true;

   static bool persist(void *context,
                       const ProdigyMasterAuthorityRuntimeState&,
                       String *)
   {
      Hooks& hooks = *static_cast<Hooks *>(context);
      hooks.events.push_back(1);
      return hooks.persistSucceeds;
   }

   static bool pair(void *context,
                    const ProdigyDnsControlPairingLease&,
                    bool activate,
                    String *)
   {
      Hooks& hooks = *static_cast<Hooks *>(context);
      hooks.events.push_back(activate ? 2 : 3);
      return hooks.pairSucceeds;
   }

   ProdigyDns::ControlPairingLeases::Hooks value(void)
   {
      return {this, persist, pair};
   }
};

static void testDurableMintAndRoleIsolation(TestSuite& suite)
{
   ProdigyMasterAuthorityRuntimeState state;
   Hooks hooks;
   ProdigyDns::ControlPairingLeases leases(state, hooks.value());
   ProdigyDnsControlPairingLease mothership;
   ProdigyDnsControlPairingLease prodigy;
   String failure;

   suite.expect(leases.mint(ProdigyDnsControlClientRole::mothership,
                            IPAddress("2001:db8::10", true),
                            1'000,
                            ProdigyDns::ControlPairingLeases::minimumLifetimeMs,
                            mothership,
                            &failure) &&
                    hooks.events.size() == 3 && hooks.events[0] == 1 &&
                    hooks.events[1] == 2 && hooks.events[2] == 1,
                "dns_control_lease_persists_before_activation");

   hooks.events.clear();
   suite.expect(leases.mint(ProdigyDnsControlClientRole::prodigy,
                            IPAddress("2001:db8::11", true),
                            1'000,
                            ProdigyDns::ControlPairingLeases::minimumLifetimeMs,
                            prodigy,
                            &failure) &&
                    mothership.role != prodigy.role &&
                    mothership.leaseID != prodigy.leaseID &&
                    mothership.secret != prodigy.secret,
                "dns_control_lease_mints_distinct_role_credentials");

   hooks.events.clear();
   suite.expect(leases.revoke(mothership.leaseID,
                              mothership.generation + 1,
                              &failure) == false &&
                    hooks.events.empty(),
                "dns_control_lease_rejects_stale_generation");
   suite.expect(leases.revoke(mothership.leaseID,
                              mothership.generation,
                              &failure) &&
                    hooks.events.size() == 3 && hooks.events[0] == 1 &&
                    hooks.events[1] == 3 && hooks.events[2] == 1,
                "dns_control_lease_persists_revocation_before_deactivation");
}

static void testPersistenceFenceAndExpiry(TestSuite& suite)
{
   ProdigyMasterAuthorityRuntimeState state;
   Hooks hooks;
   ProdigyDns::ControlPairingLeases leases(state, hooks.value());
   ProdigyDnsControlPairingLease minted;
   String failure;

   hooks.persistSucceeds = false;
   suite.expect(leases.mint(ProdigyDnsControlClientRole::prodigy,
                            IPAddress("2001:db8::20", true),
                            1'000,
                            ProdigyDns::ControlPairingLeases::minimumLifetimeMs,
                            minted,
                            &failure) == false &&
                    state.dnsControlPairingLeases.empty() &&
                    hooks.events.size() == 1 && hooks.events[0] == 1,
                "dns_control_lease_never_activates_before_durable_commit");

   hooks.persistSucceeds = true;
   hooks.events.clear();
   suite.expect(leases.mint(ProdigyDnsControlClientRole::prodigy,
                            IPAddress("2001:db8::21", true),
                            1'000,
                            ProdigyDns::ControlPairingLeases::minimumLifetimeMs,
                            minted,
                            &failure),
                "dns_control_lease_fixture_mints_for_expiry");
   hooks.events.clear();
   suite.expect(leases.reconcile(minted.expiresAtMs, &failure) &&
                    state.dnsControlPairingLeases.empty() &&
                    hooks.events.size() == 3 && hooks.events[0] == 1 &&
                    hooks.events[1] == 3 && hooks.events[2] == 1,
                "dns_control_expiry_is_durable_before_deactivation");

   state.dnsControlPairingLeases.resize(
       ProdigyDns::ControlPairingLeases::maximumLeases);
   hooks.events.clear();
   suite.expect(leases.mint(ProdigyDnsControlClientRole::prodigy,
                            IPAddress("2001:db8::22", true),
                            1'000,
                            ProdigyDns::ControlPairingLeases::minimumLifetimeMs,
                            minted,
                            &failure) == false && hooks.events.empty(),
                "dns_control_lease_enforces_1024_entry_bound");
}

static void testPairFailureIsIdempotentlyRecoverable(TestSuite& suite)
{
   ProdigyMasterAuthorityRuntimeState state;
   Hooks hooks;
   hooks.pairSucceeds = false;
   ProdigyDns::ControlPairingLeases leases(state, hooks.value());
   ProdigyDnsControlPairingLease first;
   ProdigyDnsControlPairingLease retried;
   String failure;
   const IPAddress address("2001:db8::30", true);

   suite.expect(leases.mint(ProdigyDnsControlClientRole::mothership,
                            address,
                            1'000,
                            ProdigyDns::ControlPairingLeases::minimumLifetimeMs,
                            first,
                            &failure) == false && first.leaseID != 0 &&
                    first.secret != 0 &&
                    state.dnsControlPairingLeases.size() == 1 &&
                    state.dnsControlPairingLeases[0].applied == false,
                "dns_control_pair_failure_retains_retrievable_pending_lease");

   hooks.pairSucceeds = true;
   hooks.events.clear();
   suite.expect(leases.mint(ProdigyDnsControlClientRole::mothership,
                            address,
                            2'000,
                            ProdigyDns::ControlPairingLeases::minimumLifetimeMs,
                            retried,
                            &failure) && retried.leaseID == first.leaseID &&
                    retried.secret == first.secret && retried.applied &&
                    state.dnsControlPairingLeases.size() == 1 &&
                    hooks.events.size() == 2 && hooks.events[0] == 2 &&
                    hooks.events[1] == 1,
                "dns_control_pair_retry_reuses_exact_durable_lease");
}

static void testPairingSecretUsesSecretsDatabaseShape(TestSuite& suite)
{
   ProdigyPersistentBrainSnapshot snapshot;
   ProdigyDnsControlPairingLease lease;
   lease.leaseID = 91;
   lease.generation = 92;
   lease.secret = 93;
   snapshot.masterAuthority.runtimeState.dnsControlPairingLeases.push_back(lease);

   ProdigyPersistentBrainSnapshot publicSnapshot;
   ProdigyPersistentBrainSnapshotSecrets secrets;
   prodigyExtractPersistentBrainSnapshotSecrets(
       std::move(snapshot), publicSnapshot, secrets);
   suite.expect(publicSnapshot.masterAuthority.runtimeState
                        .dnsControlPairingLeases[0]
                        .secret == 0 &&
                    secrets.dnsControlPairingSecrets.size() == 1 &&
                    secrets.dnsControlPairingSecrets[0].secret == 93,
                "dns_control_pairing_secret_is_removed_from_public_state");

   String failure;
   suite.expect(prodigyApplyPersistentBrainSnapshotSecrets(
                    publicSnapshot, secrets, &failure) &&
                    publicSnapshot.masterAuthority.runtimeState
                            .dnsControlPairingLeases[0]
                            .secret == 93,
                "dns_control_pairing_secret_restores_from_secret_state");
   secrets.clear();
}

int main(void)
{
   TestSuite suite;
   testDurableMintAndRoleIsolation(suite);
   testPersistenceFenceAndExpiry(suite);
   testPairFailureIsIdempotentlyRecoverable(suite);
   testPairingSecretUsesSecretsDatabaseShape(suite);
   return suite.failed == 0 ? 0 : 1;
}
