// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0

package neuronhub

import (
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func fixtureBytes(t *testing.T, name string) []byte {
	t.Helper()

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("prodigy: failed to locate test file")
	}

	data, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "fixtures", name))
	if err != nil {
		t.Fatalf("prodigy: read fixture %s: %v", name, err)
	}

	return data
}

func TestFixtureCredentialBundleDecode(t *testing.T) {
	bundle, err := DecodeCredentialBundle(fixtureBytes(t, "startup.credential_bundle.full.bin"))
	if err != nil {
		t.Fatalf("DecodeCredentialBundle: %v", err)
	}

	if bundle.BundleGeneration != 101 {
		t.Fatalf("bundle generation = %d, want 101", bundle.BundleGeneration)
	}
	if len(bundle.TLSIdentities) != 1 || bundle.TLSIdentities[0].Name != "demo-cert" {
		t.Fatalf("unexpected tls identities: %#v", bundle.TLSIdentities)
	}
	if len(bundle.APICredentials) != 1 || bundle.APICredentials[0].Metadata["scope"] != "demo" {
		t.Fatalf("unexpected api credentials: %#v", bundle.APICredentials)
	}
}

func TestFixtureCredentialDeltaDecode(t *testing.T) {
	delta, err := DecodeCredentialDelta(fixtureBytes(t, "startup.credential_delta.full.bin"))
	if err != nil {
		t.Fatalf("DecodeCredentialDelta: %v", err)
	}

	if delta.BundleGeneration != 102 {
		t.Fatalf("bundle generation = %d, want 102", delta.BundleGeneration)
	}
	if len(delta.RemovedTLSNames) != 1 || delta.RemovedTLSNames[0] != "legacy-cert" {
		t.Fatalf("unexpected removed tls names: %#v", delta.RemovedTLSNames)
	}
	if len(delta.RemovedAPINames) != 1 || delta.RemovedAPINames[0] != "legacy-token" {
		t.Fatalf("unexpected removed api names: %#v", delta.RemovedAPINames)
	}
	if delta.Reason != "fixture-rotation" {
		t.Fatalf("reason = %q, want fixture-rotation", delta.Reason)
	}
}

func TestFixtureContainerParametersDecode(t *testing.T) {
	params, err := DecodeContainerParameters(fixtureBytes(t, "startup.container_parameters.full.bin"))
	if err != nil {
		t.Fatalf("DecodeContainerParameters: %v", err)
	}

	if params.MemoryMB != 1536 {
		t.Fatalf("memory = %d, want 1536", params.MemoryMB)
	}
	if len(params.Advertises) != 1 || params.Advertises[0].Port != 24001 {
		t.Fatalf("unexpected advertises: %#v", params.Advertises)
	}
	if len(params.SubscriptionPairings) != 1 || params.SubscriptionPairings[0].ApplicationID != 0x2233 {
		t.Fatalf("unexpected subscription pairings: %#v", params.SubscriptionPairings)
	}
	if len(params.AdvertisementPairings) != 1 || params.AdvertisementPairings[0].ApplicationID != 0x3344 {
		t.Fatalf("unexpected advertisement pairings: %#v", params.AdvertisementPairings)
	}
	if params.DatacenterUniqueTag != 23 {
		t.Fatalf("datacenter tag = %d, want 23", params.DatacenterUniqueTag)
	}
	if params.CredentialBundle == nil || params.CredentialBundle.BundleGeneration != 101 {
		t.Fatalf("unexpected credential bundle: %#v", params.CredentialBundle)
	}
}

func TestFixtureFrames(t *testing.T) {
	frame, err := ParseMessageFrame(fixtureBytes(t, "frame.resource_delta_ack.accepted.bin"))
	if err != nil {
		t.Fatalf("ParseMessageFrame(resource_delta_ack): %v", err)
	}
	if frame.Topic != ContainerTopicResourceDeltaAck {
		t.Fatalf("topic = %d, want %d", frame.Topic, ContainerTopicResourceDeltaAck)
	}
	if len(frame.Payload) != 1 || frame.Payload[0] != 1 {
		t.Fatalf("unexpected payload: %#v", frame.Payload)
	}

	statistics, err := ParseMessageFrame(fixtureBytes(t, "frame.statistics.demo.bin"))
	if err != nil {
		t.Fatalf("ParseMessageFrame(statistics): %v", err)
	}
	if statistics.Topic != ContainerTopicStatistics {
		t.Fatalf("statistics topic = %d, want %d", statistics.Topic, ContainerTopicStatistics)
	}
	if len(statistics.Payload) != 32 {
		t.Fatalf("statistics payload length = %d, want 32", len(statistics.Payload))
	}

	if got := BuildReadyFrame(); string(got) != string(fixtureBytes(t, "frame.healthy.empty.bin")) {
		t.Fatalf("BuildReadyFrame mismatch")
	}
	if got := BuildStatisticsFrame([]MetricPair{{Key: 1, Value: 2}, {Key: 3, Value: 4}}); string(got) != string(fixtureBytes(t, "frame.statistics.demo.bin")) {
		t.Fatalf("BuildStatisticsFrame mismatch")
	}
	if got := BuildResourceDeltaAckFrame(true); string(got) != string(fixtureBytes(t, "frame.resource_delta_ack.accepted.bin")) {
		t.Fatalf("BuildResourceDeltaAckFrame mismatch")
	}
	if got := BuildCredentialsRefreshAckFrame(); string(got) != string(fixtureBytes(t, "frame.credentials_refresh_ack.empty.bin")) {
		t.Fatalf("BuildCredentialsRefreshAckFrame mismatch")
	}
}

func TestFrameDecoderAndHandleFrame(t *testing.T) {
	params, err := DecodeContainerParameters(fixtureBytes(t, "startup.container_parameters.full.bin"))
	if err != nil {
		t.Fatalf("DecodeContainerParameters: %v", err)
	}

	hub, err := NewBorrowedNeuronHubFromParameters(DispatchBase{}, params)
	if err != nil {
		t.Fatalf("NewBorrowedNeuronHubFromParameters: %v", err)
	}

	ping := BuildMessageFrame(ContainerTopicPing, nil)
	var decoder FrameDecoder
	frames, err := decoder.Feed(ping[:5])
	if err != nil {
		t.Fatalf("Feed(partial): %v", err)
	}
	if len(frames) != 0 {
		t.Fatalf("partial feed yielded %d frames, want 0", len(frames))
	}

	frames, err = decoder.Feed(ping[5:])
	if err != nil {
		t.Fatalf("Feed(final): %v", err)
	}
	if len(frames) != 1 {
		t.Fatalf("final feed yielded %d frames, want 1", len(frames))
	}

	outbound, err := hub.HandleFrame(frames[0])
	if err != nil {
		t.Fatalf("HandleFrame: %v", err)
	}
	if len(outbound) != 1 || outbound[0].Topic != ContainerTopicPing || len(outbound[0].Payload) != 0 {
		t.Fatalf("unexpected outbound frames: %#v", outbound)
	}
}

func TestPairingAddressHelpers(t *testing.T) {
	address := U128{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}

	target, err := (SubscriptionPairing{
		Address: address,
		Port:    17011,
	}).Target()
	if err != nil {
		t.Fatalf("SubscriptionPairing.Target: %v", err)
	}
	if target != netip.MustParseAddrPort("[2001:db8::1]:17011") {
		t.Fatalf("target = %v", target)
	}

	peer, err := (AdvertisementPairing{Address: address}).PeerAddr()
	if err != nil {
		t.Fatalf("AdvertisementPairing.PeerAddr: %v", err)
	}
	if peer != netip.MustParseAddr("2001:db8::1") {
		t.Fatalf("peer = %v", peer)
	}
}
