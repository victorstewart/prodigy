// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0

package neuronhub

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestAegisSessionFixtures(t *testing.T) {
	pairing := SubscriptionPairing{
		Secret: U128{
			0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
			0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		},
		Address: U128{
			0xfd, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		},
		Service:       0x2233000000001001,
		Port:          3210,
		ApplicationID: 0x2233,
		Activate:      true,
	}

	session := AegisSessionFromSubscription(pairing)
	aux := []byte("mesh-aegis")
	plaintext := []byte("frame-one")
	fixtureHash := fixtureBytes(t, "aegis.hash.demo.bin")
	fixtureTFO := fixtureBytes(t, "aegis.tfo.demo.bin")
	fixtureFrame := fixtureBytes(t, "aegis.frame.demo.bin")

	if got := session.BuildTFOData(aux); !bytes.Equal(got, fixtureTFO) {
		t.Fatalf("BuildTFOData mismatch")
	}

	var pairingHashBytes [8]byte
	binary.LittleEndian.PutUint64(pairingHashBytes[:], session.PairingHash())
	if !bytes.Equal(pairingHashBytes[:], fixtureHash) {
		t.Fatalf("PairingHash mismatch")
	}

	nonce := U128{
		0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
		0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
	}
	frame, err := session.EncryptWithNonce(plaintext, nonce)
	if err != nil {
		t.Fatalf("EncryptWithNonce: %v", err)
	}
	if !bytes.Equal(frame, fixtureFrame) {
		t.Fatalf("EncryptWithNonce fixture mismatch")
	}

	decrypted, header, err := session.Decrypt(fixtureFrame)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if header.Size != uint32(len(fixtureFrame)) {
		t.Fatalf("header size = %d, want %d", header.Size, len(fixtureFrame))
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("Decrypt plaintext mismatch")
	}
}
