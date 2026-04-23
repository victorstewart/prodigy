// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0

package neuronhub

import (
	"crypto/rand"
	"encoding/binary"
	"errors"

	"github.com/aegis-aead/go-libaegis/aegis128l"
)

const (
	AegisAlignment       = 16
	AegisHeaderBytes     = 24
	AegisMaxFrameBytes   = 2 * 1024 * 1024
	AegisMinFrameBytes   = 48
	AegisNonceBytes      = 16
	AegisPairingHashSeed = int64(0x4d595df4d0f33173)
	AegisTagBytes        = 16
)

var (
	errAegisFrameTruncated    = errors.New("prodigy: Aegis frame is truncated")
	errAegisFrameSize         = errors.New("prodigy: Aegis frame byte length does not match declared size")
	errAegisFrameBounds       = errors.New("prodigy: Aegis frame size is out of bounds")
	errAegisFrameAlignment    = errors.New("prodigy: Aegis frame is not 16-byte aligned")
	errAegisEncryptedDataSize = errors.New("prodigy: Aegis encrypted payload size is invalid")
	errAegisPlaintextTooLarge = errors.New("prodigy: Aegis plaintext length exceeds the frame limit")
	errAegisNonceGeneration   = errors.New("prodigy: Aegis nonce generation failed")
	gxhashRoundKey0           = gxhashKeyBlock(0)
	gxhashRoundKey1           = gxhashKeyBlock(4)
	gxhashRoundKey2           = gxhashKeyBlock(8)
)

type ServiceRole uint8

const (
	ServiceRoleNone ServiceRole = iota
	ServiceRoleAdvertiser
	ServiceRoleSubscriber
)

type AegisFrameHeader struct {
	Size              uint32
	Nonce             U128
	EncryptedDataSize uint32
}

type AegisSession struct {
	Secret  U128
	Service uint64
	Role    ServiceRole
}

func AegisSessionFromAdvertisement(pairing AdvertisementPairing) AegisSession {
	return AegisSession{
		Secret:  pairing.Secret,
		Service: pairing.Service,
		Role:    ServiceRoleAdvertiser,
	}
}

func AegisSessionFromSubscription(pairing SubscriptionPairing) AegisSession {
	return AegisSession{
		Secret:  pairing.Secret,
		Service: pairing.Service,
		Role:    ServiceRoleSubscriber,
	}
}

func (session AegisSession) PairingHash() uint64 {
	return pairingHash24(session.Secret, session.Service)
}

func (session AegisSession) BuildTFOData(aux []byte) []byte {
	out := make([]byte, 8+len(aux))
	binary.LittleEndian.PutUint64(out[:8], session.PairingHash())
	copy(out[8:], aux)
	return out
}

func (session AegisSession) Encrypt(plaintext []byte) ([]byte, error) {
	var nonce U128
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, errors.Join(errAegisNonceGeneration, err)
	}

	return session.EncryptWithNonce(plaintext, nonce)
}

func (session AegisSession) EncryptWithNonce(plaintext []byte, nonce U128) ([]byte, error) {
	frameBytes, encryptedDataBytes, err := aegisFrameShape(len(plaintext))
	if err != nil {
		return nil, err
	}

	aead, err := aegis128l.New(session.Secret[:], AegisTagBytes)
	if err != nil {
		return nil, err
	}

	frame := make([]byte, AegisHeaderBytes, frameBytes)
	binary.LittleEndian.PutUint32(frame[:4], uint32(frameBytes))
	copy(frame[4:20], nonce[:])
	binary.LittleEndian.PutUint32(frame[20:24], uint32(encryptedDataBytes))
	frame = aead.Seal(frame, nonce[:], plaintext, frame[:4])
	if len(frame) < frameBytes {
		frame = append(frame, make([]byte, frameBytes-len(frame))...)
	}

	return frame, nil
}

func (session AegisSession) Decrypt(frame []byte) ([]byte, AegisFrameHeader, error) {
	header, err := DecodeAegisFrameHeader(frame)
	if err != nil {
		return nil, AegisFrameHeader{}, err
	}

	aead, err := aegis128l.New(session.Secret[:], AegisTagBytes)
	if err != nil {
		return nil, AegisFrameHeader{}, err
	}

	ciphertext := frame[AegisHeaderBytes : AegisHeaderBytes+header.EncryptedDataSize]
	plaintext, err := aead.Open(nil, header.Nonce[:], ciphertext, frame[:4])
	if err != nil {
		return nil, AegisFrameHeader{}, err
	}

	return plaintext, header, nil
}

func DecodeAegisFrameHeader(frame []byte) (AegisFrameHeader, error) {
	if len(frame) < AegisHeaderBytes {
		return AegisFrameHeader{}, errAegisFrameTruncated
	}

	size := binary.LittleEndian.Uint32(frame[:4])
	if err := validateAegisFrameBytes(int(size)); err != nil {
		return AegisFrameHeader{}, err
	}
	if len(frame) != int(size) {
		return AegisFrameHeader{}, errAegisFrameSize
	}

	var nonce U128
	copy(nonce[:], frame[4:20])
	encryptedDataSize := binary.LittleEndian.Uint32(frame[20:24])
	if encryptedDataSize < AegisTagBytes {
		return AegisFrameHeader{}, errAegisEncryptedDataSize
	}

	maxEncryptedDataBytes := int(size) - AegisHeaderBytes
	if int(encryptedDataSize) > maxEncryptedDataBytes {
		return AegisFrameHeader{}, errAegisEncryptedDataSize
	}

	return AegisFrameHeader{
		Size:              size,
		Nonce:             nonce,
		EncryptedDataSize: encryptedDataSize,
	}, nil
}

func aegisFrameShape(plaintextBytes int) (frameBytes int, encryptedDataBytes int, err error) {
	if plaintextBytes < 0 {
		return 0, 0, errAegisPlaintextTooLarge
	}

	encryptedDataBytes = plaintextBytes + AegisTagBytes
	if encryptedDataBytes < plaintextBytes {
		return 0, 0, errAegisPlaintextTooLarge
	}

	frameBytes = roundUpToAegisAlignment(AegisHeaderBytes + encryptedDataBytes)
	if err := validateAegisFrameBytes(frameBytes); err != nil {
		return 0, 0, err
	}

	return frameBytes, encryptedDataBytes, nil
}

func roundUpToAegisAlignment(size int) int {
	return (size + (AegisAlignment - 1)) &^ (AegisAlignment - 1)
}

func validateAegisFrameBytes(frameBytes int) error {
	if frameBytes < AegisMinFrameBytes || frameBytes > AegisMaxFrameBytes {
		return errAegisFrameBounds
	}
	if frameBytes%AegisAlignment != 0 {
		return errAegisFrameAlignment
	}
	return nil
}

func pairingHash24(secret U128, service uint64) uint64 {
	var input [24]byte
	copy(input[:16], secret[:])
	binary.LittleEndian.PutUint64(input[16:], service)

	hashVector := gxhashPartialVector(input[:8], 8)
	var block [16]byte
	copy(block[:], input[8:])

	compressed := aesEncryptLast(
		hashVector,
		aesEncrypt(aesEncrypt(block, gxhashRoundKey0), gxhashRoundKey1),
	)

	state := aesEncrypt(compressed, gxhashSeedVector(AegisPairingHashSeed))
	state = aesEncrypt(state, gxhashRoundKey0)
	state = aesEncrypt(state, gxhashRoundKey1)
	state = aesEncryptLast(state, gxhashRoundKey2)
	return binary.LittleEndian.Uint64(state[:8])
}

func gxhashSeedVector(seed int64) [16]byte {
	var out [16]byte
	binary.LittleEndian.PutUint64(out[:8], uint64(seed))
	binary.LittleEndian.PutUint64(out[8:], uint64(seed))
	return out
}

func gxhashKeyBlock(offset int) [16]byte {
	keys := [...]uint32{
		0xF2784542, 0xB09D3E21, 0x89C222E5, 0xFC3BC28E,
		0x03FCE279, 0xCB6B2E9B, 0xB361DC58, 0x39132BD9,
		0xD0012E32, 0x689D2B7D, 0x5544B1B7, 0xC78B122B,
	}

	var out [16]byte
	for index := 0; index < 4; index += 1 {
		binary.LittleEndian.PutUint32(out[index*4:], keys[offset+index])
	}

	return out
}

func gxhashPartialVector(data []byte, length byte) [16]byte {
	var out [16]byte
	copy(out[:], data)
	for index := range out {
		out[index] += length
	}
	return out
}

func aesEncrypt(state [16]byte, key [16]byte) [16]byte {
	return addRoundKey(mixColumns(shiftRows(subBytes(state))), key)
}

func aesEncryptLast(state [16]byte, key [16]byte) [16]byte {
	return addRoundKey(shiftRows(subBytes(state)), key)
}

func subBytes(state [16]byte) [16]byte {
	var out [16]byte
	for index, value := range state {
		out[index] = aesSBox[value]
	}
	return out
}

func shiftRows(state [16]byte) [16]byte {
	var out [16]byte
	for row := 0; row < 4; row += 1 {
		for col := 0; col < 4; col += 1 {
			out[row+(4*col)] = state[row+(4*((col+row)&3))]
		}
	}
	return out
}

func mixColumns(state [16]byte) [16]byte {
	var out [16]byte
	for col := 0; col < 4; col += 1 {
		offset := col * 4
		s0 := state[offset]
		s1 := state[offset+1]
		s2 := state[offset+2]
		s3 := state[offset+3]
		out[offset] = aesMul2(s0) ^ aesMul3(s1) ^ s2 ^ s3
		out[offset+1] = s0 ^ aesMul2(s1) ^ aesMul3(s2) ^ s3
		out[offset+2] = s0 ^ s1 ^ aesMul2(s2) ^ aesMul3(s3)
		out[offset+3] = aesMul3(s0) ^ s1 ^ s2 ^ aesMul2(s3)
	}
	return out
}

func addRoundKey(state [16]byte, key [16]byte) [16]byte {
	var out [16]byte
	for index := range state {
		out[index] = state[index] ^ key[index]
	}
	return out
}

func aesMul2(value byte) byte {
	if (value & 0x80) == 0 {
		return value << 1
	}

	return (value << 1) ^ 0x1b
}

func aesMul3(value byte) byte {
	return aesMul2(value) ^ value
}

var aesSBox = [256]byte{
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
}
