// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0

package neuronhub

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
	"syscall"
)

const (
	SDKVersion          = "1.0.0"
	WireSeries          = "WIRE_V1"
	WireProtocolVersion = uint32(1)
	frameHeaderSize     = 8
	frameAlignment      = 16
)

var (
	containerParametersMagic = [8]byte{'P', 'R', 'D', 'P', 'A', 'R', '0', '1'}
	credentialBundleMagic    = [8]byte{'P', 'R', 'D', 'B', 'U', 'N', '0', '1'}
	credentialDeltaMagic     = [8]byte{'P', 'R', 'D', 'D', 'E', 'L', '0', '1'}
)

type U128 [16]byte

type IPAddress struct {
	Address [16]byte
	IsIPv6  bool
}

type IPPrefix struct {
	Address [16]byte
	CIDR    uint8
	IsIPv6  bool
}

type TlsIdentity struct {
	Name        string
	Generation  uint64
	NotBeforeMs int64
	NotAfterMs  int64
	CertPEM     string
	KeyPEM      string
	ChainPEM    string
	DNSSANs     []string
	IPSANs      []IPAddress
	Tags        []string
}

type ApiCredential struct {
	Name         string
	Provider     string
	Generation   uint64
	ExpiresAtMs  int64
	ActiveFromMs int64
	SunsetAtMs   int64
	Material     string
	Metadata     map[string]string
}

type CredentialBundle struct {
	TLSIdentities    []TlsIdentity
	APICredentials   []ApiCredential
	BundleGeneration uint64
}

type CredentialDelta struct {
	BundleGeneration uint64
	UpdatedTLS       []TlsIdentity
	RemovedTLSNames  []string
	UpdatedAPI       []ApiCredential
	RemovedAPINames  []string
	Reason           string
}

type AdvertisedPort struct {
	Service uint64
	Port    uint16
}

type AdvertisementPairing struct {
	Secret        U128
	Address       U128
	Service       uint64
	ApplicationID uint16
	Activate      bool
}

type SubscriptionPairing struct {
	Secret        U128
	Address       U128
	Service       uint64
	Port          uint16
	ApplicationID uint16
	Activate      bool
}

type ResourceDelta struct {
	LogicalCores uint16
	MemoryMB     uint32
	StorageMB    uint32
	IsDownscale  bool
	GraceSeconds uint32
}

type MetricPair struct {
	Key   uint64
	Value uint64
}

type MessageFrame struct {
	Topic   ContainerTopic
	Payload []byte
}

type FrameDecoder struct {
	buffer []byte
}

type ContainerParameters struct {
	UUID                  U128
	MemoryMB              uint32
	StorageMB             uint32
	LogicalCores          uint16
	NeuronFD              int32
	LowCPU                int32
	HighCPU               int32
	Advertises            []AdvertisedPort
	SubscriptionPairings  []SubscriptionPairing
	AdvertisementPairings []AdvertisementPairing
	Private6              IPPrefix
	JustCrashed           bool
	DatacenterUniqueTag   uint8
	Flags                 []uint64
	CredentialBundle      *CredentialBundle
}

type ContainerTopic uint16

const (
	ContainerTopicNone ContainerTopic = iota
	ContainerTopicPing
	ContainerTopicPong
	ContainerTopicStop
	ContainerTopicAdvertisementPairing
	ContainerTopicSubscriptionPairing
	ContainerTopicHealthy
	ContainerTopicMessage
	ContainerTopicResourceDelta
	ContainerTopicDatacenterUniqueTag
	ContainerTopicStatistics
	ContainerTopicResourceDeltaAck
	ContainerTopicCredentialsRefresh
)

type Dispatch interface {
	EndOfDynamicArgs(hub *NeuronHub)
	BeginShutdown(hub *NeuronHub)
	AdvertisementPairing(hub *NeuronHub, pairing AdvertisementPairing)
	SubscriptionPairing(hub *NeuronHub, pairing SubscriptionPairing)
	ResourceDelta(hub *NeuronHub, delta ResourceDelta)
	CredentialsRefresh(hub *NeuronHub, delta CredentialDelta)
	MessageFromProdigy(hub *NeuronHub, payload []byte)
}

type DispatchBase struct{}

func (DispatchBase) EndOfDynamicArgs(*NeuronHub)                           {}
func (DispatchBase) BeginShutdown(*NeuronHub)                              {}
func (DispatchBase) AdvertisementPairing(*NeuronHub, AdvertisementPairing) {}
func (DispatchBase) SubscriptionPairing(*NeuronHub, SubscriptionPairing)   {}
func (DispatchBase) ResourceDelta(*NeuronHub, ResourceDelta)               {}
func (DispatchBase) CredentialsRefresh(*NeuronHub, CredentialDelta)        {}
func (DispatchBase) MessageFromProdigy(*NeuronHub, []byte)                 {}

type NeuronHub struct {
	FD                        int
	file                      *os.File
	Dispatch                  Dispatch
	Parameters                ContainerParameters
	autoResourceDeltaAck      *bool
	autoCredentialsRefreshAck bool
	shutdownRequested         bool
}

func NewNeuronHub(dispatch Dispatch, args []string) (*NeuronHub, error) {
	if args == nil {
		args = os.Args
	}

	params, err := LoadContainerParametersFromEnvOrArgs(args)
	if err != nil {
		return nil, err
	}

	return NewNeuronHubFromParameters(dispatch, params)
}

func NewEventLoopNeuronHub(dispatch Dispatch, args []string) (*NeuronHub, error) {
	return NewBorrowedNeuronHub(dispatch, args)
}

func NewBorrowedNeuronHub(dispatch Dispatch, args []string) (*NeuronHub, error) {
	if args == nil {
		args = os.Args
	}

	params, err := LoadContainerParametersFromEnvOrArgs(args)
	if err != nil {
		return nil, err
	}

	return NewBorrowedNeuronHubFromParameters(dispatch, params)
}

func NewNeuronHubFromParameters(dispatch Dispatch, params ContainerParameters) (*NeuronHub, error) {
	if dispatch == nil {
		return nil, errors.New("prodigy: dispatch is nil")
	}
	if params.NeuronFD < 0 {
		return nil, fmt.Errorf("prodigy: invalid neuron fd %d", params.NeuronFD)
	}
	if err := syscall.SetNonblock(int(params.NeuronFD), false); err != nil {
		return nil, fmt.Errorf("prodigy: set blocking on neuron fd %d: %w", params.NeuronFD, err)
	}

	file := os.NewFile(uintptr(params.NeuronFD), "prodigy-neuron")
	if file == nil {
		return nil, fmt.Errorf("prodigy: failed to wrap neuron fd %d", params.NeuronFD)
	}

	return &NeuronHub{
		FD:         int(params.NeuronFD),
		file:       file,
		Dispatch:   dispatch,
		Parameters: params,
	}, nil
}

func NewEventLoopNeuronHubFromParameters(dispatch Dispatch, params ContainerParameters) (*NeuronHub, error) {
	return NewBorrowedNeuronHubFromParameters(dispatch, params)
}

func NewBorrowedNeuronHubFromParameters(dispatch Dispatch, params ContainerParameters) (*NeuronHub, error) {
	if dispatch == nil {
		return nil, errors.New("prodigy: dispatch is nil")
	}

	return &NeuronHub{
		FD:         int(params.NeuronFD),
		file:       nil,
		Dispatch:   dispatch,
		Parameters: params,
	}, nil
}

func (value U128) IPv6Addr() (netip.Addr, error) {
	addr, ok := netip.AddrFromSlice(value[:])
	if !ok || !addr.Is6() || addr.IsUnspecified() {
		return netip.Addr{}, errors.New("prodigy: invalid IPv6 address")
	}

	return addr, nil
}

func (pairing SubscriptionPairing) Target() (netip.AddrPort, error) {
	addr, err := pairing.Address.IPv6Addr()
	if err != nil {
		return netip.AddrPort{}, err
	}

	return netip.AddrPortFrom(addr, pairing.Port), nil
}

func (pairing AdvertisementPairing) PeerAddr() (netip.Addr, error) {
	return pairing.Address.IPv6Addr()
}

func (hub *NeuronHub) WithResourceDeltaAck(accepted bool) *NeuronHub {
	if hub == nil {
		return nil
	}

	hub.autoResourceDeltaAck = &accepted
	return hub
}

func (hub *NeuronHub) WithCredentialsRefreshAck() *NeuronHub {
	if hub == nil {
		return nil
	}

	hub.autoCredentialsRefreshAck = true
	return hub
}

func (hub *NeuronHub) WithAutoAcks() *NeuronHub {
	if hub == nil {
		return nil
	}

	return hub.WithResourceDeltaAck(true).WithCredentialsRefreshAck()
}

func (hub *NeuronHub) ShutdownRequested() bool {
	if hub == nil {
		return false
	}

	return hub.shutdownRequested
}

func (hub *NeuronHub) Close() error {
	if hub == nil || hub.file == nil {
		return nil
	}

	err := hub.file.Close()
	hub.file = nil
	return err
}

func (hub *NeuronHub) Run() error {
	for {
		if err := hub.RunOnce(); err != nil {
			return err
		}
	}
}

func (hub *NeuronHub) RunOnce() error {
	if hub == nil || hub.file == nil {
		return errors.New("prodigy: hub is not initialized")
	}

	frame, err := ReadMessageFrame(hub.file)
	if err != nil {
		return err
	}

	outbound, err := hub.HandleFrame(frame)
	if err != nil {
		return err
	}
	for _, response := range outbound {
		if err := hub.SendFrame(response); err != nil {
			return err
		}
	}
	return nil
}

func (hub *NeuronHub) HandleFrame(frame MessageFrame) ([]MessageFrame, error) {
	var outbound []MessageFrame

	switch frame.Topic {
	case ContainerTopicNone:
		hub.Dispatch.EndOfDynamicArgs(hub)
		return outbound, nil
	case ContainerTopicPing:
		return []MessageFrame{{Topic: ContainerTopicPing}}, nil
	case ContainerTopicPong:
		return outbound, nil
	case ContainerTopicStop:
		hub.shutdownRequested = true
		hub.Dispatch.BeginShutdown(hub)
		return outbound, nil
	case ContainerTopicAdvertisementPairing:
		pairing, err := decodeAdvertisementPairingPayload(frame.Payload)
		if err != nil {
			return nil, err
		}
		hub.Dispatch.AdvertisementPairing(hub, pairing)
		return outbound, nil
	case ContainerTopicSubscriptionPairing:
		pairing, err := decodeSubscriptionPairingPayload(frame.Payload)
		if err != nil {
			return nil, err
		}
		hub.Dispatch.SubscriptionPairing(hub, pairing)
		return outbound, nil
	case ContainerTopicHealthy:
		return outbound, nil
	case ContainerTopicMessage:
		hub.Dispatch.MessageFromProdigy(hub, cloneBytes(frame.Payload))
		return outbound, nil
	case ContainerTopicResourceDelta:
		delta, err := decodeResourceDeltaPayload(frame.Payload)
		if err != nil {
			return nil, err
		}
		hub.Dispatch.ResourceDelta(hub, delta)
		if hub.autoResourceDeltaAck != nil {
			value := byte(0)
			if *hub.autoResourceDeltaAck {
				value = 1
			}
			outbound = append(outbound, MessageFrame{
				Topic:   ContainerTopicResourceDeltaAck,
				Payload: []byte{value},
			})
		}
		return outbound, nil
	case ContainerTopicDatacenterUniqueTag:
		if len(frame.Payload) != 1 {
			return nil, fmt.Errorf("prodigy: datacenterUniqueTag payload length %d", len(frame.Payload))
		}
		hub.Parameters.DatacenterUniqueTag = frame.Payload[0]
		return outbound, nil
	case ContainerTopicStatistics:
		return outbound, nil
	case ContainerTopicResourceDeltaAck:
		return outbound, nil
	case ContainerTopicCredentialsRefresh:
		if len(frame.Payload) == 0 {
			return outbound, nil
		}
		delta, err := DecodeCredentialDelta(frame.Payload)
		if err != nil {
			return nil, err
		}
		hub.Dispatch.CredentialsRefresh(hub, delta)
		if hub.autoCredentialsRefreshAck {
			outbound = append(outbound, MessageFrame{
				Topic:   ContainerTopicCredentialsRefresh,
				Payload: nil,
			})
		}
		return outbound, nil
	default:
		return nil, fmt.Errorf("prodigy: unsupported topic %d", frame.Topic)
	}
}

func (hub *NeuronHub) SignalReady() error {
	return hub.sendEmpty(ContainerTopicHealthy)
}

func (hub *NeuronHub) Healthy() error {
	return hub.SignalReady()
}

func (hub *NeuronHub) PublishStatistic(metric MetricPair) error {
	return hub.PublishStatistics([]MetricPair{metric})
}

func (hub *NeuronHub) PublishStatistics(metrics []MetricPair) error {
	return hub.sendFrame(ContainerTopicStatistics, encodeMetricPairs(metrics))
}

func (hub *NeuronHub) Statistics(metrics []MetricPair) error {
	return hub.PublishStatistics(metrics)
}

func (hub *NeuronHub) AcknowledgeResourceDelta(accepted bool) error {
	value := byte(0)
	if accepted {
		value = 1
	}
	return hub.sendFrame(ContainerTopicResourceDeltaAck, []byte{value})
}

func (hub *NeuronHub) ResourceDeltaAck(accepted bool) error {
	return hub.AcknowledgeResourceDelta(accepted)
}

func (hub *NeuronHub) AcknowledgeCredentialsRefresh() error {
	return hub.sendEmpty(ContainerTopicCredentialsRefresh)
}

func (hub *NeuronHub) CredentialsRefreshAck() error {
	return hub.AcknowledgeCredentialsRefresh()
}

func (hub *NeuronHub) sendEmpty(topic ContainerTopic) error {
	return hub.sendFrame(topic, nil)
}

func (hub *NeuronHub) SendFrame(frame MessageFrame) error {
	if hub == nil || hub.file == nil {
		return errors.New("prodigy: hub has no owned transport")
	}
	return hub.sendFrame(frame.Topic, frame.Payload)
}

func (hub *NeuronHub) sendFrame(topic ContainerTopic, payload []byte) error {
	if hub == nil || hub.file == nil {
		return errors.New("prodigy: hub is not initialized")
	}

	frame := BuildMessageFrame(topic, payload)
	return writeAll(hub.file, frame)
}

func LoadContainerParametersFromFD(fd int) (ContainerParameters, error) {
	data, err := readAllFromFD(fd)
	if err != nil {
		return ContainerParameters{}, err
	}
	return DecodeContainerParameters(data)
}

func LoadContainerParametersFromEnv() (ContainerParameters, error) {
	fdText := os.Getenv("PRODIGY_PARAMS_FD")
	if fdText == "" {
		return ContainerParameters{}, errors.New("prodigy: missing PRODIGY_PARAMS_FD")
	}

	fd, err := strconv.Atoi(fdText)
	if err != nil {
		return ContainerParameters{}, fmt.Errorf("prodigy: invalid PRODIGY_PARAMS_FD %q: %w", fdText, err)
	}

	return LoadContainerParametersFromFD(fd)
}

func LoadContainerParametersFromEnvOrArgs(args []string) (ContainerParameters, error) {
	if fdText := os.Getenv("PRODIGY_PARAMS_FD"); fdText != "" {
		return LoadContainerParametersFromEnv()
	}

	if len(args) > 1 {
		return DecodeContainerParameters([]byte(args[1]))
	}

	return ContainerParameters{}, errors.New("prodigy: missing startup parameters")
}

func DecodeContainerParameters(data []byte) (ContainerParameters, error) {
	decoder := newDecoder(data)
	if err := decoder.expectMagic(containerParametersMagic); err != nil {
		return ContainerParameters{}, err
	}

	var params ContainerParameters
	var err error
	if params.UUID, err = decoder.u128(); err != nil {
		return ContainerParameters{}, err
	}
	if params.MemoryMB, err = decoder.u32(); err != nil {
		return ContainerParameters{}, err
	}
	if params.StorageMB, err = decoder.u32(); err != nil {
		return ContainerParameters{}, err
	}
	if params.LogicalCores, err = decoder.u16(); err != nil {
		return ContainerParameters{}, err
	}
	if params.NeuronFD, err = decoder.i32(); err != nil {
		return ContainerParameters{}, err
	}
	if params.LowCPU, err = decoder.i32(); err != nil {
		return ContainerParameters{}, err
	}
	if params.HighCPU, err = decoder.i32(); err != nil {
		return ContainerParameters{}, err
	}

	advertiseCount, err := decoder.u32()
	if err != nil {
		return ContainerParameters{}, err
	}
	params.Advertises = make([]AdvertisedPort, int(advertiseCount))
	for index := range params.Advertises {
		if params.Advertises[index].Service, err = decoder.u64(); err != nil {
			return ContainerParameters{}, err
		}
		if params.Advertises[index].Port, err = decoder.u16(); err != nil {
			return ContainerParameters{}, err
		}
	}

	subscriptionCount, err := decoder.u32()
	if err != nil {
		return ContainerParameters{}, err
	}
	params.SubscriptionPairings = make([]SubscriptionPairing, int(subscriptionCount))
	for index := range params.SubscriptionPairings {
		if params.SubscriptionPairings[index].Secret, err = decoder.u128(); err != nil {
			return ContainerParameters{}, err
		}
		if params.SubscriptionPairings[index].Address, err = decoder.u128(); err != nil {
			return ContainerParameters{}, err
		}
		if params.SubscriptionPairings[index].Service, err = decoder.u64(); err != nil {
			return ContainerParameters{}, err
		}
		if params.SubscriptionPairings[index].Port, err = decoder.u16(); err != nil {
			return ContainerParameters{}, err
		}
		params.SubscriptionPairings[index].ApplicationID = uint16(params.SubscriptionPairings[index].Service >> 48)
		params.SubscriptionPairings[index].Activate = true
	}

	advertisementCount, err := decoder.u32()
	if err != nil {
		return ContainerParameters{}, err
	}
	params.AdvertisementPairings = make([]AdvertisementPairing, int(advertisementCount))
	for index := range params.AdvertisementPairings {
		if params.AdvertisementPairings[index].Secret, err = decoder.u128(); err != nil {
			return ContainerParameters{}, err
		}
		if params.AdvertisementPairings[index].Address, err = decoder.u128(); err != nil {
			return ContainerParameters{}, err
		}
		if params.AdvertisementPairings[index].Service, err = decoder.u64(); err != nil {
			return ContainerParameters{}, err
		}
		params.AdvertisementPairings[index].ApplicationID = uint16(params.AdvertisementPairings[index].Service >> 48)
		params.AdvertisementPairings[index].Activate = true
	}

	if params.Private6, err = decoder.ipPrefix(); err != nil {
		return ContainerParameters{}, err
	}
	if params.JustCrashed, err = decoder.boolean(); err != nil {
		return ContainerParameters{}, err
	}
	if params.DatacenterUniqueTag, err = decoder.u8(); err != nil {
		return ContainerParameters{}, err
	}

	flagCount, err := decoder.u32()
	if err != nil {
		return ContainerParameters{}, err
	}
	params.Flags = make([]uint64, int(flagCount))
	for index := range params.Flags {
		if params.Flags[index], err = decoder.u64(); err != nil {
			return ContainerParameters{}, err
		}
	}

	hasBundle, err := decoder.boolean()
	if err != nil {
		return ContainerParameters{}, err
	}
	if hasBundle {
		bundle, err := decodeCredentialBundleFromDecoder(decoder)
		if err != nil {
			return ContainerParameters{}, err
		}
		params.CredentialBundle = &bundle
	}

	if !decoder.done() {
		return ContainerParameters{}, errors.New("prodigy: trailing bytes in container parameters")
	}

	return params, nil
}

func DecodeCredentialBundle(data []byte) (CredentialBundle, error) {
	decoder := newDecoder(data)
	if err := decoder.expectMagic(credentialBundleMagic); err != nil {
		return CredentialBundle{}, err
	}

	bundle, err := decodeCredentialBundleFromDecoder(decoder)
	if err != nil {
		return CredentialBundle{}, err
	}
	if !decoder.done() {
		return CredentialBundle{}, errors.New("prodigy: trailing bytes in credential bundle")
	}
	return bundle, nil
}

func DecodeCredentialDelta(data []byte) (CredentialDelta, error) {
	decoder := newDecoder(data)
	if err := decoder.expectMagic(credentialDeltaMagic); err != nil {
		return CredentialDelta{}, err
	}

	delta, err := decodeCredentialDeltaFromDecoder(decoder)
	if err != nil {
		return CredentialDelta{}, err
	}
	if !decoder.done() {
		return CredentialDelta{}, errors.New("prodigy: trailing bytes in credential delta")
	}
	return delta, nil
}

func decodeResourceDeltaPayload(payload []byte) (ResourceDelta, error) {
	decoder := newDecoder(payload)
	var delta ResourceDelta
	var err error
	if delta.LogicalCores, err = decoder.u16(); err != nil {
		return ResourceDelta{}, err
	}
	if delta.MemoryMB, err = decoder.u32(); err != nil {
		return ResourceDelta{}, err
	}
	if delta.StorageMB, err = decoder.u32(); err != nil {
		return ResourceDelta{}, err
	}
	if delta.IsDownscale, err = decoder.boolean(); err != nil {
		return ResourceDelta{}, err
	}
	if delta.GraceSeconds, err = decoder.u32(); err != nil {
		return ResourceDelta{}, err
	}
	if !decoder.done() {
		return ResourceDelta{}, errors.New("prodigy: trailing bytes in resource delta")
	}
	return delta, nil
}

func decodeAdvertisementPairingPayload(payload []byte) (AdvertisementPairing, error) {
	decoder := newDecoder(payload)
	var pairing AdvertisementPairing
	var err error
	if pairing.Secret, err = decoder.u128(); err != nil {
		return AdvertisementPairing{}, err
	}
	if pairing.Address, err = decoder.u128(); err != nil {
		return AdvertisementPairing{}, err
	}
	if pairing.Service, err = decoder.u64(); err != nil {
		return AdvertisementPairing{}, err
	}
	if pairing.ApplicationID, err = decoder.u16(); err != nil {
		return AdvertisementPairing{}, err
	}
	if pairing.Activate, err = decoder.boolean(); err != nil {
		return AdvertisementPairing{}, err
	}
	if !decoder.done() {
		return AdvertisementPairing{}, errors.New("prodigy: trailing bytes in advertisement pairing")
	}
	return pairing, nil
}

func decodeSubscriptionPairingPayload(payload []byte) (SubscriptionPairing, error) {
	decoder := newDecoder(payload)
	var pairing SubscriptionPairing
	var err error
	if pairing.Secret, err = decoder.u128(); err != nil {
		return SubscriptionPairing{}, err
	}
	if pairing.Address, err = decoder.u128(); err != nil {
		return SubscriptionPairing{}, err
	}
	if pairing.Service, err = decoder.u64(); err != nil {
		return SubscriptionPairing{}, err
	}
	if pairing.Port, err = decoder.u16(); err != nil {
		return SubscriptionPairing{}, err
	}
	if pairing.ApplicationID, err = decoder.u16(); err != nil {
		return SubscriptionPairing{}, err
	}
	if pairing.Activate, err = decoder.boolean(); err != nil {
		return SubscriptionPairing{}, err
	}
	if !decoder.done() {
		return SubscriptionPairing{}, errors.New("prodigy: trailing bytes in subscription pairing")
	}
	return pairing, nil
}

func decodeCredentialBundleFromDecoder(decoder *byteDecoder) (CredentialBundle, error) {
	tlsCount, err := decoder.u32()
	if err != nil {
		return CredentialBundle{}, err
	}
	bundle := CredentialBundle{
		TLSIdentities:  make([]TlsIdentity, int(tlsCount)),
		APICredentials: nil,
	}
	for index := range bundle.TLSIdentities {
		if bundle.TLSIdentities[index], err = decoder.tlsIdentity(); err != nil {
			return CredentialBundle{}, err
		}
	}

	apiCount, err := decoder.u32()
	if err != nil {
		return CredentialBundle{}, err
	}
	bundle.APICredentials = make([]ApiCredential, int(apiCount))
	for index := range bundle.APICredentials {
		if bundle.APICredentials[index], err = decoder.apiCredential(); err != nil {
			return CredentialBundle{}, err
		}
	}

	if bundle.BundleGeneration, err = decoder.u64(); err != nil {
		return CredentialBundle{}, err
	}

	return bundle, nil
}

func decodeCredentialDeltaFromDecoder(decoder *byteDecoder) (CredentialDelta, error) {
	var delta CredentialDelta
	var err error
	if delta.BundleGeneration, err = decoder.u64(); err != nil {
		return CredentialDelta{}, err
	}

	updatedTLSCount, err := decoder.u32()
	if err != nil {
		return CredentialDelta{}, err
	}
	delta.UpdatedTLS = make([]TlsIdentity, int(updatedTLSCount))
	for index := range delta.UpdatedTLS {
		if delta.UpdatedTLS[index], err = decoder.tlsIdentity(); err != nil {
			return CredentialDelta{}, err
		}
	}

	if delta.RemovedTLSNames, err = decoder.stringArray(); err != nil {
		return CredentialDelta{}, err
	}

	updatedAPICount, err := decoder.u32()
	if err != nil {
		return CredentialDelta{}, err
	}
	delta.UpdatedAPI = make([]ApiCredential, int(updatedAPICount))
	for index := range delta.UpdatedAPI {
		if delta.UpdatedAPI[index], err = decoder.apiCredential(); err != nil {
			return CredentialDelta{}, err
		}
	}

	if delta.RemovedAPINames, err = decoder.stringArray(); err != nil {
		return CredentialDelta{}, err
	}
	if delta.Reason, err = decoder.string(); err != nil {
		return CredentialDelta{}, err
	}
	return delta, nil
}

func BuildMessageFrame(topic ContainerTopic, payload []byte) []byte {
	total := frameHeaderSize + len(payload)
	padding := (frameAlignment - (total % frameAlignment)) % frameAlignment
	frame := make([]byte, total+padding)

	binary.LittleEndian.PutUint32(frame[0:4], uint32(len(frame)))
	binary.LittleEndian.PutUint16(frame[4:6], uint16(topic))
	frame[6] = byte(padding)
	frame[7] = frameHeaderSize
	copy(frame[8:], payload)
	return frame
}

func BuildReadyFrame() []byte {
	return BuildMessageFrame(ContainerTopicHealthy, nil)
}

func BuildStatisticsFrame(metrics []MetricPair) []byte {
	return BuildMessageFrame(ContainerTopicStatistics, encodeMetricPairs(metrics))
}

func BuildResourceDeltaAckFrame(accepted bool) []byte {
	value := byte(0)
	if accepted {
		value = 1
	}
	return BuildMessageFrame(ContainerTopicResourceDeltaAck, []byte{value})
}

func BuildCredentialsRefreshAckFrame() []byte {
	return BuildMessageFrame(ContainerTopicCredentialsRefresh, nil)
}

func ParseMessageFrame(data []byte) (MessageFrame, error) {
	if len(data) < frameHeaderSize {
		return MessageFrame{}, io.ErrUnexpectedEOF
	}

	size := binary.LittleEndian.Uint32(data[0:4])
	topic := binary.LittleEndian.Uint16(data[4:6])
	padding := int(data[6])
	headerSize := int(data[7])

	if headerSize != frameHeaderSize {
		return MessageFrame{}, fmt.Errorf("prodigy: unexpected header size %d", headerSize)
	}
	if size < frameHeaderSize {
		return MessageFrame{}, fmt.Errorf("prodigy: invalid frame size %d", size)
	}
	if size%frameAlignment != 0 {
		return MessageFrame{}, fmt.Errorf("prodigy: frame size %d is not %d-byte aligned", size, frameAlignment)
	}
	if int(size) != len(data) {
		return MessageFrame{}, fmt.Errorf("prodigy: frame size %d does not match buffer length %d", size, len(data))
	}

	bodyLength := int(size) - frameHeaderSize
	if padding > bodyLength {
		return MessageFrame{}, fmt.Errorf("prodigy: invalid frame padding %d for body %d", padding, bodyLength)
	}

	payloadLength := bodyLength - padding
	payload := make([]byte, payloadLength)
	copy(payload, data[frameHeaderSize:frameHeaderSize+payloadLength])

	return MessageFrame{
		Topic:   ContainerTopic(topic),
		Payload: payload,
	}, nil
}

func (decoder *FrameDecoder) Feed(data []byte) ([]MessageFrame, error) {
	decoder.buffer = append(decoder.buffer, data...)
	frames := make([]MessageFrame, 0)
	for {
		frame, consumed, err := tryExtractFrame(decoder.buffer)
		if err != nil {
			return nil, err
		}
		if consumed == 0 {
			return frames, nil
		}
		frames = append(frames, frame)
		decoder.buffer = decoder.buffer[consumed:]
	}
}

func ReadMessageFrame(reader io.Reader) (MessageFrame, error) {
	header := make([]byte, frameHeaderSize)
	if _, err := io.ReadFull(reader, header); err != nil {
		return MessageFrame{}, err
	}

	size := binary.LittleEndian.Uint32(header[0:4])
	padding := int(header[6])
	headerSize := int(header[7])

	if headerSize != frameHeaderSize {
		return MessageFrame{}, fmt.Errorf("prodigy: unexpected header size %d", headerSize)
	}
	if size < frameHeaderSize {
		return MessageFrame{}, fmt.Errorf("prodigy: invalid frame size %d", size)
	}
	if size%frameAlignment != 0 {
		return MessageFrame{}, fmt.Errorf("prodigy: frame size %d is not %d-byte aligned", size, frameAlignment)
	}

	bodyLength := int(size) - frameHeaderSize
	if padding > bodyLength {
		return MessageFrame{}, fmt.Errorf("prodigy: invalid frame padding %d for body %d", padding, bodyLength)
	}

	body := make([]byte, bodyLength)
	if _, err := io.ReadFull(reader, body); err != nil {
		return MessageFrame{}, err
	}

	frameData := make([]byte, frameHeaderSize+len(body))
	copy(frameData[:frameHeaderSize], header)
	copy(frameData[frameHeaderSize:], body)
	return ParseMessageFrame(frameData)
}

func encodeMetricPairs(metrics []MetricPair) []byte {
	payload := make([]byte, len(metrics)*16)
	offset := 0
	for _, metric := range metrics {
		binary.LittleEndian.PutUint64(payload[offset:offset+8], metric.Key)
		binary.LittleEndian.PutUint64(payload[offset+8:offset+16], metric.Value)
		offset += 16
	}

	return payload
}

func tryExtractFrame(data []byte) (MessageFrame, int, error) {
	if len(data) < frameHeaderSize {
		return MessageFrame{}, 0, nil
	}

	size := binary.LittleEndian.Uint32(data[0:4])
	headerSize := int(data[7])
	if headerSize != frameHeaderSize {
		return MessageFrame{}, 0, fmt.Errorf("prodigy: unexpected header size %d", headerSize)
	}
	if size < frameHeaderSize {
		return MessageFrame{}, 0, fmt.Errorf("prodigy: invalid frame size %d", size)
	}
	if size%frameAlignment != 0 {
		return MessageFrame{}, 0, fmt.Errorf("prodigy: frame size %d is not %d-byte aligned", size, frameAlignment)
	}
	if int(size) > len(data) {
		return MessageFrame{}, 0, nil
	}

	frame, err := ParseMessageFrame(data[:size])
	if err != nil {
		return MessageFrame{}, 0, err
	}
	return frame, int(size), nil
}

func readAllFromFD(fd int) ([]byte, error) {
	if fd < 0 {
		return nil, fmt.Errorf("prodigy: invalid fd %d", fd)
	}

	duplicateFD, err := syscall.Dup(fd)
	if err != nil {
		return nil, fmt.Errorf("prodigy: dup fd %d: %w", fd, err)
	}

	file := os.NewFile(uintptr(duplicateFD), "prodigy-params")
	if file == nil {
		_ = syscall.Close(duplicateFD)
		return nil, fmt.Errorf("prodigy: failed to open fd %d", fd)
	}
	defer file.Close()

	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("prodigy: seek fd %d: %w", fd, err)
	}

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("prodigy: read fd %d: %w", fd, err)
	}
	return data, nil
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		count, err := writer.Write(data)
		if err != nil {
			return err
		}
		if count == 0 {
			return io.ErrShortWrite
		}
		data = data[count:]
	}
	return nil
}

func cloneBytes(input []byte) []byte {
	if len(input) == 0 {
		return nil
	}
	output := make([]byte, len(input))
	copy(output, input)
	return output
}

type byteDecoder struct {
	data []byte
	pos  int
}

func newDecoder(data []byte) *byteDecoder {
	return &byteDecoder{data: data}
}

func (decoder *byteDecoder) done() bool {
	return decoder.pos == len(decoder.data)
}

func (decoder *byteDecoder) expectMagic(expected [8]byte) error {
	bytes, err := decoder.bytes(len(expected))
	if err != nil {
		return err
	}
	if string(bytes) != string(expected[:]) {
		return fmt.Errorf("prodigy: magic mismatch %q", string(bytes))
	}
	return nil
}

func (decoder *byteDecoder) bytes(count int) ([]byte, error) {
	if count < 0 || decoder.pos+count > len(decoder.data) {
		return nil, io.ErrUnexpectedEOF
	}
	start := decoder.pos
	decoder.pos += count
	return decoder.data[start:decoder.pos], nil
}

func (decoder *byteDecoder) u8() (uint8, error) {
	bytes, err := decoder.bytes(1)
	if err != nil {
		return 0, err
	}
	return bytes[0], nil
}

func (decoder *byteDecoder) boolean() (bool, error) {
	value, err := decoder.u8()
	if err != nil {
		return false, err
	}
	switch value {
	case 0:
		return false, nil
	case 1:
		return true, nil
	default:
		return false, fmt.Errorf("prodigy: invalid bool value %d", value)
	}
}

func (decoder *byteDecoder) u16() (uint16, error) {
	bytes, err := decoder.bytes(2)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint16(bytes), nil
}

func (decoder *byteDecoder) u32() (uint32, error) {
	bytes, err := decoder.bytes(4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(bytes), nil
}

func (decoder *byteDecoder) i32() (int32, error) {
	value, err := decoder.u32()
	return int32(value), err
}

func (decoder *byteDecoder) u64() (uint64, error) {
	bytes, err := decoder.bytes(8)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(bytes), nil
}

func (decoder *byteDecoder) i64() (int64, error) {
	value, err := decoder.u64()
	return int64(value), err
}

func (decoder *byteDecoder) u128() (U128, error) {
	bytes, err := decoder.bytes(16)
	if err != nil {
		return U128{}, err
	}
	var value U128
	copy(value[:], bytes)
	return value, nil
}

func (decoder *byteDecoder) sizedBytes() ([]byte, error) {
	length, err := decoder.u32()
	if err != nil {
		return nil, err
	}
	return decoder.bytes(int(length))
}

func (decoder *byteDecoder) string() (string, error) {
	bytes, err := decoder.sizedBytes()
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

func (decoder *byteDecoder) stringArray() ([]string, error) {
	count, err := decoder.u32()
	if err != nil {
		return nil, err
	}
	values := make([]string, int(count))
	for index := range values {
		if values[index], err = decoder.string(); err != nil {
			return nil, err
		}
	}
	return values, nil
}

func (decoder *byteDecoder) ipAddress() (IPAddress, error) {
	raw, err := decoder.bytes(16)
	if err != nil {
		return IPAddress{}, err
	}
	isIPv6, err := decoder.boolean()
	if err != nil {
		return IPAddress{}, err
	}

	var address IPAddress
	copy(address.Address[:], raw)
	address.IsIPv6 = isIPv6
	return address, nil
}

func (decoder *byteDecoder) ipPrefix() (IPPrefix, error) {
	address, err := decoder.ipAddress()
	if err != nil {
		return IPPrefix{}, err
	}
	cidr, err := decoder.u8()
	if err != nil {
		return IPPrefix{}, err
	}

	var prefix IPPrefix
	prefix.Address = address.Address
	prefix.CIDR = cidr
	prefix.IsIPv6 = address.IsIPv6
	return prefix, nil
}

func (decoder *byteDecoder) ipAddressArray() ([]IPAddress, error) {
	count, err := decoder.u32()
	if err != nil {
		return nil, err
	}
	values := make([]IPAddress, int(count))
	for index := range values {
		if values[index], err = decoder.ipAddress(); err != nil {
			return nil, err
		}
	}
	return values, nil
}

func (decoder *byteDecoder) tlsIdentity() (TlsIdentity, error) {
	var identity TlsIdentity
	var err error
	if identity.Name, err = decoder.string(); err != nil {
		return TlsIdentity{}, err
	}
	if identity.Generation, err = decoder.u64(); err != nil {
		return TlsIdentity{}, err
	}
	if identity.NotBeforeMs, err = decoder.i64(); err != nil {
		return TlsIdentity{}, err
	}
	if identity.NotAfterMs, err = decoder.i64(); err != nil {
		return TlsIdentity{}, err
	}
	if identity.CertPEM, err = decoder.string(); err != nil {
		return TlsIdentity{}, err
	}
	if identity.KeyPEM, err = decoder.string(); err != nil {
		return TlsIdentity{}, err
	}
	if identity.ChainPEM, err = decoder.string(); err != nil {
		return TlsIdentity{}, err
	}
	if identity.DNSSANs, err = decoder.stringArray(); err != nil {
		return TlsIdentity{}, err
	}
	if identity.IPSANs, err = decoder.ipAddressArray(); err != nil {
		return TlsIdentity{}, err
	}
	if identity.Tags, err = decoder.stringArray(); err != nil {
		return TlsIdentity{}, err
	}
	return identity, nil
}

func (decoder *byteDecoder) apiCredential() (ApiCredential, error) {
	var credential ApiCredential
	var err error
	if credential.Name, err = decoder.string(); err != nil {
		return ApiCredential{}, err
	}
	if credential.Provider, err = decoder.string(); err != nil {
		return ApiCredential{}, err
	}
	if credential.Generation, err = decoder.u64(); err != nil {
		return ApiCredential{}, err
	}
	if credential.ExpiresAtMs, err = decoder.i64(); err != nil {
		return ApiCredential{}, err
	}
	if credential.ActiveFromMs, err = decoder.i64(); err != nil {
		return ApiCredential{}, err
	}
	if credential.SunsetAtMs, err = decoder.i64(); err != nil {
		return ApiCredential{}, err
	}
	if credential.Material, err = decoder.string(); err != nil {
		return ApiCredential{}, err
	}

	metadataCount, err := decoder.u32()
	if err != nil {
		return ApiCredential{}, err
	}
	credential.Metadata = make(map[string]string, int(metadataCount))
	for index := uint32(0); index < metadataCount; index += 1 {
		key, err := decoder.string()
		if err != nil {
			return ApiCredential{}, err
		}
		value, err := decoder.string()
		if err != nil {
			return ApiCredential{}, err
		}
		credential.Metadata[key] = value
	}

	return credential, nil
}
