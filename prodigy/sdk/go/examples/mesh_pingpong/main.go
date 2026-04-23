// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	neuronhub "github.com/victorstewart/prodigy/sdk/go"
)

const (
	meshPingPayload          = "ping"
	meshPongPayload          = "pong"
	meshTimeout              = 5 * time.Second
	statDatacenterTag        = uint64(0x6d6573680001)
	statStartupPairings      = uint64(0x6d6573680002)
	statAdvertisementPairing = uint64(0x6d6573680010)
	statSubscriptionPairing  = uint64(0x6d6573680011)
	statResourceLogicalCores = uint64(0x6d6573680020)
	statResourceMemoryMB     = uint64(0x6d6573680021)
	statResourceStorageMB    = uint64(0x6d6573680022)
	statResourceDownscale    = uint64(0x6d6573680023)
	statResourceGraceSeconds = uint64(0x6d6573680024)
	statCredentialGeneration = uint64(0x6d6573680030)
	statCredentialTLSUpdates = uint64(0x6d6573680031)
	statCredentialAPIUpdates = uint64(0x6d6573680032)
	statCredentialRemovals   = uint64(0x6d6573680033)
)

type role uint8

const (
	roleAdvertiser role = iota + 1
	roleSubscriber
)

type eventKind uint8

const (
	eventAdvertisementPairing eventKind = iota + 1
	eventSubscriptionPairing
	eventSubscriberPong
)

type meshEvent struct {
	Kind          eventKind
	Advertisement neuronhub.AdvertisementPairing
	Subscription  neuronhub.SubscriptionPairing
}

type meshDispatch struct {
	neuronhub.DispatchBase
	sink neuronhub.ReactorSink[meshEvent]
}

func (dispatch *meshDispatch) EndOfDynamicArgs(hub *neuronhub.NeuronHub) {
	params := hub.Parameters
	dispatch.publishStats(hub,
		metric(statDatacenterTag, uint64(params.DatacenterUniqueTag)),
		metric(statStartupPairings, uint64(len(params.AdvertisementPairings)+len(params.SubscriptionPairings))),
	)
}

func (dispatch *meshDispatch) AdvertisementPairing(hub *neuronhub.NeuronHub, pairing neuronhub.AdvertisementPairing) {
	dispatch.publishStats(
		hub,
		metric(statDatacenterTag, uint64(hub.Parameters.DatacenterUniqueTag)),
		metric(statAdvertisementPairing, boolValue(pairing.Activate)),
	)
	dispatch.sink.Emit(meshEvent{
		Kind:          eventAdvertisementPairing,
		Advertisement: pairing,
	})
}

func (dispatch *meshDispatch) SubscriptionPairing(hub *neuronhub.NeuronHub, pairing neuronhub.SubscriptionPairing) {
	dispatch.publishStats(
		hub,
		metric(statDatacenterTag, uint64(hub.Parameters.DatacenterUniqueTag)),
		metric(statSubscriptionPairing, boolValue(pairing.Activate)),
	)
	dispatch.sink.Emit(meshEvent{
		Kind:         eventSubscriptionPairing,
		Subscription: pairing,
	})
}

func (dispatch *meshDispatch) ResourceDelta(hub *neuronhub.NeuronHub, delta neuronhub.ResourceDelta) {
	if err := hub.AcknowledgeResourceDelta(true); err != nil {
		dispatch.sink.EmitError(err)
		return
	}

	dispatch.publishStats(
		hub,
		metric(statDatacenterTag, uint64(hub.Parameters.DatacenterUniqueTag)),
		metric(statResourceLogicalCores, uint64(delta.LogicalCores)),
		metric(statResourceMemoryMB, uint64(delta.MemoryMB)),
		metric(statResourceStorageMB, uint64(delta.StorageMB)),
		metric(statResourceDownscale, boolValue(delta.IsDownscale)),
		metric(statResourceGraceSeconds, uint64(delta.GraceSeconds)),
	)
}

func (dispatch *meshDispatch) CredentialsRefresh(hub *neuronhub.NeuronHub, delta neuronhub.CredentialDelta) {
	if err := hub.AcknowledgeCredentialsRefresh(); err != nil {
		dispatch.sink.EmitError(err)
		return
	}

	dispatch.publishStats(
		hub,
		metric(statDatacenterTag, uint64(hub.Parameters.DatacenterUniqueTag)),
		metric(statCredentialGeneration, delta.BundleGeneration),
		metric(statCredentialTLSUpdates, uint64(len(delta.UpdatedTLS))),
		metric(statCredentialAPIUpdates, uint64(len(delta.UpdatedAPI))),
		metric(statCredentialRemovals, uint64(len(delta.RemovedTLSNames)+len(delta.RemovedAPINames))),
	)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	reactor := neuronhub.NewReactor[meshEvent]()
	dispatch := &meshDispatch{sink: reactor.Sink()}
	hub, err := neuronhub.NewNeuronHub(dispatch, nil)
	if err != nil {
		return err
	}

	handle, err := reactor.AttachNeuron(hub)
	if err != nil {
		return err
	}

	params := handle.Parameters()
	role, listenPort := detectRole(params)
	if role == roleAdvertiser {
		listener, err := net.ListenTCP("tcp6", &net.TCPAddr{IP: net.IPv6zero, Port: int(listenPort)})
		if err != nil {
			return err
		}
		defer listener.Close()
		servePingPong(listener, dispatch.sink)
		seedAdvertisements(dispatch.sink, params.AdvertisementPairings)
	} else {
		seedSubscriptions(dispatch.sink, params.SubscriptionPairings)
	}

	for {
		event, err := reactor.Wait()
		if err != nil {
			return err
		}
		if event.Neuron != nil {
			return nil
		}
		if event.App == nil {
			continue
		}

		switch event.App.Kind {
		case eventAdvertisementPairing:
			if event.App.Advertisement.Activate {
				if err := handle.SignalReady(); err != nil {
					return err
				}
			}
		case eventSubscriptionPairing:
			if !event.App.Subscription.Activate {
				continue
			}

			pairing := event.App.Subscription
			reactor.Once(meshEvent{Kind: eventSubscriberPong}, func() error {
				return runSubscriberPing(pairing)
			})
		case eventSubscriberPong:
			if err := handle.SignalReady(); err != nil {
				return err
			}
		}
	}
}

func detectRole(params neuronhub.ContainerParameters) (role, uint16) {
	if len(params.Advertises) > 0 {
		return roleAdvertiser, params.Advertises[0].Port
	}

	return roleSubscriber, 0
}

func seedAdvertisements(sink neuronhub.ReactorSink[meshEvent], pairings []neuronhub.AdvertisementPairing) {
	for _, pairing := range pairings {
		sink.Emit(meshEvent{
			Kind:          eventAdvertisementPairing,
			Advertisement: pairing,
		})
	}
}

func seedSubscriptions(sink neuronhub.ReactorSink[meshEvent], pairings []neuronhub.SubscriptionPairing) {
	for _, pairing := range pairings {
		sink.Emit(meshEvent{
			Kind:         eventSubscriptionPairing,
			Subscription: pairing,
		})
	}
}

func servePingPong(listener *net.TCPListener, sink neuronhub.ReactorSink[meshEvent]) {
	go func() {
		for {
			conn, err := listener.AcceptTCP()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}

				sink.EmitError(err)
				return
			}

			go func(conn *net.TCPConn) {
				if err := handlePing(conn); err != nil {
					sink.EmitError(err)
				}
			}(conn)
		}
	}()
}

func handlePing(conn *net.TCPConn) error {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(meshTimeout))

	request := make([]byte, len(meshPingPayload))
	if _, err := io.ReadFull(conn, request); err != nil {
		return err
	}
	if string(request) != meshPingPayload {
		return fmt.Errorf("unexpected pingpong request %q", request)
	}

	_, err := conn.Write([]byte(meshPongPayload))
	return err
}

func runSubscriberPing(pairing neuronhub.SubscriptionPairing) error {
	target, err := pairing.Target()
	if err != nil {
		return err
	}

	var lastErr error
	targetText := target.String()
	deadline := time.Now().Add(meshTimeout)
	for time.Now().Before(deadline) {
		if err := runSubscriberPingOnce(targetText); err == nil {
			return nil
		} else {
			lastErr = err
		}

		time.Sleep(200 * time.Millisecond)
	}

	return lastErr
}

func runSubscriberPingOnce(target string) error {
	conn, err := net.DialTimeout("tcp6", target, meshTimeout)
	if err != nil {
		return err
	}
	defer conn.Close()

	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetDeadline(time.Now().Add(meshTimeout))
	}

	if _, err := conn.Write([]byte(meshPingPayload)); err != nil {
		return err
	}

	reply := make([]byte, len(meshPongPayload))
	if _, err := io.ReadFull(conn, reply); err != nil {
		return err
	}
	if string(reply) != meshPongPayload {
		return fmt.Errorf("unexpected pingpong reply %q", reply)
	}

	return nil
}

func (dispatch *meshDispatch) publishStats(hub *neuronhub.NeuronHub, metrics ...neuronhub.MetricPair) {
	if err := hub.PublishStatistics(metrics); err != nil {
		dispatch.sink.EmitError(err)
	}
}

func metric(key uint64, value uint64) neuronhub.MetricPair {
	return neuronhub.MetricPair{Key: key, Value: value}
}

func boolValue(value bool) uint64 {
	if value {
		return 1
	}

	return 0
}
