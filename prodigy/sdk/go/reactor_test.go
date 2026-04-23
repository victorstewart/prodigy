// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0

package neuronhub

import (
	"io"
	"syscall"
	"testing"
)

type reactorEvent uint8

const reactorProbeReady reactorEvent = 1

func TestReactorReceivesAppAndNeuronEvents(t *testing.T) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	container := fds[0]
	peer := fds[1]
	defer syscall.Close(peer)

	params := ContainerParameters{
		NeuronFD: int32(container),
	}

	hub, err := NewNeuronHubFromParameters(DispatchBase{}, params)
	if err != nil {
		t.Fatalf("new hub: %v", err)
	}

	reactor := NewReactor[reactorEvent]()
	handle, err := reactor.AttachNeuron(hub.WithAutoAcks())
	if err != nil {
		t.Fatalf("attach neuron: %v", err)
	}
	reactor.Once(reactorProbeReady, func() error { return nil })

	event, err := reactor.Wait()
	if err != nil || event.App == nil || *event.App != reactorProbeReady {
		t.Fatalf("unexpected app event: err=%v event=%+v", err, event)
	}

	if err := handle.SignalReady(); err != nil {
		t.Fatalf("ready: %v", err)
	}

	healthy := make([]byte, 16)
	if _, err := syscall.Read(peer, healthy); err != nil {
		t.Fatalf("read healthy: %v", err)
	}
	frame, err := ParseMessageFrame(healthy)
	if err != nil {
		t.Fatalf("parse healthy: %v", err)
	}
	if frame.Topic != ContainerTopicHealthy {
		t.Fatalf("expected healthy, got %v", frame.Topic)
	}

	stop := BuildMessageFrame(ContainerTopicStop, nil)
	if _, err := syscall.Write(peer, stop); err != nil {
		t.Fatalf("write stop: %v", err)
	}

	event, err = reactor.Wait()
	if err != nil || event.Neuron == nil || *event.Neuron != NeuronEventShutdown {
		t.Fatalf("unexpected neuron event: err=%v event=%+v", err, event)
	}

	if err := hub.Close(); err != nil && err != io.EOF {
		t.Fatalf("close hub: %v", err)
	}
}

func TestReactorSinkEmitsAppEvent(t *testing.T) {
	reactor := NewReactor[reactorEvent]()
	reactor.Sink().Emit(reactorProbeReady)

	event, err := reactor.Wait()
	if err != nil {
		t.Fatalf("wait: %v", err)
	}
	if event.App == nil || *event.App != reactorProbeReady {
		t.Fatalf("unexpected app event: %+v", event)
	}
}
