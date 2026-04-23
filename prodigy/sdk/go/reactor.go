// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0

package neuronhub

import (
	"context"
	"fmt"
	"io"
)

type NeuronEvent uint8

const (
	NeuronEventShutdown NeuronEvent = iota + 1
	NeuronEventClosed
)

type ReactorEvent[T any] struct {
	App    *T
	Neuron *NeuronEvent
}

type ReactorResult[T any] struct {
	Event ReactorEvent[T]
	Err   error
}

type Reactor[T any] struct {
	events chan ReactorResult[T]
}

type ReactorSink[T any] struct {
	events chan<- ReactorResult[T]
}

type NeuronHandle struct {
	parameters ContainerParameters
	hub        *NeuronHub
	readySent  bool
}

func NewReactor[T any]() *Reactor[T] {
	return &Reactor[T]{
		events: make(chan ReactorResult[T], 16),
	}
}

func (reactor *Reactor[T]) Next(ctx context.Context) (ReactorEvent[T], error) {
	select {
	case <-ctx.Done():
		return ReactorEvent[T]{}, ctx.Err()
	case result, ok := <-reactor.events:
		if !ok {
			return ReactorEvent[T]{}, io.EOF
		}
		if result.Err != nil {
			return ReactorEvent[T]{}, result.Err
		}
		return result.Event, nil
	}
}

func (reactor *Reactor[T]) Wait() (ReactorEvent[T], error) {
	return reactor.Next(context.Background())
}

func (reactor *Reactor[T]) Events() <-chan ReactorResult[T] {
	return reactor.events
}

func (reactor *Reactor[T]) Sink() ReactorSink[T] {
	return ReactorSink[T]{
		events: reactor.events,
	}
}

func (reactor *Reactor[T]) Once(event T, fn func() error) {
	go func() {
		sink := reactor.Sink()
		if err := fn(); err != nil {
			sink.EmitError(err)
			return
		}

		sink.Emit(event)
	}()
}

func (reactor *Reactor[T]) AttachNeuron(hub *NeuronHub) (*NeuronHandle, error) {
	if hub == nil {
		return nil, fmt.Errorf("prodigy: hub is nil")
	}

	handle := &NeuronHandle{
		parameters: hub.Parameters,
		hub:        hub,
	}

	go func() {
		for {
			err := hub.RunOnce()
			if err != nil {
				if err == io.EOF {
					closed := NeuronEventClosed
					reactor.events <- ReactorResult[T]{
						Event: ReactorEvent[T]{
							Neuron: &closed,
						},
					}
				} else {
					reactor.events <- ReactorResult[T]{Err: err}
				}
				return
			}

			if hub.ShutdownRequested() {
				shutdown := NeuronEventShutdown
				reactor.events <- ReactorResult[T]{
					Event: ReactorEvent[T]{
						Neuron: &shutdown,
					},
				}
				return
			}
		}
	}()

	return handle, nil
}

func (handle *NeuronHandle) Parameters() ContainerParameters {
	return handle.parameters
}

func (handle *NeuronHandle) Ready(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return handle.SignalReady()
}

func (handle *NeuronHandle) SignalReady() error {
	if handle.readySent {
		return nil
	}

	if err := handle.hub.SignalReady(); err != nil {
		return err
	}

	handle.readySent = true
	return nil
}

func (sink ReactorSink[T]) Emit(event T) {
	eventCopy := event
	sink.events <- ReactorResult[T]{
		Event: ReactorEvent[T]{
			App: &eventCopy,
		},
	}
}

func (sink ReactorSink[T]) EmitError(err error) {
	sink.events <- ReactorResult[T]{Err: err}
}
