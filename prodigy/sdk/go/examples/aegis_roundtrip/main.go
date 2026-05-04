// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log"

	neuronhub "github.com/victorstewart/prodigy/sdk/go"
)

func main() {
	subscription := neuronhub.SubscriptionPairing{
		Secret: neuronhub.U128{
			0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
			0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		},
		Address: neuronhub.U128{
			0xfd, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		},
		Service:       0x2233000000001001,
		Port:          3210,
		ApplicationID: 0x2233,
		Activate:      true,
	}
	advertisement := neuronhub.AdvertisementPairing{
		Secret:        subscription.Secret,
		Address:       subscription.Address,
		Service:       subscription.Service,
		ApplicationID: subscription.ApplicationID,
		Activate:      true,
	}

	parameters := neuronhub.ContainerParameters{
		SubscriptionPairings:  []neuronhub.SubscriptionPairing{subscription},
		AdvertisementPairings: []neuronhub.AdvertisementPairing{advertisement},
	}

	subscriber := neuronhub.AegisSessionFromSubscription(parameters.SubscriptionPairings[0])
	advertiser := neuronhub.AegisSessionFromAdvertisement(parameters.AdvertisementPairings[0])
	frame, err := subscriber.Encrypt([]byte("ping from prodigy-sdk"))
	if err != nil {
		log.Fatal(err)
	}

	plaintext, _, err := advertiser.Decrypt(frame)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("pairing_hash=%#x tfo_bytes=%d\n", subscriber.PairingHash(), len(subscriber.BuildTFOData([]byte("mesh-aegis"))))
	fmt.Println(string(plaintext))
}
