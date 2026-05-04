// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0

pub mod aegis;
pub mod opinionated;

#[path = "../neuron_hub.rs"]
mod imp;

pub use imp::*;
pub use opinionated::{ActivationAction, AegisStream, InboundMessage, PairingBook, PairingKey};

#[cfg(feature = "tokio")]
pub mod tokio_support;
