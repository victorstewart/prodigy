Bundle Update Security (Ed25519)

We require signed Prodigy bundles for in-place updates. The receiving node embeds a pinned Ed25519 public key and verifies signatures when receiving a new bundle from the Brain.

Process

- CI signs the bundle using Ed25519 and produces `prodigy.sig` (64 bytes raw).
- The master Brain, when pushing a bundle to peers, attaches both the bundle and the signature if `/root/prodigy.sig` exists.
- The receiving node verifies the signature against its pinned public key before writing `/root/prodigy.bundle.new.tar.zst`.
- Only on successful verification does it proceed to `transitionToNewBundle`.

Pinned Public Key

- The pinned key path is not currently wired into the shipping Prodigy build. Do not treat bundle-signature verification as active until the verification path is connected to the bundle update flow.

Rationale (even over VPN)

- VPN controls transport and identity but does not prevent insider mistakes or payload corruption.
- Signature verification prevents both malicious tampering and accidental corruption from bricking a fleet.

SSH Access Hardening

Option A: OpenSSH CA‑signed user certificates

- Create an SSH CA keypair; distribute the CA public key to machines via `TrustedUserCAKeys` or per‑user `authorized_principals`.
- The Brain issues short‑lived (e.g., 5–10 min) user certs to ops engineers that encode allowed principals.
- Configure sudoers for the ops user to allow exactly the required commands (e.g., `systemctl restart neuron`) with NOPASSWD.
- Benefit: No static keys on hosts; revocation is at the CA level; cert lifetimes bound blast radius.

Option B: GCP OS Login / SSM

- Use GCE OS Login or a cloud SSM (AWS SSM analogs) to execute lifecycle operations via IAM.
- The Brain calls the cloud API to request a command session instead of opening inbound SSH.
- Benefits: no inbound SSH, centralized IAM policies and logging, strong audit.
