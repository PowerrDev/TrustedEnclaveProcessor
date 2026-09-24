# tepOS

tepOS (Trusted Enclave Processor Operating System) is the security OS of the
Trusted Enclave Processor, NXU's counterpart to a secure enclave. It runs on
the seL4 microkernel in its own machine (a separate QEMU) and talks to NXU only
over a serial mailbox.

```
QEMU (aarch64 virt)
  TEP loader (boot/loader)  ->  seL4  ->  root task (boot/rootserver)
                                              TEPManager: builds, watches and restarts services
                                              +-- diag        health probe target
                                              +-- mailbox     NXU mailbox on serial1
                                              +-- crypto      virtio-rng entropy, HMAC_DRBG, SHA-256
                                              +-- keystore    Ed25519 keys + sealed records on disk
                                              +-- auth        passcode (Argon2id), delays, lockout
                                              +-- bootpolicy  signed boot manifests, anti-rollback
```

Every service is its own seL4 protection domain: own address space,
capability space and thread, memory from a private pool (revoked and zeroed on
restart), and only the capabilities listed in `boot/include/tep/ipc.h`. The
root task never calls a service (it only replies and signals), so no service
can stall it. Services call each other through badged endpoints the root task
mints (`boot/include/tep/services.h`).

## Building and running

```sh
make run              # build and boot tepOS (Ctrl-A X quits)
make qemu-devices     # QEMU device flags, for tools that boot tepOS themselves
```

`make run` in NXU (`tools/with_tepos.sh`) boots tepOS next to NXU and joins the
two with `tools/mailbox_link.py`.

## Tests

| Target | What |
|---|---|
| `make test-crypto` | SHA-256, HMAC-SHA-256, HMAC_DRBG against NIST/RFC vectors; Monocypher's Ed25519 and AEAD (host, ASan/UBSan) |
| `make test-keystore` | keys survive reboots; a tampered store or another sealing key is refused |
| `make test-auth` | passcode, attempt delays across reboots, lockout, recovery reset |
| `make test-boot-policy` | manifest signatures, digests, rollback, minimum surviving a reboot |
| `tools/mailbox_client.py --selftest` | the mailbox protocol and crypto commands against a running tepOS |

## What it does and does not protect

- Keys are generated and used inside the KeyStore; private keys never cross the
  mailbox.
- The key store on disk is sealed with a key from a **host file** (fw_cfg), so
  the host can open it: it survives reboots and detects tampering, but it is
  **not a protection boundary** against the host, and it cannot prevent rolling
  back to an older sealed copy. That needs a hardware root of trust.
- Passcode delays use the RTC, which is the host's clock.
- Boot manifests are **verified and reported, not enforced**: NXU measures its
  own image and nothing in the boot chain acts on the verdict yet.
- Entropy comes from virtio-rng, i.e. the host's random source, checked by a
  repetition count test.
