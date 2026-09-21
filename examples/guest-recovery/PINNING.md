# Guest recovery toolchain pins

`toolchain-lock.json` pins the Debian 13 amd64 cloud image to build
`20260914-2601` and records all 18 Ubuntu tool archives used by the task-local
QEMU pilot. Every archive has its exact URL, filename, package version including
epoch, architecture, byte length and SHA-256. The image uses SHA-512. There is no
floating `latest` download in the lock.

The 2026-09-21 validation checked the cached image and all 18 archives against
their recorded sizes and hashes. The pilot originally downloaded the image via
`latest`; those bytes match the dated build's checksum. Archive control metadata
also matched the package versions and architectures. QEMU, qemu-img, genisoimage
and the selected SeaBIOS binary were compared directly with members of their
pinned archives. The image's upstream signature has **not** been verified; its
checksum manifest is provenance for integrity, not independent authentication.

Extract verified archives into a fresh dedicated directory in the listed order
using `dpkg-deb --extract`. This does not install host packages or run package
maintainer scripts. Use the explicit environment, executable paths, module
directory and firmware paths in `extraction`. Keep these loader settings scoped
to the tools that need them. The image remains an immutable backing file; guest
writes belong in a separate disposable overlay.

These archives are **not a complete host dependency closure**. The tools use the
host's `/lib64/ld-linux-x86-64.so.2` and many host shared libraries. The lock records
the observed interpreter hash, initial dependency names, six task-local library
hashes, and extracted binary hashes. A different host can load different library
bytes despite identical package checksums. Record the actual loader/library and
module identities for every execution, and fail when required dependencies are
unavailable. Loader `--list` inspection does not inventory later `dlopen` calls.
The lock makes no portability, hermetic-runtime or security-update claim.

The intended accelerator setting is `tcg,thread=single,tb-size=64`. QEMU 8.2.2
rejects `-accel tcg,help`, but the read-only command below succeeds and lists
`thread=<string>` and `tb-size=<int>`:

```text
<QEMU_ROOT>/usr/bin/qemu-system-x86_64 -object tcg-accel,help
```

Its exact output and hash are recorded in `qemu_option_evidence`. This establishes
that the properties exist. Acceptance of the complete accelerator argument and
actual guest behavior require execution evidence from the recovery harness. No
guest was started while producing this lock.

Consumers need only this public lock; the named source records are historical
provenance, not runtime dependencies on an enclosing development repository.
Before extraction or boot, verify the downloaded bytes against the lock. Never
substitute a newer package, image, firmware or runtime silently. Hash the exact
lock bytes into the execution evidence packet, together with the harness source
SHA, runtime identity and actual commands. This lock alone does not pass any
guest recovery or product acceptance gate.

## Offline guest prerequisites

`guest-packages-lock.json` adds Git `1:2.47.3-0+deb13u1` and bubblewrap
`0.12.0-1~deb13u1` to the same pristine Debian image. It contains 11 Debian
archives, totaling 19,353,640 bytes, with exact URLs, hashes, sizes and package
versions. All downloaded archives are retained in the task-local cache. These
are guest packages; the 18 Ubuntu archives in `toolchain-lock.json` are tools
for running QEMU on the existing host.

The required dependency closure resolves 47 `Depends`/`Pre-Depends` clauses
against the image's 322-package build manifest. It uses 23 existing base packages
without upgrading any. The added dependencies are Git's Perl libraries, manual
pages and GnuTLS curl libraries; bubblewrap's required libraries already exist
in the image. Recommendations and suggestions are excluded. The lock records
every resolved clause and the exact base-package versions it relies on.

The Debian archives were downloaded from the official mirror, checked against
the authenticated `trixie/main` amd64 Packages index, and inspected with
`dpkg-deb --field`. `gpgv` verified the InRelease signatures; the compressed and
uncompressed package indexes matched the signed Release checksums. No Debian
archive keyring was preinstalled on the host. The public signing keys were
bootstrapped over official HTTPS and their fingerprints matched Debian's
official key page. The lock preserves that trust limitation, public-key hashes,
signer fingerprints and exact metadata identities. Stable main's signed Release
has no `Valid-Until`; these are explicit version pins, not automatic updates.

Verify archive bytes before transfer and again inside the disposable guest.
Install only the listed files in `install_order`, using the guest's `dpkg
--install`; do not run a network resolver or host package installer. Check
`dpkg --audit`, installed package versions, `git --version` and `bwrap --version`
after installation. A changed base image requires a fresh dependency resolution.
The lock does not prove that guest maintainer scripts configure successfully or
that the running guest kernel permits the namespace operations needed by
bubblewrap. Those checks remain part of the guest harness.
