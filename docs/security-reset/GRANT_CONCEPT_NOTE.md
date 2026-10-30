# Aegis — concept note for a security audit grant

- Status: **DRAFT for owner review** (not submitted)
- Date: 2026-10-30
- Related: `GRANT_PLAN.md`, `FISCAL_SPONSOR_SHORTLIST.md`,
  `THREAT_MODEL_V2.md`, `PROTOCOL_V2.md`, `ROADMAP_V2.md`

> This is a grant concept note, not a claim that Aegis is already secure.
> The current repository contains an insecure prototype; the security reset
> is a plan, and no external audit has been performed yet.

## 1. Summary

Aegis is an open-source (AGPL-3.0-or-later), invite-only messenger designed
for people who cannot afford to be identified by their network, their
platform, or the service operator. The MVP is 1:1 text and files on Android
and Desktop, with embedded Tor and Oblivious HTTP (OHTTP) by default. There
is no phone number, email, global nickname, contact discovery, telemetry, or
cloud backup.

We are requesting **$60,000–$120,000** to fund an independent security audit
of the cryptographic core, protocol, client, and relay, plus twelve months
of infrastructure. The grant would move Aegis from a documented security
reset to a public alpha that can be honestly labeled “unaudited”, and then to
a 1.0 release with a published audit. The audit is the bottleneck; the
development plan is deliberately narrow so that a solo maintainer can
execute it with audited libraries.

## 2. Problem

Most “private” messengers still expose a social graph to a platform:

- phone-number or email registration links an account to a legal identity;
- contact discovery uploads the address book;
- push notifications often depend on Google/Apple infrastructure;
- users are told to install and configure Tor themselves, which most do
  not do;
- server operators can log IP addresses, timing, and queue metadata;
- “end-to-end encrypted” often says nothing about metadata, backups, or
  operator compromise.

For journalists, activists, survivors of abuse, and people under
state-level surveillance, metadata is often more dangerous than content.
A messenger that is easy to use but reveals who talks to whom does not solve
the problem.

## 3. Solution

Aegis makes the private path the default path:

1. **Invite-only identity.** A contact card contains public keys and a
   prekey bundle; there is no global username and no searchable directory.
   The default is seed-only identity. An optional OPAQUE account service
   exists only for seed recovery and a signed device list; it never sees
   messages.
2. **Audited cryptography.** PQXDH and the Double Ratchet come from
   libsignal (pinned commit); MLS groups come from OpenMLS after the 1:1
   MVP; storage uses SQLCipher; TLS 1.3 uses rustls. No custom primitives.
3. **Embedded Tor + OHTTP.** The client ships Arti; the user installs
   nothing. API requests use OHTTP so the gateway does not learn the client
   IP and the relay does not learn the account. Direct IP is an explicit
   opt-in with a warning, not the default.
4. **Blind relay.** The relay stores opaque envelopes by `inbox_id`, with
   TTL, size buckets, and no sender identity. It does not need an account
   registration endpoint.
5. **Deletion-resistant code and network.** AGPL source, reproducible
   builds, independent builders, federation, and later P2P onion transport
   make it possible to fork and mirror the network. This does not make a
   message undeletable on a recipient’s device; we do not claim that.
6. **Honest security posture.** Public alpha is labeled “unaudited” and
   follows an internal red team. External audit is completed before 1.0.
   There is no “100% anonymous” or “unhackable” marketing.

## 4. Threat model and non-goals

**In scope:** state-level passive and active network adversaries, platform
surveillance, malicious or compromised relay/account operators, server
seizure, traffic analysis, replay, downgrade, malformed input, and supply
chain attacks. The design also aims to limit what the creator can learn and
to make backdoored builds detectable through independent reproducible
builds.

**Out of scope:** a compromised device, a coercive adversary who can force
a user to unlock the device, global passive adversaries against all
traffic, and absolute anonymity. These are documented residual risks, not
hidden assumptions.

## 5. Current status (honest)

- The existing prototype passed 98 tests, but those tests validate a custom
  implementation, not a secure design.
- The security reset (rev.2) is approved: threat model, protocol,
  architecture, roadmap, and dependency ADRs.
- No production code has been written for the new core.
- No external audit has been performed.
- The project is solo and unfunded; the audit and part-time development
  time are the two constraints.

This grant is specifically intended to change the last two facts without
overstating the first three.

## 6. Plan and milestones

| Milestone | Deliverable | Indicative timing |
|---|---|---|
| M0. Phase 0 | Approved threat model, protocol, architecture, ADRs; grant plan drafted | done / in progress |
| M1. Audited 1:1 core | libsignal PQXDH/Double Ratchet, invite v2, inbox, SQLCipher, CLI | 8–12 weeks |
| M2. Transport | rustls, Arti, OHTTP, blind relay, blob store, opt-in OPAQUE | 8–12 weeks |
| M3. MVP | Android/Desktop 1:1 text + files, 7-day soak | 10–16 weeks |
| M4. Internal red team | Report; all critical/high closed | 4–6 weeks |
| M5. Public alpha | “unaudited/alpha” label, reproducible builds, SBOM | 2–4 weeks |
| M6. External audit | Published report; all critical/high closed | 6–10 weeks |
| M7. 1.0 | “Unaudited” label removed | 2–4 weeks |

Timing is indicative. The project uses hard phase gates: no groups, calls,
plugins, or iOS until the 1:1 core and its audit are stable.

## 7. Budget

| Item | Range |
|---|---|
| Independent audit: crypto, protocol, client, relay | $50,000–$100,000 |
| Infrastructure (relay, account service, OHTTP gateway, blob store, CI) for 12 months | $3,000–$6,000 |
| Legal consultation and fiscal sponsor fees | $5,000–$10,000 |
| Contingency (10%) | $6,000–$12,000 |
| **Total** | **$64,000–$128,000** |

We seek **$60,000–$120,000** for the first grant, focused on audit and
infrastructure. Development time may be funded separately or later so that
the first grant has a narrow, auditable scope. A fiscal sponsor will receive
and administer the funds; the project does not yet have its own legal
entity.

## 8. Team and governance

- **Maintainer:** solo developer; responsible for protocol, Rust core,
  Android/Desktop clients, documentation, and release engineering.
- **Fiscal sponsor:** to be selected (CCT, SPI, or OSC shortlist); handles
  contracts, payroll, tax, and grant reporting.
- **Independent auditors:** to be selected after funding; scope and price
  will be fixed before work starts.
- **Independent reproducible builders:** at least two, at least one not the
  author; verify release binaries.
- **Governance:** technical decisions follow published ADRs; security-
  relevant changes require review and tests; no telemetry or third-party
  SDKs in the core.

## 9. Sustainability

Aegis will remain AGPL-3.0-or-later. Funding comes from privacy/security
grants and small donations, not from advertising, data sale, or a token.
Infrastructure is designed to be cheap enough for a small user base and
federated enough that no single operator is a choke point. The project will
publish an audit report, SBOM, reproducible build instructions, and a
transparent expense report as required by the funder.

## 10. Why this grant matters

A working, audited, Tor-by-default messenger with no phone number and no
global identity is still rare. The hard part is not writing another chat UI;
it is getting the cryptographic core, metadata handling, and release
process right. This grant buys the one thing a solo unfunded project cannot
buy: independent scrutiny before users are asked to trust it.

## 11. What we will not claim

- We will not claim “100% anonymity” or “unhackable”.
- We will not claim the current prototype is secure.
- We will not claim a message is undeletable on a recipient’s device.
- We will not ship a public alpha before the internal red team.
- We will not remove the “unaudited” label before the external audit.
- We will not add calls, plugins, or growth features at the expense of the
  audit.
