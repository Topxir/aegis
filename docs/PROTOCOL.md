# Aegis protocol v2

Status: alpha, not externally audited. This document is the single source of truth
for the desktop client, the Android client and the server. Both clients must
produce and accept byte-identical data for the same inputs (see `test-vectors.json`).

## 1. Primitives

| Purpose | Primitive | Rust crate | Android |
|---|---|---|---|
| Vault key from password | Argon2id v0x13 (parameters stored in the vault header) | `argon2` | BouncyCastle `Argon2BytesGenerator` |
| Key agreement | X25519 | `x25519-dalek` | BC `X25519Agreement` |
| Signatures | Ed25519 | `ed25519-dalek` | BC `Ed25519Signer` |
| KDF | HKDF-SHA256 | `hkdf` + `sha2` | BC `HKDFBytesGenerator` |
| AEAD | ChaCha20-Poly1305 (12-byte nonce, 16-byte tag) | `chacha20poly1305` | BC `ChaCha20Poly1305` |
| Transport | TLS 1.2+ through the OS stack and OS trust store | `native-tls` (Schannel on Windows) | `HttpsURLConnection` |

No hand-written cryptography. `HKDF(ikm, salt, info, L)` is RFC 5869 with SHA-256.
Strings are UTF-8. `||` is concatenation. `hex` is lowercase.

## 2. Identity

- Username: `^[a-z0-9_]{3,24}$`, case-folded to lowercase before any use.
- Password: at least 10 characters. It only protects the local vault (section 9).
- At registration the client generates a random X25519 key pair (`x_sk`, `x_pk`) and a
  random Ed25519 key pair (`ed_sk`, `ed_pk`) from the OS CSPRNG. Secret keys live only
  inside the encrypted vault.
- Moving to another device is done with an explicit export file (the vault file itself,
  section 9). Without it a reinstall means a new account; the old username stays bound
  to the old key.

## 3. Directory (server)

`POST /api/v2/dir/register`, body `application/x-www-form-urlencoded`:
`u`, `title` (display name, ≤ 64 chars, may be empty), `x` (hex x_pk), `ed` (hex ed_pk),
`ts` (unix seconds), `sig` (hex Ed25519 signature), `pow` (decimal u64, section 4). Each field
appears exactly once.

Signed message: `"aegis-v2 dir\n" || u || "\n" || title || "\n" || x || "\n" || ed || "\n" || ts`.

Server rules: valid username, valid signature, `|ts − now| ≤ 600`, valid proof of work
(section 4) with `scope = "dir:" || u`. A username is bound to
the first `ed` that registers it; later registrations are accepted only with the same `ed`
(this is how the display name is updated). Different `ed` → `409`.

`GET /api/v2/dir/lookup?u=<username>` → `200 {"u":…,"title":…,"x":…,"ed":…}` or `404`.
Exact match only: users cannot be listed or searched by prefix.

Clients look up a username only on first contact and then use the pinned key
(section 8); every lookup tells the server who is about to talk to whom.

## 4. Queues (server)

Queue id: 32 bytes, sent as 64 hex chars.

- `POST /api/v2/queue/send?q=<hex>&ts=<unix>&pow=<u64>` body = hex of a padded frame →
  `200 {"seq":N}`. Padded length must be one of the buckets below, otherwise `400`.
  Full queue → `429`. Bad, stale or reused proof of work, or `ts` outside the window → `403`.
  Malformed parameters or body (not lowercase hex, wrong queue id length) → `400`.
- `GET /api/v2/queue/poll?q=<hex>&after=<seq>` → `200 {"frames":[{"seq":N,"d":"<hex>"}],"next":M}`,
  at most 100 frames with `seq > after`, ascending. `next` is the last returned seq
  (or `after` when empty).
- `GET /health` → `200 {"status":"ok","protocol":2}`.

Proof of work: find a decimal `u64` `pow` such that
`SHA256("aegis-v2 pow\n" || scope || "\n" || ts || "\n" || body_hash || "\n" || pow)` starts
with at least 18 zero bits. For queue sends `scope` is the queue hex and `body_hash` is the hex
SHA-256 of the request body; for directory registration `scope = "dir:" || u` and `body_hash`
is the hex SHA-256 of the signed message. `|ts − now| ≤ 600`. The server remembers accepted
hashes for 20 minutes and rejects repeats.

Frames are kept 14 days, at most 2000 per queue; a full queue rejects new frames with `429`
rather than dropping old ones. The server stores no
IP addresses and no request logs. It never sees plaintext, usernames of senders, or group
membership. It does see: which queue receives how many frames and when, and the
username ↔ public key directory.

Padding: `padded = BE32(len(frame)) || frame || zeros`, total length = the smallest bucket
in `[256, 512, 1024, 2048, 4096, 8192, 16384]` that fits. Frames larger than 16380 bytes
are rejected by the client.

## 5. Envelope (plaintext inside every frame)

UTF-8, lines separated by `\n`, each value percent-encoded (keep `A-Z a-z 0-9 - _ . ~`,
everything else `%XX` uppercase on bytes):

```
0 AEGIS2
1 type          dm | ginv | gmsg
2 msg_id        32 hex chars, random
3 sender        username
4 sender_name   display name
5 sender_ed     hex ed_pk
6 ts_ms         unix milliseconds
7 ttl_s         seconds until both sides delete, 0 = keep
8 group_id      hex, empty for dm
9 body          text (dm, gmsg) or group title (ginv)
10 group_key    hex, ginv only, else empty
11 members      comma-separated usernames, ginv only, else empty
```

Receivers reject envelopes with a wrong header, wrong field count (12), or invalid hex.
Frame type must match envelope type: `0x01` carries `dm` or `ginv`, `0x02` carries `gmsg`.
`msg_id` values already seen are dropped (the set is kept in the vault, because the server
can replay frames).

## 6. Direct messages and group invites (frame type 0x01)

Sender `S` (x_sk, x_pk), recipient `R` (x_pk from directory or pinned contact).
Recipient inbox queue: `SHA256("aegis-v2 inbox" || R.x_pk)`.

```
e        = fresh random X25519 key pair
dh1      = X25519(e_sk, R.x_pk)
k1       = HKDF(dh1, e_pk || R.x_pk, "aegis-v2 seal-1", 32)
c1       = AEAD(k1, nonce=0^12, aad = 0x01 || e_pk, S.x_pk)              // 48 bytes
dh2      = X25519(S.x_sk, R.x_pk)
k2       = HKDF(dh1 || dh2, e_pk || R.x_pk, "aegis-v2 seal-2", 32)
c2       = AEAD(k2, nonce=0^12, aad = 0x01 || e_pk || c1, envelope)
frame    = 0x01 || e_pk || c1 || c2
```

The fixed nonce is safe because `k1`/`k2` are unique per message (fresh `e`).
An all-zero `dh1` or `dh2` is rejected.

The recipient decrypts `c1` to get `S.x_pk`, then `c2`. The sender is authenticated by `dh2`,
and the server cannot see who sent the frame. The recipient then checks that
`S.x_pk` and `sender_ed` match the pinned contact for `sender`; only an unknown sender is
looked up in the directory (and then pinned).
On mismatch the message is dropped and the contact is flagged as "key changed".

Each client also keeps its own copy of what it sent; nothing is sent to self.

## 7. Groups (frame type 0x02)

A creator makes a random 32-byte `G` and sends a `ginv` envelope to every member
(section 6). Members ≤ 20.

```
group_id = hex(SHA256("aegis-v2 group-id" || G))
queue    = HKDF(G, "", "aegis-v2 group-queue", 32)
k        = HKDF(G, "", "aegis-v2 group-msg", 32)
sig      = Ed25519(sender ed_sk, "aegis-v2 gmsg\n" || envelope)
frame    = 0x02 || nonce(12, random) || AEAD(k, nonce, aad = 0x02, envelope || sig)
```

Receivers verify `sig` against `sender_ed`, which must match the pinned key for `sender`
(unknown members are looked up once and pinned), and require `group_id` in the envelope to
equal the id of the group whose queue delivered the frame. Group members are not anonymous to each other.

No forward secrecy in v2: a stolen `x_sk` or `G` decrypts past traffic captured by the
server. This is a known limitation.

## 8. Contacts and verification

The first key seen for a username is pinned locally. Safety number for two users A and B:
`h = SHA256("aegis-v2 safety" || lo || hi)` where `lo`/`hi` are `ed_pk || x_pk` of each user
sorted bytewise. Display the first 30 bytes as six groups: each 5-byte big-endian chunk
`mod 100000`, zero-padded to 5 digits. Both sides see the same number.

## 9. Local storage

Everything (keys, contacts, chats, settings) is stored in one encrypted file per account:

```
"AGV2" || m_kib(BE32) || t(BE32) || p(BE32) || salt(16) || nonce(12) || ciphertext
key        = Argon2id v0x13(password, salt, m_kib, t, p) → 32 bytes
ciphertext = AEAD(key, nonce, aad = first 32 bytes of the file, data)
```

Defaults: m = 65536 KiB on desktop, 19456 KiB on Android, t = 2, p = 1. Salt and nonce are
random and the nonce is renewed on every write. File name: first 32 hex chars of
`SHA256("aegis-v2 vault-name" || 0x0A || username)` + `.vault`. There is no unencrypted index;
the app asks for username and password on every start. Writes go to a temp file and are
renamed into place. The same file is the export format.

## 10. Transport

Endpoints are `https://host[:port]` (default `https://freeoasis.space`). `http://` is only
accepted for `127.0.0.1`, `localhost` and `.onion` hosts. With the default server, TLS ends
at Cloudflare: Cloudflare sees the client IP, queue ids and directory lookups, but not
message contents. An optional SOCKS5 proxy (for
example Tor at `127.0.0.1:9050`) is used with remote DNS (`socks5h`), so the client never
resolves the server name itself.

## 11. Test vectors

`docs/test-vectors.json` is generated by the Rust core with fixed randomness (`e_sk`,
group nonces, keys, salts) through `*_with_rng`-style entry points, and must be reproduced
exactly by the Android implementation. HKDF with an empty salt means "no salt" (Rust `None`,
BouncyCastle `null`). Argon2 is version 0x13.

## 12. Server implementation notes

- Status codes: malformed request `400`; `ts` outside the window, insufficient, reused or
  mismatched proof of work, or bad signature `403`; username bound to another `ed` `409`;
  oversized HTTP body (> 64 KiB) `413`; full queue `429`; server table limits (queues,
  directory entries) `503`; unknown path `404`; known path with the wrong method `405`.
- `seq` values come from one counter for the whole server, so they never repeat even when a
  queue is emptied and recreated. `after` defaults to `0`.
- The proof-of-work replay cache is kept in memory only. A request rejected for a full queue
  does not consume its proof of work.
- Hex fields are lowercase only; percent-escapes in envelope fields are uppercase only.
- State is stored in `server-v2.state` inside the data directory and replaced atomically.
  An unreadable state file stops the server instead of being replaced.
- The server itself speaks plain HTTP and must sit behind a TLS terminator (Cloudflare tunnel,
  reverse proxy) when reachable from outside the machine; clients refuse `http://` to public hosts.
- Section 11 entry points are named `*_with` and take the random bytes explicitly.
