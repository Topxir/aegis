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
`u`, `title` (legacy display name, ≤ 64 chars, clients send it empty), `x` (hex x_pk), `ed` (hex ed_pk),
`ts` (unix seconds), `sig` (hex Ed25519 signature), `pow` (decimal u64, section 4).
Reserved names: `owner`, `aegis`, `admin`, `support`, `official`, and any name that reads the
same after dropping `_` and folding `0 1 l 3 4 5 6 7 8 9 2` to `o i i e a s b t b g z`, `rn` to `m` and
`vv` to `w`, or whose folded form contains a reserved name (for example `adm1n`, `0wner`,
`aegis_support`, `adrnin`), get `403`. The only exception is the configured owner key: the server reads the owner
`ed_pk` (64 hex digits) from the environment variable `AEGIS_OWNER_ED_PK`, else from the file
`owner-ed-pk` in the data directory, and lets only that key register reserved names. Without a
configured key nobody can register them. Each field
appears exactly once.

Signed message: `"aegis-v2 dir\n" || u || "\n" || title || "\n" || x || "\n" || ed || "\n" || ts`.

Server rules: valid username, valid signature, `|ts − now| ≤ 600`, valid proof of work
(section 4) with `scope = "dir:" || u`. A username is bound to
the first `ed` that registers it; later registrations are accepted only with the same `ed`.
Different `ed` → `409`. One `ed` holds at most one username: registering a second name with a
key that already has one → `409` (names held twice from before this rule keep working).

The server does not store the display name. `title` is still covered by the signature so old
clients keep working, but it is dropped on receipt; display name and avatar travel only end to
end (section 22). State files written before this rule lose their stored titles on load.

`GET /api/v2/dir/lookup?u=<username>` → `200 {"u":…,"title":"","x":…,"ed":…}` or `404`.
Exact match only: users cannot be listed or searched by prefix. `title` is always empty and is
kept only for old clients. A hidden profile (section 29.4) answers `404` exactly like an unknown
name.

Clients look up a username only on first contact and then use the pinned key
(section 8); every lookup tells the server who is about to talk to whom.

## 4. Queues (server)

Queue id: 32 bytes, sent as 64 hex chars.

- `POST /api/v2/queue/send?q=<hex>&ts=<unix>&pow=<u64>` body = hex of a padded frame →
  `200 {"seq":N}`. Padded length must be one of the buckets below, otherwise `400`.
  Full queue → `429`, but only for a fresh proof of work at the base bits, which is then spent
  like that of an accepted send. Bad, stale or reused proof of work, or `ts` outside the window
  → `403`.
  The required work rises with the fill of the queue: the base 18 bits up to 50% full, then one
  more bit for every further 12.5% (`bits = 18 + max(0, floor(8 * len / max) − 4)`, so 19 from
  62.5%, up to 22 when full). A proof that meets the base but not the current requirement gets
  `429 {"error":"…","bits":N}` with the bits wanted; clients mine again at `N` (at most 28) and
  retry once.
  The official queue (section 19) also needs `&sig=<hex>`, the owner's signature (below).
  Malformed parameters or body (not lowercase hex, wrong queue id length) → `400`.
- `GET /api/v2/queue/poll?q=<hex>&after=<seq>` → `200 {"frames":[{"seq":N,"d":"<hex>"}],"next":M,"has_more":false}`,
  at most 100 frames with `seq > after`, ascending, and at most about 1,000,000 bytes of JSON
  (always at least one frame), so the answer fits the largest sealed bucket. `next` is the last
  returned seq (or `after` when empty). `has_more` is true when frames beyond `next` are still
  waiting; the client polls again at once with `after = next`. A client treats a missing
  `has_more` as false.
- `GET /health` → `200 {"status":"ok","protocol":2}`.

Proof of work: find a decimal `u64` `pow` such that
`SHA256("aegis-v2 pow\n" || scope || "\n" || ts || "\n" || body_hash || "\n" || pow)` starts
with at least 18 zero bits. For queue sends `scope` is the queue hex and `body_hash` is the hex
SHA-256 of the request body; for directory registration `scope = "dir:" || u` and `body_hash`
is the hex SHA-256 of the signed message. `|ts − now| ≤ 600`. The server remembers accepted
hashes for 20 minutes and rejects repeats.

Frames are kept 14 days, at most 2000 per queue; a full queue rejects new frames with `429`
rather than dropping old ones. Queue ids are public (the inbox id derives from the public
`x_pk`), so anyone willing to pay the work can fill a queue; the rising work makes that cost
about 2^22 hashes per frame near the top and the queue frees itself after 14 days. This is a
residual risk, not a fix: an attacker with enough compute can still lock out one inbox for the
retention time. A user who is locked out creates a new identity. The server stores no
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
(section 6). Members ≤ 100. Any user can create groups and channels.

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

Frame type 0x02 is the original group format. Clients send group messages as frame type 0x05
(section 28), which adds forward secrecy; 0x02 is still accepted on receive.

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

Vectors added for sections 13 to 17 (top-level names in `test-vectors.json`): `attachment`
(sealed chunks and descriptor body for a 100-byte image, chunk lengths and hashes for a
two-chunk one, plus the `dmf` envelope), `channel` (`channel_id`, queue, key, a `cinv` and a signed
`cmsg` frame), `avatar` (two identities, 25-char row-major mask, `bg`, `fg`) and `mp4` (a
synthetic MP4 with GPS metadata: input hex, sanitized output hex and SHA-256, width, height,
duration).

Vectors for sections 19, 20 and 22: `official` (`G`, channel id, queue, key, a signed post), `prof`
(a `prof` envelope and invalid bodies) and `pin` (Argon2id `T`, verifier, wrap key, the 116-byte pin
file, hash inputs, the duress record). The `pin` vector uses Argon2id m=64 KiB, t=1, p=1 to stay
fast; the protocol values are in section 20.

Vectors for sections 23, 27 and 28 (all with fixed secrets): `x3dh` (a signed prekey, a one-time
prekey, `AD`, and `SK` with and without the one-time prekey), `ratchet` (three messages A to B
delivered in the order 0, 2, 1, so one key is skipped and then used, plus one reply B to A that
triggers a DH step), `session` (a type 0x03 start frame with its `0x00` inner header, B's
reply, and A's next frame, which carries the `0x01` inner header), `senderkey` (an `skey`
envelope and a type 0x05 frame with `hnonce`, `chain_id` and `n`) and `sealed_transport` (an
outer request, the response key and an outer response). Each vector lists the secrets needed to
reproduce it.

## 12. Server implementation notes

- Status codes: malformed request `400`; `ts` outside the window, insufficient, reused or
  mismatched proof of work, or bad signature `403`; username bound to another `ed` `409`;
  oversized HTTP body (> 64 KiB) `413`; full queue `429`; server table limits (queues,
  directory entries) `503`; unknown path `404`; known path with the wrong method `405`.
- `seq` values come from one counter for the whole server, so they never repeat even when a
  queue is emptied and recreated. `after` defaults to `0`.
- The proof-of-work replay cache is kept in memory only. A request rejected for a full queue
  consumes its proof of work, so one proof buys one answer.
- Hex fields are lowercase only; percent-escapes in envelope fields are uppercase only.
- State is stored in `server-v2.state` inside the data directory and replaced atomically
  (unique temporary name, `create_new`, mode 0600 on unix; one writer at a time).
- HTTP limits: request headers must arrive within 10 s; a small body within 10 s; blob and sealed
  bodies within 60 s and at no less than 4096 B/s after a 10 s grace. When the connection cap
  (256) is reached, the oldest connection that has not finished its headers is closed first, so
  idle sockets cannot lock out clients. There are no per-IP limits (clients sit behind a
  terminator or Tor).
  An unreadable state file stops the server instead of being replaced.
- The server itself speaks plain HTTP and must sit behind a TLS terminator (Cloudflare tunnel,
  reverse proxy) when reachable from outside the machine; clients refuse `http://` to public hosts.
- Section 11 entry points are named `*_with` and take the random bytes explicitly.
- State file magic is `AEGSRV04` (directory, PIN slots, prekeys, queues); `AEGSRV02` and
  `AEGSRV03` files are still read. Prekey table limit (section 27.1): `max_prekey_users`,
  default as many as directory entries. `prekeys/put` with a `spk_ts` that is older than the
  stored one, or equal with a different `spk`/`spk_sig`, gets `409`; other rule failures `403`; unknown user `404`.
- The blob quota (section 14) is set with `aegis-serverd --blob-quota-mib <MiB>` (default 4096).

## 13. Attachments (photos and videos)

Only two kinds exist: `image` (always JPEG after sanitizing, section 16) and `video`
(MP4/MOV after sanitizing). Nothing is sent unless sanitizing succeeded; the original file
is never uploaded and its file name is never sent.

Upload, for sanitized bytes `m` (at most 31 MiB):

```
key     = 32 random bytes
padded  = BE64(len(m)) || m || zeros     // total = smallest power of two ≥ 65536 that fits
n       = ceil(len(padded) / 1048576)    // chunks of 1 MiB, last one may be shorter; n ≤ 32
chunk_i = AEAD(key, nonce = 0^8 || BE32(i), aad = "aegis-v2 blob" || BE32(i) || BE32(n), padded[i MiB ..])
id_i    = 32 random bytes                // ids are unrelated to each other
```

Each `chunk_i` is uploaded with `POST /api/v2/blob/put` (section 14). Receivers fetch all
chunks, decrypt them in order, check `BE64` length and `SHA256(m)` against the descriptor and
check the magic bytes: `image` must start with `FF D8 FF`, `video` must have `ftyp` at
offset 4. Anything else is dropped. The receiver decides the media type from `kind`, never
from data supplied by the sender.

Descriptor: new envelope types `dmf` (frame `0x01`), `gmf` (frame `0x02`, group queue) and
`cmf` (frame `0x02`, channel queue). All other envelope fields are as for `dm`/`gmsg`/`cmsg`.
`body` holds these lines joined by `\n` (the whole body is percent-encoded as usual):

```
0 AT1
1 kind        image | video
2 size        len(m), decimal
3 sha256      hex SHA256(m)
4 key         hex key
5 width       decimal pixels
6 height      decimal pixels
7 duration_ms decimal, 0 for image
8 ids         comma-separated hex ids, in chunk order
9 caption     text, may be empty
```

Bounds, checked by sender and receiver: width and height at most 16384; duration_ms at most
86400000; caption at most 1024 characters with no control characters (so no `\n`), no bidi
controls (U+202A to U+202E, U+2066 to U+2069) and no zero-width characters (U+200B to U+200F,
U+2060 to U+2064, U+FEFF) or other hidden format character (U+00AD, U+061C, U+180E, U+2028, U+2029,
U+206A to U+206F, U+FFF9 to U+FFFB, U+E0000 to U+E007F). A descriptor outside these bounds is dropped like any malformed envelope.

Exactly 10 lines. `n` must match `ceil((padded size)/1 MiB)` for the padded size implied by `size`.
Clients that do not know a type drop the frame like any malformed envelope.

Local storage of attachments: the vault holds a random 32-byte `media_key`. Each received or
sent attachment is stored next to the vault as `<vault name>.media/<32 hex random>.bin` =
`nonce(12) || AEAD(media_key, nonce, aad = "aegis-v2 media", m)`. Deleting a message
(including disappearing messages) deletes its file.

## 14. Blob store (server)

- `POST /api/v2/blob/put?id=<hex64>&ts=<unix>&pow=<u64>`, body `application/octet-stream`,
  raw bytes, 1 ≤ length ≤ 1048592 (1 MiB + tag). Proof of work as in section 4 with
  `scope = "blob:" || id` and `body_hash` = hex SHA-256 of the body. → `200 {}`.
  Existing id → `409`. Store over quota → `503`.
- `GET /api/v2/blob/get?id=<hex64>` → `200` raw bytes, `Content-Type: application/octet-stream`,
  `Cache-Control: no-store`; unknown or expired → `404`.
- Blobs are files in `blobs/` inside the data directory, written to a temp file and renamed.
  They expire 14 days after upload and are not deleted on read (several group members read
  the same blob). Total size is capped (default 4 GiB). Only the blob route accepts bodies
  over 64 KiB.
- The server learns: blob sizes (padded to powers of two), upload and download times.

## 15. Channels

A channel is a broadcast group where only the owner posts. The owner makes a random 32-byte
`G` and sends a `cinv` envelope (frame `0x01`) to each subscriber: `body` = channel title,
`group_key` = hex `G`, `members` empty. Subscribers never learn who else is subscribed.

```
channel_id = hex(SHA256("aegis-v2 channel-id" || G))
queue      = HKDF(G, "", "aegis-v2 channel-queue", 32)
k          = HKDF(G, "", "aegis-v2 channel-msg", 32)
```

Posts are `cmsg` (text) or `cmf` (attachment) envelopes, framed exactly like section 7 with
`aad = 0x02` and the Ed25519 signature over `"aegis-v2 gmsg\n" || envelope`, and `group_id` =
`channel_id`. The owner is the sender of the `cinv`. Receivers accept a post only if `sender`
equals the owner and the signature verifies against the owner's pinned key; everything else
on the channel queue is dropped. At most 200 subscribers per channel (one invite each).
Channels are not listed or searchable anywhere; joining needs an invite from the owner.

## 16. Sanitizing media before sending

Both clients must do exactly this; failure at any step means nothing is sent.

Images (input JPEG, PNG, WebP; Android also HEIC):
- Input at most 40 MiB and 50 megapixels, checked before full decode.
- Decode, apply the EXIF orientation, drop everything except pixels.
- Scale so the longer side is at most 1600 px; encode JPEG quality 80, no metadata segments.
- The output must contain no `APP1`..`APP15` segments (no Exif, XMP, ICC, maker notes).

Videos (input ISO BMFF: MP4/MOV, at most 31 MiB):
- Reject when there is no `ftyp` or `moov`, when `moof` exists (fragmented), or when any box
  size is inconsistent.
- The output has exactly the input length, so `stco`/`co64` offsets stay valid. Inside every
  container the allowed children are copied in order, and the bytes of everything else become one
  `free` box (zero payload) at the end of that container. At the top level, each run of boxes that
  are not `ftyp`, `moov` or `mdat` becomes one `free` box. A `free` box is therefore never a
  copy of a dropped box; what stays visible is the total size dropped per container (residual
  risk, accepted to keep offsets unchanged).
- Allowlist. Top level: `ftyp`, `moov`, `mdat`. `moov`: `mvhd`, `trak`. `trak`: `tkhd`, `edts`,
  `mdia`. `edts`: `elst`. `mdia`: `mdhd`, `hdlr`, `minf`. `minf`: `vmhd`, `smhd`, `dinf`, `stbl`.
  `dinf`: `dref`. `stbl`: `stsd`, `stts`, `ctts`, `cslg`, `stss`, `stsc`, `stsz`, `stco`, `co64`.
  `stsd`: sample entries, whose children are limited to `avcC`, `hvcC`, `av1C`, `vpcC`, `vvcC`,
  `esds`, `colr`, `pasp`, `clap`, `btrt`, `dac3`, `dec3`, `dOps`, `dfLa`. This removes `udta`,
  `meta`, `©xyz`, `tref`, `sgpd`, `uuid` and the like.
- `ftyp` is rewritten to major brand + minor version 0 + the compatible brands, keeping only
  `isom iso2 iso4 iso5 iso6 mp41 mp42 avc1 qt   M4V  M4A  hvc1` (a brand not on the list becomes
  the major brand; an unlisted major brand becomes `isom`).
- In kept tracks: the `hdlr` bytes after the handler type (reserved words and name) are zeroed;
  in each sample entry the visual `compressorname` (32 bytes at payload offset 42) and the visual
  version, revision, vendor and quality fields (payload bytes 8..24), or the audio vendor field
  (4 bytes at offset 12), are zeroed; a `colr` box is kept only if its colour type is `nclx` or
  `nclc` (an ICC profile can name the device and is dropped); every `dref` entry becomes a self-contained
  `url ` entry (flags 1, rest of the payload zero); a `dref` entry of another type rejects the
  video. `stsd` and `dref` entry counts must match the boxes.
- Only tracks whose `hdlr` type is `vide` or `soun` are kept. Any other track (timed metadata
  such as `mebx`, `gpmd`, `camm`, text) is dropped.
- Sample bytes: the sample ranges of every track are computed from `stsc`, `stsz`,
  `stco`/`co64`; if those tables are inconsistent or point outside the file, the video is
  rejected. Inside every `mdat`, all bytes that no kept sample covers are zeroed.
- Creation and modification times in `mvhd`, `tkhd` and `mdhd` are set to 0, and the `mdhd`
  language is set to `und`.
- `ftyp` must be the first box of the file (offset 0); otherwise the video is rejected.
- Exactly one `moov`, one `ftyp` and one `mvhd`; at most one `tkhd`, `mdia`, `hdlr`, `mdhd`,
  `minf`, `stbl` per parent. Every kept or dropped track must have `stsc`, `stsz` and `stco` or
  `co64` (`stz2` is rejected).
- At least one `vide` track must remain.

## 17. Default avatars

Generated from the identity key so that a key change also changes the avatar.

```
h     = SHA256("aegis-v2 avatar" || ed_pk)
cell(r, c) for r in 0..5, c in 0..3: on = bit (r*3 + c) of h[0..2] (bit 0 = h[0] & 1)
column 3 mirrors column 1, column 4 mirrors column 0
bg    = gray level 0x1c + h[2] % 0x18
fg    = gray level 0xa0 + h[3] % 0x50
```

Drawn as a 5×5 grid inside a circle with a margin of one cell. Grayscale only.

## 18. Search

The directory only answers exact usernames (section 3); nothing else can be searched on the
server. Search in the clients covers local chats, groups, channels and message text inside
the open vault.

## 19. Official channel

Every client has one built-in channel, "Aegis", owned by the username `owner`. Anyone can
read it; only `owner` can post. It uses section 15 framing with a public key:

```
G          = SHA256("aegis-v2 official-channel")
```

so its content is not secret, only authenticated. The owner's `ed_pk` is compiled into the
clients (`official::OFFICIAL_OWNER_ED_PK`). Clients never trust a key learned from the
directory or the server for this channel: while no key is compiled in (`None`, TODO: the author
must set the real key before release) `official::verify` fails and every official post is
dropped. Posts not signed by the compiled-in key are dropped. Other channels (section 15) can
be created by any user. Core: `official::{official_g, official_queue, official_msg_key,
verify, open_official_post, sign_post_auth}`.

Appending to the official queue needs the owner's signature on the send request, checked by the
server against its configured owner `ed_pk` (section 3): query parameter `sig` = Ed25519 over
`"aegis-v2 official-post" || queue_id (32 bytes) || BE64(ts) || SHA256(frame)` where `frame` is
the decoded padded frame. Without a configured owner key, or with a wrong or missing `sig`, the
server answers `403`. `Client::send_official(owner_ed_sk, padded)` does this. Reading stays
public. Residual risk: whoever holds the server controls what is served, but without the owner
key cannot make clients accept a forged post; a malicious server can still drop or replay old
official posts.

## 20. PIN unlock

After the first unlock with the password, a user may set a 4- or 6-digit PIN for re-opening a
locked session on the same device. The PIN alone is useless: unlocking also needs a secret
held by the server, and the server erases it after 5 wrong attempts. Then only the password
works.

Setup (client):

```
salt     = 16 random bytes                     // stored locally
T        = Argon2id(pin, salt, m = 19456 KiB, t = 2, p = 1) → 32 bytes
slot     = 32 random bytes                     // stored locally
S        = 32 random bytes                     // sent to the server, then forgotten
verifier = HKDF(T, slot, "aegis-v2 pin-verify", 32)
wrap     = HKDF(T || S, slot, "aegis-v2 pin-wrap", 32)
pin file = "AGP1" || salt || slot || nonce(12) || AEAD(wrap, nonce, aad = "AGP1" || salt || slot, vault_key)
```

`POST /api/v2/pin/create`, form body: `slot`, `v` (verifier), `s` (S), `ts`, `pow`
(section 4, `scope = "pin:" || slot`, `body_hash` = hex SHA-256 of `slot || v || s` as hex
strings joined by `\n`). Existing slot → `409`.

Unlock: `POST /api/v2/pin/open`, form body `slot`, `v`, `ts`, `pow` (same scope rule, hash of
`slot || v`). Server compares `v` in constant time. Match → `200 {"s":"<hex>"}` and the
attempt counter is reset. Mismatch → `403 {"left":N}`; after the fifth consecutive mismatch the
slot is deleted and later requests get `404`. The client then deletes the pin file and asks
for the password. Removing the PIN: `POST /api/v2/pin/delete` with `slot`, `v`, `ts`, `pow`.
Slots unused for 90 days expire.

Throttle: the server accepts one attempt per slot per second. There is no budget shared between
slots: an attacker can create any number of slots of their own, and a shared budget would let
them refuse everybody else's attempts; each wrong verifier already costs the attacker its slot's
5 tries and a proof of work, and a guess against someone else's 256-bit slot id is hopeless. A
request over the limit gets `429`; it does not count
as an attempt, does not change `left`, and its proof of work is not consumed, so the client
waits a second and sends the same request again. `left` is the number of attempts remaining
after this mismatch (4, 3, 2, 1, 0); `0` means the slot has just been deleted. A request that
fails the ts window, proof of work or form checks gets `400`/`403` and is not an attempt.
Every PIN change is written to disk before the reply, so restarting the server never resets a
counter. If the write fails the server answers `503` and takes the change back in memory too:
a refused create leaves no slot and a refused attempt is not counted. The same holds for
`prekeys/put` and for a one-time prekey handed out by `prekeys/take`.

`pin` is exactly 4 or 6 ASCII digits and is hashed as its UTF-8 bytes. `Argon2id` is version
0x13 with a 32-byte output; the cost parameters are the fixed values above (the test vector
uses smaller ones and says so). The pin file is 116 bytes; its AEAD plaintext is the 32-byte
vault key. Opening needs one Argon2 run: derive `T`, send the verifier, then wrap with `T || S`.

What this protects: a stolen device cannot be brute-forced offline, because `S` is not on it.
What it does not: the server operator together with the stolen device can try all PINs. The
server alone has no ciphertext. Each unlock tells the server that this slot was used and when.
Unlocking with a PIN needs a connection to the server; offline, use the password.

## 21. Notifications

No push service (no Google or Apple servers) is used. Clients poll.
- Android: a background job polls the inbox queue (derived from the public `x_pk`, section 6)
  and the official channel queue at most every 15 minutes while the vault is locked, and shows
  "New message" without sender or text. Group and channel queues are polled only while the vault
  is open, because their ids need the vault secrets.
- Desktop: while the app runs and the window is not focused, new messages show a system
  notification with the sender's display name; the text is hidden by default.

## 22. Profile card

Display name, an "about" line and a particle effect are shared with contacts only (the
directory keeps no display name, section 3). Envelope type `prof` (frame `0x01`), sent
to each contact when the profile changes and on first message to a new contact. `body`:

```
0 PF1
1 display name   ≤ 64 chars
2 about          ≤ 140 chars, no \n
3 particles      none | dust | snow | embers | orbit | rain
```

Parsing is strict: exactly four lines, no control characters (Unicode category Cc) in any
field, no bidi controls (U+202A to U+202E, U+2066 to U+2069) and no zero-width characters
(U+200B to U+200F, U+2060 to U+2064, U+FEFF) or other hidden format character (the list of the attachment caption rule) in name or about, name ≤ 64 and about ≤ 140 characters (code points), and a particle value outside the
list makes the whole card invalid (it is dropped, not shown as `none`). A `prof` is accepted only from a pinned
contact (same sender checks as `dm`) and only if its `ts_ms` is newer than the stored one.

Media sanitizing (section 16) is always on and cannot be disabled.

## 23. Sealed transport

Every API call (sections 3, 4, 14, 20) can be wrapped so that a TLS terminator in front of the
server (Cloudflare with the default address) sees only one path, bucketed sizes and timing:
no queue ids, usernames, blob ids or request types. Clients use it by default.

The server has a long-term X25519 key pair (`srv_sk`, `srv_pk`), generated on first start and
kept in the data directory. `GET /api/v2/key` → `{"x":"<hex srv_pk>"}`. The client pins
`srv_pk`: compiled in for the default server, first-use pinning for other servers; a changed
key stops the client with an error instead of falling back. The compiled-in key is
`net::DEFAULT_SERVER_X_PK` for `net::DEFAULT_SERVER_URL`, looked up with `net::pinned_key_for`
(`None` for any other endpoint); the key is `8e5b9b5c709ec893f16624d00d410dc697887d4dee434d5bcf5f705a35062860`. A client with a compiled-in key must compare it before it accepts any key
fetched from the server.

```
e      = fresh X25519 key pair per request
dh     = X25519(e_sk, srv_pk)              // all-zero → reject
k_req  = HKDF(dh, e_pk || srv_pk, "aegis-v2 sealed-req", 32)
k_resp = HKDF(dh, e_pk || srv_pk, "aegis-v2 sealed-resp", 32)
inner  = method || "\n" || path_and_query || "\n" || body
outer  = e_pk || AEAD(k_req, nonce = 0^12, aad = "aegis-v2 sealed-req" || e_pk, pad(inner))
```

`POST /api/v2/s` with body `outer` (octet-stream). The server decrypts, runs the inner request
exactly as if it had arrived directly (same limits, proof of work, status codes), and replies
`200` with `rn || AEAD(k_resp, nonce = rn, aad = "aegis-v2 sealed-resp", pad(BE16(status) || body))`,
where `rn` is 12 fresh random bytes sent in front of the ciphertext (the response is 12 bytes longer
than the bucket + 16).
Undecryptable requests get `400` with no body. The body limit is the largest bucket + 32 + 16;
the inner request may not be `/api/v2/s` (sealed `400`). `pad` is `BE32(len) || data || zeros` to the
smallest bucket in `[1024, 4096, 16384, 65536, 262144, 1048576, 1114112]`.
Each `e` is used once, so the fixed request nonce is safe; the response nonce is random because
`k_resp` is a function of `e_pk` alone and a replayed outer request would otherwise reuse the
keystream. The method line may carry the client clock: `method SP ts` with `ts` in decimal Unix seconds (for example `GET 1700000000`); clients always send it. The server answers an empty `400` when `ts` is more than 600 s away from its own clock, and keeps the first 16 bytes of `e_pk` until `ts + 601`, so a recorded request can never run twice. A request without `ts` gets an empty `400`. Accepted keys are kept in memory, grouped by their `ts` second, at most 2048 per second, and a repeat gets an empty `400` before the inner request runs. A replay carries the same `ts`, so only that second is searched; when one second is full, further requests stamped with it get an empty `400`, while the next second, which honest clients move on to, is unaffected. Nothing is dropped early. The set is not persisted: for up to 600 s after a server restart a recorded request can run once more. The inner request carries no cookies or identifying headers. Responses to `POST
/api/v2/nop` (section 26) are padded like any other response of the same body length.

The key is stored in `server-x25519.key` (32 raw bytes, created atomically with owner-only
permissions where the platform has them). An unreadable or wrongly sized key file stops the
server; it is never regenerated.

What this hides from the TLS terminator: everything except the client IP, sizes (bucketed),
timing and the fact that Aegis is used. To hide the IP as well, use Tor (section 24).

## 24. Tor

- The server can be published as a Tor onion service (the server listens on 127.0.0.1; the
  operator adds a `HiddenServiceDir`/`HiddenServicePort` to their torrc). Clients accept
  `http://<56 chars>.onion` endpoints; the onion address authenticates the server.
- Desktop and Android include a Tor client (desktop: Arti; Android: the Guardian Project
  Tor library). Setting "Connect through Tor" sends all traffic through it; with an onion
  endpoint neither Cloudflare nor the server operator learns the client IP.
- An external SOCKS5 proxy (section 10) remains available.

## 25. Traffic shape and device hardening

- Polling runs on a fixed interval with ±30% random jitter whether or not anything is
  expected, and outgoing messages are delayed by a random 0–2 s, so timing says less about who
  talks to whom.
- Screen capture is blocked (Android `FLAG_SECURE`, which also hides the app in Recents; Windows
  `WDA_EXCLUDEFROMCAPTURE`), on by default.
- Android text fields ask the keyboard not to learn (`IME_FLAG_NO_PERSONALIZED_LEARNING`).
- Duress PIN (optional): a second PIN that, when entered on the lock screen, deletes the vault,
  the pin file and the media folder on this device, then shows the normal "wrong PIN" result.
  It cannot remove copies already exported or messages held by other people. The duress PIN has
  no server slot. It is kept locally as `"AGD1" || salt(16) || slot(32) || verifier(32)` with
  the same Argon2id and verifier derivation as section 20; the lock screen checks it first and
  must refuse a duress PIN equal to the real one at setup. The record can be tested offline against
every PIN by whoever holds the device files, so an attacker who has them can learn the duress PIN and
avoid it. This is accepted: the real PIN stays behind the server slot (five tries online), so the
record only costs the user the wipe, and the record has to be checkable on a locked device without
the network. The cost per guess is the same Argon2id as the vault's.
- Auto-lock after a chosen idle time drops all key material from memory.

## 26. Cover traffic

Goal: an observer of the client's connection (ISP, TLS terminator, Tor guard) sees requests at
a rate that does not depend on whether the user is reading, writing or idle.

While the app is unlocked and in the foreground, the client sends sealed requests (section 23)
on a schedule of slots with exponentially distributed gaps (mean 20 s on desktop, 30 s on
Android; minimum 2 s). A gap is `2 s + Exp(mean - 2 s)`, so the minimum holds and the mean is
exact. Each slot carries exactly one request:

1. the oldest queued real request (send, blob put/get, profile, channel post), if any;
2. otherwise a due poll (polls are scheduled into slots instead of running on their own timer);
3. otherwise a dummy request.

Real requests are not sent outside slots, except a user-visible action that would otherwise
wait more than 2 s: it takes the next slot early and the slot after it is skipped, so the
average rate stays the same. When the queue holds more than one request, slots run at the
2 s minimum until it is empty.

Dummy request: inner `POST /api/v2/nop` with body `BE32(resp_len) || random bytes`. The body
length is drawn from the sizes of the last 16 real requests (1024 bytes if none), so the
sealed request lands in the same bucket mix. `resp_len` is drawn the same way from the last
16 real response sizes, capped at 1048592 bytes, the largest real response (a blob chunk),
whatever the size of the request (`cover::max_resp_len`; the server answers `400` above that). A
body-less `GET` for a blob or a large poll page has the smallest request bucket and the largest
response bucket, so a dummy must be able to ask for the same. A dummy request body is at most 64 KiB.
The server checks only the length field and answers `200` with `resp_len` filler bytes, so the
sealed response has the same size as a real one. The
server writes no log line. Filler bytes come from one budget for the whole server
(`nop_bytes_per_sec`, default 8 MiB per second, at most 4 seconds' worth saved up); a dummy
the budget cannot cover gets `429 {"error":"busy"}`, which clients ignore like any dummy
failure. Clients record the real response sizes as the length of the JSON body the server
sent (rebuilt from the parsed answer), not an estimate.

Settings → Connection → Cover traffic: Off, Standard (above, default), High (mean 8 s on
desktop, 12 s on Android). Cover traffic stops when the app is locked or in the background; the
background poll of section 21 still runs on its own jittered timer.

Cost at Standard: about 180 requests per hour on desktop, about 1–2 MB per hour.

Client notes. `aegis_core::cover::Scheduler` is a pure state machine: the app calls `tick` when a
slot is due and gets back what to send. An early slot (a user action) displaces the next regular
slot, which is then skipped, and the gap after it is drawn as usual. Dummy sizes are inner body
lengths (the sealed padding then picks the bucket); with no real requests seen yet the request is
1024 bytes and the response length is 1024. `Client::nop(req_len, resp_len)` sends the dummy.

Limits. This hides activity inside a session, not the session itself: an observer still sees
when the app is open. It does not defeat an adversary who watches both ends and can delay or
drop traffic. Combine it with Tor (section 24) to hide the IP.

## 27. Sessions with forward secrecy (X3DH and Double Ratchet)

Direct messages, group and channel invites, sender keys, profile cards and attachment
descriptors between two users travel inside a pairwise session. A stolen identity key does
not decrypt past messages, and a session heals after a key compromise once both sides have
sent again. This follows the Signal X3DH and Double Ratchet specifications; only the
encodings and labels below are ours. Frame type 0x01 is still accepted on receive and is
never sent.

### 27.1 Prekeys (server)

Each user keeps a signed prekey `spk` (X25519, rotated every 7 days, the old secret kept 14 more
days) and up to 100 one-time prekeys `opk` (X25519, refilled to 50 when fewer than 10 remain).

```
spk_sig = Ed25519(ed_sk, "aegis-v2 spk\n" || hex(spk_pk) || "\n" || spk_ts)
```

`POST /api/v2/prekeys/put`, form fields `u`, `spk`, `spk_ts`, `spk_sig`, `opks`
(comma-separated hex, may be empty, at most 100), `ts`, `sig`, each exactly once. `sig` is
Ed25519 by the directory `ed` of `u` over
`"aegis-v2 prekeys\n" || u || "\n" || spk || "\n" || spk_ts || "\n" || spk_sig || "\n" || opks || "\n" || ts`.
Rules: `|ts − now| ≤ 600`; the signed message is remembered for 20 minutes and a repeat is
rejected; `spk_sig` must be valid; `spk_ts` must be no more than 600 s in the future and newer
than the stored one, or equal to it with `spk` and `spk_sig` identical to the stored ones (so a
client can refill `opks` without rotating; an equal `spk_ts` with a different `spk` gets `409`).
Rate limit per user: at most one accepted `put` per 60 s and at most 5 per rolling hour,
otherwise `429` (kept in memory only; `prekey_put_interval_secs`, `prekey_puts_per_hour`).
The server replaces the stored `spk` and appends the `opks` (duplicates
ignored, total capped at 100, oldest dropped). Response `200 {"opks":N}` with the number now
stored.

`POST /api/v2/prekeys/take`, form fields `u`, `ts`, `pow`, where `pow` is the proof of work of
section 4 with `scope = "pk:" || u` and `body_hash` = hex SHA-256 of `u || "\n" || ts`.
Response `200 {"spk":…,"spk_ts":…,"spk_sig":…,"opk":"<hex or empty>"}`; the returned `opk` is
deleted from the server. `404` for an unknown user or one with no `spk`. An optional fifth field
`ed` (hex) names the key the caller has pinned for `u`; if present and not equal to the
directory key the answer is `404`. A hidden user (section 29.4) gets `404` unless `ed` is given
and matches, so existing contacts keep working while strangers see "not found". A `put` for an
unknown user answers `403` like a bad signature, so it does not tell a hidden name apart. The proof of work
makes draining someone's one-time prekeys expensive. Without an `opk` the handshake still
works, with weaker replay protection for the first message.

Prekey records live in the server state file next to the directory.

### 27.2 Handshake

Initiator `A`, responder `B`. `A` fetches B's prekeys, checks `spk_sig` against B's pinned
`ed_pk` and that `spk_ts` is within the last 21 days (`SPK_ROTATE_SECS + SPK_KEEP_SECS`, as long as the secret is kept), and refuses otherwise.

```
EK   = fresh X25519 key pair
DH1  = X25519(A.x_sk, B.spk)
DH2  = X25519(EK_sk, B.x_pk)
DH3  = X25519(EK_sk, B.spk)
DH4  = X25519(EK_sk, B.opk)                       // omitted when there is no opk
SK   = HKDF(0xFF*32 || DH1 || DH2 || DH3 || DH4, salt = 0^32, "aegis-v2 x3dh", 32)
AD   = A.ed_pk || A.x_pk || B.ed_pk || B.x_pk     // 128 bytes, initiator first
```

Any all-zero DH result aborts. Both sides erase `EK_sk` and the DH outputs as soon as `SK` is
computed. B erases the used `opk` secret after the first frame of the session decrypts.

### 27.3 Double Ratchet

```
KDF_RK(rk, dh)  = HKDF(dh, salt = rk, "aegis-v2 ratchet", 64)   → rk' (first 32), ck (last 32)
KDF_CK(ck)      = mk = HMAC-SHA256(ck, 0x01), ck' = HMAC-SHA256(ck, 0x02)
msg_keys(mk)    = HKDF(mk, salt = 0^32, "aegis-v2 msg-key", 44)  → key (32) || nonce (12)
header          = dh_pk (32) || BE32(pn) || BE32(n)               // 40 bytes
ratchet_msg     = header || AEAD(key, nonce, aad = AD || header, envelope)
```

Initial state. A: `DHs` = fresh key pair, `DHr = B.spk`, `(rk, CKs) = KDF_RK(SK, X25519(DHs_sk, B.spk))`.
B: `DHs` = the spk key pair, `rk = SK`, no chains until the first message arrives.
From there the Double Ratchet algorithm runs unchanged (RatchetEncrypt, RatchetDecrypt,
DHRatchet, skipped message keys). An all-zero DH output is rejected. Limits: at most 1000
skipped keys per step and 2000 per session; skipped keys are deleted after 30 days; a message
that would need more is dropped. Decryption works on a copy of the state, which replaces the
stored state only when the AEAD check succeeds.

State is written to the vault before a sent frame leaves the device and after a received
frame is processed. The poll cursor moves past a frame only after that write.

### 27.4 Frames

Every session frame is frame type `0x03`, sent to the recipient's inbox queue (section 6) with
the same sealed-sender construction as section 6, using `0x03` in place of `0x01` in both aads.
The server sees the recipient's inbox, as before, and nothing about the sender, the session or
whether this is the first message. The inner plaintext of `c2` is one of:

- `0x00 || EK_pk (32) || spk_pk (32) || opk_pk (32, zeros when none) || ratchet_msg`: start.
- `0x01 || ratchet_msg`: message on an existing session.

The recipient first opens `c1` to get `S.x_pk` and finds the pinned contact with that key (an
unknown sender is looked up and pinned as in section 6). For a start it recomputes SK from the
referenced prekeys; an unknown `spk_pk` or an `opk_pk` it does not hold drops the frame. For a
message it tries the sessions held for that contact, newest first. After decryption,
`sender_ed` and `sender` in the envelope must match that contact.

All frames are padded as in section 4. The envelope rules of section 5 still apply, including
`msg_id` deduplication.

### 27.5 Session lifecycle

- A sends starts until it receives any message from B on that session, then switches to
  messages. Each start repeats the same `EK`/prekey triple with a fresh ratchet message.
- Each client remembers the last 1000 `EK_pk` values it has accepted, and per contact the last
  64. A start with a known `EK_pk` is handled on the existing session for it and never resets
  that session. This stops replayed starts.
- A ratchet message (in a start or a message frame) whose DH key is a receiving chain the
  client holds or held, at a counter whose key is already spent and not among the skipped
  keys, is a replay: it is ignored without a state change and does not count toward recovery.
  Per contact the client keeps the final counter of the last 256 receiving chains it left
  behind (by a DH step or by deleting a session).
- A start with a new `EK_pk` from a pinned contact creates a new session. That session becomes
  the one used for sending. Older sessions are kept for receiving until 30 days after they last decrypted a message (or were superseded, if never), then deleted.
- If both sides start at the same time, both sessions are kept for receiving. For sending, both
  use the one whose `EK_pk` is bytewise smaller.
- Recovery: after 3 frames from a pinned contact whose sealed sender verifies but whose ratchet
  message does not decrypt on any held session (for example after the peer restored an old
  vault export), the client starts a new session with that contact. It does this at most once
  per contact per 24 hours. Messages lost before that are shown as one "Some messages could
  not be decrypted" line.
- If `prekeys/take` returns `404`, the client does not send, and shows
  "This contact needs to update the app". There is no fallback to frame type 0x01.
- A key change in the directory (section 8) blocks new sessions until the user confirms it.
- A session with no traffic for 180 days is deleted; the next message starts a new one.
- Clients publish prekeys right after registration and on every start, and refill them per
  section 27.1.

Implementation notes (`aegis_core::session::SessionStore`):

- All state is local and versioned: a ratchet is stored as `AGR1`, the whole store as `AGS2`,
  a sender chain as `AGC1` and a set of received chains as `AGK2`. `AGS1` and `AGK1` (without
  the per-contact replay state and the seen-post digests) are still read. Decoding is strict
  and a failed decode never yields partial state. A name longer than 255 bytes is an encode
  error, never truncated.
- `decrypt` returns the envelope plus actions for the app. `LookupSender{x_pk}` means no contact
  has that key yet: the app looks the sender up, calls `add_contact`, and handles the same frame
  again. `NeedsPrekeysFetch`/`StartNewSession` ask the app to call `prekeys/take` and then
  `start_session`; `UndecryptableNotice` is the "Some messages could not be decrypted" line.
- A frame whose SHA-256 is among the last 1024 accepted frames is ignored (a replay by the server
  or the network); this is in addition to the `EK_pk` and spent-counter rules above, which do
  not depend on this bounded set.
- Recovery marks the contact as needing a new start: `encrypt` then returns `NeedsPrekeys`
  until `start_session` has been called.
- Of several send sessions, the one whose `EK_pk` the store remembers as `send_ek` is used.
  Frames are returned unpadded; the caller pads them (section 4).
- `prepare_prekeys(me, u, now, server_opks)` returns the signed `prekeys/put` request. With
  `server_opks = None` it adds no one-time prekeys and the answer tells the count; the same
  `spk`/`spk_ts` is sent again, which section 27.1 allows.

## 28. Groups and channels with sender keys

Every member of a group (and the owner of a channel) has a sender chain per group:
`chain_id` (16 random bytes), `n` (starts at 0) and chain key `ck` (32 random bytes).

The chain is given to each other member as an envelope of type `skey` through the pairwise
session (section 27). Fields: `group_id`, `group_key = hex(ck)`,
`body = hex(chain_id) || ":" || n` (decimal), everything else as in section 5.

```
mk, ck'          = KDF_CK(ck)                          // section 27.3
key || nonce     = HKDF(mk, salt = 0^32, "aegis-v2 group-key", 44)
sig              = Ed25519(sender ed_sk, "aegis-v2 gmsg\n" || envelope)
hk               = HKDF(G, "", "aegis-v2 group-hdr", 32)
hdr              = hnonce (12, random) || AEAD(hk, hnonce, aad = 0x05, chain_id || BE32(n))   // 48 bytes
frame (0x05)     = 0x05 || hdr || AEAD(key, nonce, aad = 0x05 || chain_id || BE32(n), envelope || sig)
```

The header is encrypted so that the server cannot tell senders apart or count their messages.

Implementation notes (`aegis_core::senderkey`): the `skey` envelope carries the chain's current
`n` and `ck`, so a chain given later starts where the sender is, not at 0. Envelope kind `skey`
is sent only inside type 0x03 session frames; the legacy type 0x01 seal refuses it.
A channel `RecvSet` is created with the owner's `ed_pk` and accepts chains from the owner
only; a group `RecvSet` takes no owner key. A set holds at most 1000 chains (8 per sender),
and decoding rejects a larger count before reading the chains. A `SendChain` is rotated when
`needs_rotation(now, member_removed)` says so.

The signature does not cover `chain_id` or `n`, so anyone holding a chain key can re-encrypt
an old signed post at another position. Receivers therefore keep, per chain, the first 16
bytes of SHA-256(envelope || sig) for the last 2000 accepted posts, and ignore a post already
accepted on any held chain of the same sender without changing state, so the key at that
position stays for the real post. Residual gap: a post from a chain already dropped (30 days
after it was superseded) can still be replayed onto a newer chain once.

The frame goes to the group queue of section 7 (for channels, section 15). The sender
advances its chain after each message and erases `mk` and the old `ck`. Receivers advance their
copy, keep at most 2000 skipped message keys per chain for 30 days, and erase used keys. The
`sender` of the envelope must be the member who distributed that `chain_id`.

New chains: when a member is removed, every remaining member makes a new chain and
distributes it, and nobody encrypts with an old chain after that. A sender also replaces its
chain every 7 days or 1000 messages. Receivers drop an old chain 30 days after a newer one from
the same sender arrives. A removed member can still read the queue but cannot decrypt anything
sent under the new chains. To also hide traffic volume from it, the creator can move the group
to a new `G` with a fresh `ginv`.

Channels use the same scheme with the owner as the only sender. When a subscriber leaves,
the owner makes a new chain.

The official channel (section 19) keeps the static key of section 15. It is public
broadcast content with no subscriber list.

Limits: the server still sees which queues are active and when. A removed member who still
holds `G` can read headers (who sends how often) but not content. Sender keys give forward
secrecy per chain step, but no post-compromise security until the next chain rotation.

Implementations expose deterministic variants (`*_with` taking the ephemeral keys and random
values as arguments) so that X3DH, ratchet steps and group frames have test vectors.

## 29. Invites and hidden profiles

A one-time invite lets two people connect without a directory lookup. The inviter makes a
random 32-byte secret `s` and shares it as a link or QR code:

```
link   = "aegis://invite/" || hex(s)                 // 64 lowercase hex digits
id     = SHA256("aegis-v2 invite-id" || s)
k      = HKDF(s, salt = "", "aegis-v2 invite-key", 32)
plain  = "AIV1
" || u || "
" || hex(x_pk) || "
" || hex(ed_pk), zero-padded to 160 bytes
box    = AEAD(k, nonce = 0^12, aad = id, plain)       // 176 bytes
```

The fixed nonce is safe because `k` seals exactly one message. Parsers accept the link with
surrounding white space and in any letter case, and nothing else. The padding hides the
length of the username.

### 29.1 Server

`POST /api/v2/invite/create`, form fields `u`, `id`, `box`, `ts`, `sig`, each exactly once.
`sig` is Ed25519 by the directory `ed` of `u` over
`"aegis-v2 invite
" || u || "
" || id || "
" || box || "
" || ts` (hex fields lowercase).
Rules: `|ts − now| ≤ 600`, the signed message is remembered for 20 minutes and a repeat gets
`403`; an unknown `u` gets `403` like a bad signature; a known `id` gets `409`. Each user may
create at most 10 invites in any 7 days (`429`); the count is kept per user and day in memory
only and is never linked to the invites. The server stores only `id → (exp, box)` with
`exp = now + 7 days`, rounded up to the hour. It never stores `s` or the creator.

`POST /api/v2/invite/redeem`, form `id=<hex>`. `200 {"box":…}` once, and the record is deleted
in the same durable write. Unknown, already used and expired ids all answer the same `404`.
Expired records are dropped by the periodic purge.

`POST /api/v2/invite/revoke`, form `id=<hex>`. Deletes the record if it exists; always `200`.
A revoked invite still counts towards the creator's limit until its day falls out of the window.

Redeeming or creating an invite never registers, reserves or transfers a username.

### 29.2 Redeeming

The redeemer derives `id`, calls `redeem`, opens `box` with `k` (a box that does not open, or
whose plaintext is not exactly the format above, is refused) and pins `u`, `x_pk`, `ed_pk` as a
contact without asking the directory. It fetches prekeys with `ed` set (section 27.1), so this
works for a hidden inviter too.

### 29.3 Accepting

The redeemer then sends the inviter an envelope of type `iacc` (frame `0x01`, section 6) with
empty `group_id`, `group_key` and `members` and

```
tag  = HKDF(s, salt = "", "aegis-v2 invite-accept
" || u_r || "
" || hex(x_r) || "
" || hex(ed_r), 32)
sig  = Ed25519(ed_r_sk, "aegis-v2 invite-accept-sig
" || u_r || "
" || hex(x_r) || "
" || hex(tag))
body = hex(tag || sig)                                   // 192 hex digits
```

where `u_r`, `x_r`, `ed_r` are the redeemer's username and keys (`x_r` is the sender key proved
by the seal, `ed_r` is `sender_ed`). The inviter keeps its open secrets locally until they
expire or are used. An `iacc` from an unknown sender is accepted only if the tag matches one of
those secrets and the signature checks; the inviter then pins the sender without a directory
lookup and forgets that secret. Any other `iacc` is dropped. Display name and avatar follow in
the usual `prof` envelope.

### 29.4 Hidden profile

`POST /api/v2/dir/hide`, form fields `u`, `hidden` (`0` or `1`), `ts`, `sig`, with `sig` by the
directory `ed` of `u` over `"aegis-v2 hide
" || u || "
" || hidden || "
" || ts`. Same time
window and replay rules as above; an unknown `u` gets `403` like a bad signature. The flag is
kept in the state file and survives re-registration. Default off.

While on, `dir/lookup` for `u` answers the same `404` as an unknown name and `prekeys/take`
without the matching `ed` answers `404`. Queues are addressed by key, so existing contacts keep
working. A stranger can still learn that the name is taken by trying to register it (`409`),
because names stay unique.

### 29.5 Group membership

The server has no route that lists group members or answers whether a user is in a group.
Groups are only queues derived from `G` (section 7); membership is known only to members,
carried inside `ginv` and `skey` envelopes. A non-member cannot even name the group's queue
without `G`.
