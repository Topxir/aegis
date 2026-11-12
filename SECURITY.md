# Security policy

Aegis is an unaudited alpha. Do not rely on it where a compromise would put someone at risk.

## Reporting a vulnerability

Do not open a public issue. Use GitHub's private reporting: **Security → Report a vulnerability**.
A pseudonymous account is fine. Include the affected component, steps to reproduce, impact and version.

We acknowledge reports within 7 days and credit the reporter only if they ask for it.

## In scope

Cryptography and protocol (`docs/PROTOCOL.md`), key and vault storage, metadata leaks to the
server or network, desktop UI injection (HTML/JS), Android app isolation, server denial of service.

## Known limitations

- No forward secrecy: a stolen identity key decrypts previously captured traffic.
- The server sees which queue receives frames and when, and the username → public key directory.
- With the default server, Cloudflare terminates TLS and sees client IP addresses.
- The Android release build is signed with a debug key.
