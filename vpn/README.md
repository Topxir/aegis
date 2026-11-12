# Aegis VPN node

Stage 1 of the built-in VPN: a WireGuard node with a free tier. Untested on a real server yet.

| Per client (defaults) | |
|---|---|
| Speed | 200 KB/s each direction (`FREE_RATE_KBYTES`) |
| Simultaneous connections | 64 (`FREE_MAX_CONNS`) |
| Traffic | 2048 MB per calendar month (`FREE_QUOTA_MB`) |
| Clients on the node | 2000 at once (`MAX_PEERS`) |

What the node keeps, all in RAM (`/run`, kernel memory), gone after a reboot:

- WireGuard peers: client public key, tunnel address, and the client's current IP and port
  (WireGuard needs it to send replies).
- Connection tracking: which tunnel address talks to which server, while the connection is open.
- Per key: a hash of the key, the month, bytes used this month.

Nothing about clients is written to disk: `SaveConfig = false`, journald in RAM, rsyslog off,
no DNS resolver on the node.

Limits of this stage: the quota is per key, so a client can get a new quota with a new key.
Reboots reset quotas. Both go away once aegis-server issues per-account tokens (stage 2).

## Install on Oracle Cloud Always Free

1. Create an Ampere A1 instance (Ubuntu 22.04 or 24.04).
2. In the VCN security list, add an ingress rule: UDP, port 51820, source `0.0.0.0/0`.
3. Copy this folder to the server and run:

   ```bash
   sudo VPN_ENDPOINT=<public-ip>:51820 bash node/setup-node.sh
   ```

Do not enable VCN Flow Logs: they record client IPs on Oracle's side. Re-running the setup
restarts `wg0` and disconnects everyone; quota state in `/run` survives it.

## Manual test

On a laptop with WireGuard installed:

```bash
wg genkey | tee client.key | wg pubkey
```

On the server, with the printed public key:

```bash
sudo aegis-vpn-peer add <client-public-key>
```

Put the printed config into the WireGuard client, replacing `PrivateKey` with the contents of
`client.key`, and connect. Then check:

- `ip link show wg0` reports `mtu 1420`;
- a speed test shows about 1.6 Mbit/s down and up;
- `sudo aegis-vpn-peer stats` shows 1 connected;
- `ls /etc/wireguard` has only `wg0.conf` without `[Peer]`, and `journalctl --disk-usage`
  reports no archived journals on disk;
- after 15 minutes disconnected the peer disappears from `sudo wg show`.

## Русский

Первый этап встроенного VPN: нода WireGuard с бесплатным тарифом. Лимиты на клиента: 200 КБ/с,
64 соединения, 2 ГБ в месяц, на ноде до 2000 клиентов одновременно. Всё о клиентах хранится
только в оперативной памяти и стирается при перезагрузке. Установка и проверка описаны выше.
