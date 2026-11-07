@echo off
REM Starts aegis-serverd on 127.0.0.1:8443 and exposes it through a Cloudflare Tunnel.
REM Server data is stored in %APPDATA%\Aegis\server unless --data-dir is given.
REM Public key of the official channel owner; only this key may register "owner" and post.
if not defined AEGIS_OWNER_ED_PK set AEGIS_OWNER_ED_PK=9b714d3e9f6b7d248a15c7302d3b1ff391ca416c98ccc935bb4349f00eec5884
start "" /B "%~dp0aegis-serverd.exe" --bind=127.0.0.1 --port=8443 --data-dir="%APPDATA%\Aegis\server"
REM Onion service: same server over Tor, address in %USERPROFILE%\.aegis-tools\tor\onion\hostname.
if exist "%USERPROFILE%\.aegis-tools\tor\tor\tor.exe" start "" /B "%USERPROFILE%\.aegis-tools\tor\tor\tor.exe" -f "%USERPROFILE%\.aegis-tools\tor\torrc"
if exist "%USERPROFILE%\.cloudflared\aegis-tunnel.yml" (
    start "" /B cloudflared tunnel --config "%USERPROFILE%\.cloudflared\aegis-tunnel.yml" run
) else (
    cloudflared tunnel --url http://127.0.0.1:8443
)
