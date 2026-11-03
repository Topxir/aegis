@echo off
REM Starts aegis-serverd on 127.0.0.1:8443 and exposes it through a Cloudflare Tunnel.
REM Server data is stored in %APPDATA%\Aegis\server unless --data-dir is given.
start "" /B "%~dp0aegis-serverd.exe" --bind=127.0.0.1 --port=8443 --data-dir="%APPDATA%\Aegis\server"
if exist "%USERPROFILE%\.cloudflared\aegis-tunnel.yml" (
    start "" /B cloudflared tunnel --config "%USERPROFILE%\.cloudflared\aegis-tunnel.yml" run
) else (
    cloudflared tunnel --url http://127.0.0.1:8443
)
