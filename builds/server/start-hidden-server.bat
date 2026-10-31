@echo off
REM Запускает aegis-serverd ТОЛЬКО на локальном петлевом интерфейсе 127.0.0.1:8443
REM и пробрасывает его наружу через исходящий Anycast-туннель (Cloudflare Tunnel),
REM чтобы реальный домашний IP вашего ПК никогда не раскрывался и не открывались порты.
start "" /B "%~dp0aegis-serverd.exe" --bind=127.0.0.1 --port=8443
if exist "%USERPROFILE%\.cloudflared\aegis-tunnel.yml" (
    start "" /B cloudflared tunnel --config "%USERPROFILE%\.cloudflared\aegis-tunnel.yml" run
) else (
    cloudflared tunnel --url http://127.0.0.1:8443
)
