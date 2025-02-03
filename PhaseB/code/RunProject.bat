@echo off
cd out\build\x64-Debug\qsslBackend

if not exist server.exe (
    echo Run build all first
    exit /b 1
)

if not exist client.exe (
    echo Run build all first
    exit /b 1
)

start server.exe
timeout /t 5 /nobreak
start client.exe

timeout /t 3/nobreak

cd ..\..\..\..\qsslWPF\bin\Debug\net5.0-windows
start qsslWPF.exe