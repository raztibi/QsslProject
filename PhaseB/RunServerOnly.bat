@echo off
cd out\build\x64-Debug\tests

if not exist server.exe (
    echo Run build all first
    exit /b 1
)

start server.exe


