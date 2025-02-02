@echo off
cd out\build\x64-Debug\tests

if not exist client.exe (
    echo Run build all first
    exit /b 1
)

start client.exe


