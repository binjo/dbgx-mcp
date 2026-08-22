# CLAUDE.md

See [`AGENTS.md`](AGENTS.md) for full project documentation, architecture details, build/test commands, and agent guidelines.

## Quick Commands

```powershell
# Build & Deploy (x64 and x86)
powershell -ExecutionPolicy Bypass -File deploy.ps1 -Arch all -BuildType Debug

# Run C++ Unit Tests
./build/x64/unit_tests.exe

# Run Python Bridge Tests
python -m unittest tests/test_bridge.py
```
