# slhook
Reverse engineered pso2h dll hook

## Injection
This should be able to be injected through any lazy LoadLibrary loader.
On Wine, you can simply load pso2.exe using the following flag:
```bash
WINEDLLOVERRIDES="pso2h.dll=n"
```

## Configuration
The only expected configuration is a proxy.txt file placed in the _pso2_bin_ directory
with the IP/Hostname you would like to connect to.

## Quick Note - Encryption
I've opted not to re-implement AOB scanning or hooking to crypto functions on this.
The alternative makes much more sense for custom servers; patch pso2.exe.
Within pso2.exe, patch bytes 0x05803600 (94 bytes) with your publicKey.blob.
