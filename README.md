# StripchatRecorder 

All credits to @beaston02 and @ahsand97

This is script to automate the recording of public webcam shows from stripchat.com. 

## Requirements

Requires python3.5 or newer. You can grab python3.5.2 from https://www.python.org/downloads/release/python-352/

to install required modules, run:
```
python3.5 -m pip install streamlink bs4 lxml gevent
```


Edit the config file (config.conf) to point to the directory you want to record to, where your "wanted" file is located, which genders, and the interval between checks (in seconds)

Add models to the "wanted.txt" file (only one model per line). The model should match the models name in their chatrooms URL (https://stripchat.com/{modelname}/). T clarify this, it should only be the "modelname" portion, not the entire url.

## Proxy (optional)

If your server/network gets `403` / DNS errors when opening HLS URLs, set an outbound proxy:

- `config.conf` → `[settings]` → `proxy = http://127.0.0.1:3247`
- or environment variable: `SC_PROXY=http://127.0.0.1:3247`

## MOUFLON v2 keys (optional)

Some streams use MOUFLON v2 segment obfuscation. You can provide keys in
`stripchat_mouflon_keys.json` (same folder as the script) to enable decoding.

Supported formats:
- plain key string: `"<pdkey>"` (will be SHA256-hashed; also used as `pdkey` for auth)
- raw sha256 bytes: `"sha256:<hex>"` (32 bytes hex)
- derived XOR mask bytes: `"mask:<hex>"`

If you have HAR captures, you can derive masks:
```
python derive_mouflon_keys_from_har.py sc.har sc2.har sc3.har
```
