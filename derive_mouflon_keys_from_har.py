import argparse
import base64
import gzip
import io
import json
import re
from collections import Counter
from pathlib import Path

MOUFLON_URI_RE = re.compile(r'_(\d+)_([^_]+)_(\d+)(?:_part(\d+))?\.mp4$')


def _decode_content(content):
    text = content.get('text', '')
    if not text:
        return ''
    if content.get('encoding') == 'base64':
        try:
            data = base64.b64decode(text)
        except Exception:
            return ''
        try:
            return gzip.decompress(data).decode('utf-8', errors='replace')
        except Exception:
            return data.decode('utf-8', errors='replace')
    if text.strip().startswith('H4sIA'):
        try:
            data = base64.b64decode(text.strip())
            return gzip.decompress(data).decode('utf-8', errors='replace')
        except Exception:
            return text
    return text


def _pad_b64(value):
    pad_len = (4 - (len(value) % 4)) % 4
    return value + ('=' * pad_len)


def _parse_mouflon_uri(uri):
    match = MOUFLON_URI_RE.search(uri)
    if not match:
        return None
    seq = int(match.group(1))
    enc = match.group(2)
    ts = int(match.group(3))
    part = int(match.group(4)) if match.group(4) is not None else None
    return seq, enc, ts, part


def _extract_playlist(entries):
    for entry in entries:
        url = entry.get('request', {}).get('url', '')
        if '.m3u8' not in url:
            continue
        content = entry.get('response', {}).get('content', {})
        text = _decode_content(content)
        if 'MOUFLON:URI' in text:
            return url, text
    return None, None


def _extract_pkeys(playlist_text):
    pkeys = []
    for line in playlist_text.splitlines():
        if line.startswith('#EXT-X-MOUFLON:PSCH:'):
            parts = line.split(':')
            if len(parts) >= 4:
                pkeys.append(parts[3].strip())
    return [p for p in pkeys if p]


def _derive_masks(enc_dec_pairs, reverse):
    masks = Counter()
    for enc, dec in enc_dec_pairs:
        try:
            cipher = base64.b64decode(_pad_b64(enc[::-1] if reverse else enc))
        except Exception:
            continue
        plain = dec.encode('utf-8')
        mask = bytes(cb ^ pb for cb, pb in zip(cipher, plain))
        if mask:
            masks[mask.hex()] += 1
    return masks


def _decode_with_mask(enc, mask_bytes, reverse):
    cipher = base64.b64decode(_pad_b64(enc[::-1] if reverse else enc))
    out = bytearray()
    for i, cb in enumerate(cipher):
        out.append(cb ^ mask_bytes[i % len(mask_bytes)])
    return out.decode('utf-8', errors='replace')


def _merge_keys(existing, additions):
    def normalize(value):
        if isinstance(value, list):
            return [v for v in value if isinstance(v, str) and v]
        if isinstance(value, str) and value:
            return [value]
        return []

    merged = dict(existing)
    for pkey, keys in additions.items():
        combined = []
        for item in normalize(merged.get(pkey)) + normalize(keys):
            if item not in combined:
                combined.append(item)
        merged[pkey] = combined if len(combined) > 1 else combined[0]
    return merged


def main():
    parser = argparse.ArgumentParser(description='Derive MOUFLON mask keys from HAR files.')
    parser.add_argument('har_files', nargs='+', help='HAR file paths')
    parser.add_argument('--output', default='stripchat_mouflon_keys.json', help='Output JSON file')
    args = parser.parse_args()

    derived = {}

    for har_path in args.har_files:
        path = Path(har_path)
        if not path.exists():
            print(f'[WARN] Missing HAR: {har_path}')
            continue
        try:
            har = json.loads(path.read_text(encoding='utf-8-sig'))
        except Exception as exc:
            print(f'[WARN] Failed to read {har_path}: {exc}')
            continue

        entries = har.get('log', {}).get('entries', [])
        playlist_url, playlist_text = _extract_playlist(entries)
        if not playlist_text:
            print(f'[WARN] No MOUFLON playlist in {har_path}')
            continue

        pkeys = _extract_pkeys(playlist_text)
        if not pkeys:
            print(f'[WARN] No pkey in {har_path}')
            continue

        pkey = pkeys[0]
        reverse = True  # v2 playlists carry MOUFLON:URI, which needs reverse before base64

        mouflon_map = {}
        for line in playlist_text.splitlines():
            if line.startswith('#EXT-X-MOUFLON:URI:'):
                uri = line.split(':', 2)[2].strip()
                parsed = _parse_mouflon_uri(uri)
                if not parsed:
                    continue
                key = (parsed[0], parsed[2], parsed[3])
                mouflon_map[key] = parsed[1]

        first_uri = next(iter(mouflon_map.values()), None)
        if not first_uri:
            print(f'[WARN] No MOUFLON URIs in {har_path}')
            continue

        uri_example = next(
            (line.split(':', 2)[2].strip() for line in playlist_text.splitlines()
             if line.startswith('#EXT-X-MOUFLON:URI:')),
            None,
        )
        prefix = None
        if uri_example:
            parts = uri_example.split('/')
            prefix = '/'.join(parts[:5]) if len(parts) >= 5 else None

        segment_map = {}
        for entry in entries:
            url = entry.get('request', {}).get('url', '')
            if not url.endswith('.mp4'):
                continue
            if prefix and not url.startswith(prefix):
                continue
            parsed = _parse_mouflon_uri(url)
            if not parsed:
                continue
            key = (parsed[0], parsed[2], parsed[3])
            segment_map[key] = parsed[1]

        pairs = []
        for key, enc in mouflon_map.items():
            dec = segment_map.get(key)
            if dec:
                pairs.append((enc, dec))

        if not pairs:
            print(f'[WARN] No matching segments in {har_path}')
            continue

        masks = _derive_masks(pairs, reverse)
        if not masks:
            print(f'[WARN] Failed to derive mask in {har_path}')
            continue

        sorted_masks = [m for m, _ in masks.most_common()]
        new_masks = [f'mask:{m}' for m in sorted_masks]
        if pkey in derived:
            combined = []
            for item in derived[pkey] + new_masks:
                if item not in combined:
                    combined.append(item)
            derived[pkey] = combined
        else:
            derived[pkey] = new_masks

        # Verify best mask
        best_mask = bytes.fromhex(sorted_masks[0])
        matched = 0
        ok = 0
        for enc, dec in pairs:
            matched += 1
            got = _decode_with_mask(enc, best_mask, reverse)
            if got == dec:
                ok += 1

        print(f'[INFO] {har_path}: pkey={pkey} masks={len(sorted_masks)} match={ok}/{matched}')

    output_path = Path(args.output)
    existing = {}
    if output_path.exists():
        try:
            existing = json.loads(output_path.read_text(encoding='utf-8'))
        except Exception:
            existing = {}

    merged = _merge_keys(existing, derived)
    output_path.write_text(json.dumps(merged, indent=2, ensure_ascii=True), encoding='utf-8')
    print(f'[INFO] Wrote keys to {output_path}')


if __name__ == '__main__':
    main()
