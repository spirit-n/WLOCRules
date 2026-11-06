import argparse
from hashlib import sha256
from io import BytesIO
import os
from pathlib import Path
import plistlib
import shutil
import struct
import subprocess
import tempfile
import zipfile


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify_macho(binary):
    magic, cpu, _, filetype, count = struct.unpack_from('<5I', binary)
    require((magic, cpu, filetype) == (0xfeedfacf, 0x0100000c, 2), 'Expected an arm64 Mach-O executable')
    offset = 32
    platform = signature = None
    for _ in range(count):
        command, length = struct.unpack_from('<II', binary, offset)
        if command == 0x32:
            platform = struct.unpack_from('<II', binary, offset + 8)
        if command == 0x1d:
            signature = struct.unpack_from('<II', binary, offset + 8)
        offset += length
    require(platform == (2, 0x000f0000), 'Expected an iOS executable with deployment target 15.0')
    require(signature and signature[1] and sum(signature) <= len(binary), 'Code signature missing or invalid')
    return binary[signature[0]:sum(signature)]


def verify_entitlements(signature, expected):
    magic, size, count = struct.unpack_from('>III', signature)
    require(magic == 0xfade0cc0 and size <= len(signature), 'Invalid code signature')
    slots = dict(struct.unpack_from('>II', signature, 12 + 8 * i) for i in range(count))
    require(5 in slots and 7 in slots, 'Code signature must include XML and DER entitlements')
    xml_offset = slots[5]
    magic, size = struct.unpack_from('>II', signature, xml_offset)
    require(magic == 0xfade7171 and plistlib.loads(signature[xml_offset + 8:xml_offset + size]) == expected,
            'Signed XML entitlements differ from entitlements.plist')


def build_package(ldid):
    root = Path(__file__).resolve().parent
    app = root / 'package/Payload/WLOCRules.app'
    executable = app / 'WLOCRules'
    entitlements = root / 'entitlements.plist'
    info = (app / 'Info.plist').read_bytes()
    manifest = plistlib.loads(info)
    require(manifest['CFBundleExecutable'] == executable.name and manifest['MinimumOSVersion'] == '15.0',
            'Unexpected app bundle metadata')

    with tempfile.TemporaryDirectory(prefix='wlocrules-sign-') as directory:
        signed = Path(directory) / executable.name
        signing_entitlements = signed.with_name(entitlements.name)
        shutil.copyfile(executable, signed)
        shutil.copyfile(entitlements, signing_entitlements)
        subprocess.run([ldid, f'-S{signing_entitlements}', str(signed)], check=True)
        binary = signed.read_bytes()
    verify_entitlements(verify_macho(binary), plistlib.loads(entitlements.read_bytes()))

    prefix = 'Payload/WLOCRules.app/'
    output = BytesIO()
    with zipfile.ZipFile(output, 'w') as archive:
        for name, data, mode in [('WLOCRules', binary, 0o100755), ('Info.plist', info, 0o100644)]:
            entry = zipfile.ZipInfo(prefix + name)
            entry.create_system = 3
            entry.external_attr = mode << 16
            archive.writestr(entry, data, compress_type=zipfile.ZIP_DEFLATED)
    with zipfile.ZipFile(output) as archive:
        require(archive.testzip() is None and archive.read(prefix + 'WLOCRules') == binary,
                'Package verification failed')
        require(archive.getinfo(prefix + 'WLOCRules').external_attr >> 16 == 0o100755,
                'Package executable permissions are missing')
    return output.getvalue()


def main():
    parser = argparse.ArgumentParser(description='Sign and package a built WLOCRules app for TrollStore.')
    parser.add_argument('destination', type=Path, help='Path for a new .tipa file')
    parser.add_argument('--ldid', default=os.environ.get('WLOC_LDID', 'ldid'),
                        help='Path to ldid (default: WLOC_LDID or ldid on PATH)')
    args = parser.parse_args()
    ldid = shutil.which(args.ldid)
    if not ldid:
        parser.error('ldid not found. Pass --ldid or set WLOC_LDID.')
    destination = args.destination.resolve()
    try:
        package = build_package(str(Path(ldid).resolve()))
        with destination.open('xb') as file:
            file.write(package)
    except (OSError, ValueError, struct.error, subprocess.CalledProcessError) as error:
        parser.exit(1, f'Packaging failed: {error}\n')
    print('Verified arm64 iOS 15.0 app, XML/DER entitlements and IPA contents')
    print(destination)
    print('SHA-256', sha256(package).hexdigest())


if __name__ == '__main__':
    main()
