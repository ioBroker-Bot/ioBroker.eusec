import { expect } from 'chai';
import { createHash } from 'node:crypto';
import { promises as fs } from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { deflateRawSync } from 'node:zlib';

import { GO2RTC_VERSION, type Go2rtcAsset, go2rtcAsset, provideGo2rtc, unzipFile } from './go2rtcBinary';

/**
 * Builds a zip archive the way Go writes it: sizes only in the central directory, zeros in the
 * local headers (data descriptor flag), so a reader that trusts the local header gets nothing.
 *
 * @param entries Name and content of each entry
 * @param method 0 stored, 8 deflated
 * @returns The archive
 */
const makeZip = (entries: Array<[string, Buffer]>, method = 8): Buffer => {
    const locals: Buffer[] = [];
    const centrals: Buffer[] = [];
    let offset = 0;
    for (const [name, content] of entries) {
        const data = method === 8 ? deflateRawSync(content) : content;
        const nameBytes = Buffer.from(name);
        const local = Buffer.alloc(30);
        local.writeUInt32LE(0x04034b50, 0);
        local.writeUInt16LE(0x0008, 6);
        local.writeUInt16LE(method, 8);
        local.writeUInt16LE(nameBytes.length, 26);
        const central = Buffer.alloc(46);
        central.writeUInt32LE(0x02014b50, 0);
        central.writeUInt16LE(0x0008, 8);
        central.writeUInt16LE(method, 10);
        central.writeUInt32LE(data.length, 20);
        central.writeUInt32LE(content.length, 24);
        central.writeUInt16LE(nameBytes.length, 28);
        central.writeUInt32LE(offset, 42);
        locals.push(local, nameBytes, data);
        centrals.push(central, nameBytes);
        offset += 30 + nameBytes.length + data.length;
    }
    const directory = Buffer.concat(centrals);
    const end = Buffer.alloc(22);
    end.writeUInt32LE(0x06054b50, 0);
    end.writeUInt16LE(entries.length, 8);
    end.writeUInt16LE(entries.length, 10);
    end.writeUInt32LE(directory.length, 12);
    end.writeUInt32LE(offset, 16);
    return Buffer.concat([...locals, directory, end]);
};

const sha256 = (data: Buffer): string => createHash('sha256').update(data).digest('hex');

describe('go2rtcBinary => go2rtcAsset', () => {
    it('should pick the release asset of common ioBroker hosts', () => {
        expect(go2rtcAsset('linux', 'x64')?.name).to.equal('go2rtc_linux_amd64');
        expect(go2rtcAsset('linux', 'arm64')?.name).to.equal('go2rtc_linux_arm64');
        expect(go2rtcAsset('linux', 'arm', '7')?.name).to.equal('go2rtc_linux_arm');
        expect(go2rtcAsset('win32', 'x64')?.name).to.equal('go2rtc_win64.zip');
        expect(go2rtcAsset('darwin', 'arm64')?.name).to.equal('go2rtc_mac_arm64.zip');
    });

    it('should pick the ARMv6 build for a Raspberry Pi Zero or 1', () => {
        expect(go2rtcAsset('linux', 'arm', '6')?.name).to.equal('go2rtc_linux_armv6');
    });

    it('should have no asset for a host the release does not cover', () => {
        expect(go2rtcAsset('aix', 'ppc64')).to.equal(undefined);
        expect(go2rtcAsset('linux', 'riscv64')).to.equal(undefined);
        expect(go2rtcAsset('', '')).to.equal(undefined);
    });
});

describe('go2rtcBinary => unzipFile', () => {
    const binary = Buffer.from('#!binary\n'.repeat(1000));

    it('should extract a deflated entry whose sizes are only in the central directory', () => {
        const zip = makeZip([
            ['README.md', Buffer.from('readme')],
            ['go2rtc.exe', binary],
        ]);
        expect(unzipFile(zip, 'go2rtc.exe').equals(binary)).to.equal(true);
    });

    it('should extract a stored entry', () => {
        expect(unzipFile(makeZip([['go2rtc', binary]], 0), 'go2rtc').equals(binary)).to.equal(true);
    });

    it('should reject an archive without the entry', () => {
        expect(() => unzipFile(makeZip([['other', binary]]), 'go2rtc')).to.throw('go2rtc not found');
    });

    it('should reject data that is no zip archive', () => {
        expect(() => unzipFile(binary, 'go2rtc')).to.throw('not a zip archive');
        expect(() => unzipFile(Buffer.alloc(0), 'go2rtc')).to.throw('not a zip archive');
    });

    it('should reject a central directory that points outside the archive', () => {
        const zip = makeZip([['go2rtc', binary]]);
        zip.writeUInt32LE(zip.length + 100, zip.length - 6);
        expect(() => unzipFile(zip, 'go2rtc')).to.throw('broken zip central directory');
    });

    it('should reject an unsupported compression method', () => {
        const zip = makeZip([['go2rtc', binary]], 0);
        const central = zip.indexOf(Buffer.from([0x50, 0x4b, 0x01, 0x02]));
        zip.writeUInt16LE(14, central + 10);
        expect(() => unzipFile(zip, 'go2rtc')).to.throw('unsupported zip compression 14');
    });
});

describe('go2rtcBinary => provideGo2rtc', () => {
    let dir: string;
    let messages: string[];
    let downloads: string[];
    const log = {
        info: (message: string): void => void messages.push(message),
        warn: (message: string): void => void messages.push(message),
    };
    const binary = Buffer.from('go2rtc binary');

    beforeEach(async () => {
        dir = await fs.mkdtemp(path.join(os.tmpdir(), 'eusec-go2rtc-'));
        messages = [];
        downloads = [];
    });

    afterEach(async () => {
        await fs.rm(dir, { recursive: true, force: true });
    });

    const provide = (data: Buffer, asset: Go2rtcAsset, platform = 'linux'): Promise<string | undefined> =>
        provideGo2rtc({
            dir,
            platform,
            arch: 'x64',
            asset,
            log,
            download: url => {
                downloads.push(url);
                return Promise.resolve(data);
            },
        });

    it('should download a verified binary once and reuse it', async () => {
        const asset = { name: 'go2rtc_linux_amd64', sha256: sha256(binary) };
        const target = await provide(binary, asset);
        expect(target).to.equal(path.join(dir, `go2rtc-${GO2RTC_VERSION}`));
        expect((await fs.readFile(target!)).equals(binary)).to.equal(true);
        expect(downloads).to.deep.equal([
            `https://github.com/AlexxIT/go2rtc/releases/download/v${GO2RTC_VERSION}/go2rtc_linux_amd64`,
        ]);

        expect(await provide(binary, asset)).to.equal(target);
        expect(downloads).to.have.length(1);
    });

    it('should unpack the executable of a zip asset', async () => {
        const zip = makeZip([['go2rtc.exe', binary]]);
        const target = await provide(zip, { name: 'go2rtc_win64.zip', sha256: sha256(zip) }, 'win32');
        expect(target).to.equal(path.join(dir, `go2rtc-${GO2RTC_VERSION}.exe`));
        expect((await fs.readFile(target!)).equals(binary)).to.equal(true);
    });

    it('should remove the binaries of other versions, nothing else', async () => {
        await fs.writeFile(path.join(dir, 'go2rtc-1.9.9'), 'old');
        await fs.writeFile(path.join(dir, 'persistent.json'), '{}');
        await provide(binary, { name: 'go2rtc_linux_amd64', sha256: sha256(binary) });
        expect((await fs.readdir(dir)).sort()).to.deep.equal([`go2rtc-${GO2RTC_VERSION}`, 'persistent.json']);
    });

    it('should refuse a download whose checksum does not match, and keep nothing of it', async () => {
        await fs.writeFile(path.join(dir, 'go2rtc-1.9.9'), 'old');
        const target = await provide(binary, { name: 'go2rtc_linux_amd64', sha256: '0'.repeat(64) });
        expect(target).to.equal(undefined);
        expect(messages.join('\n')).to.contain('does not match the release');
        expect(await fs.readdir(dir)).to.deep.equal(['go2rtc-1.9.9']);
    });

    it('should give up when the download fails', async () => {
        const target = await provideGo2rtc({
            dir,
            platform: 'linux',
            arch: 'x64',
            log,
            download: () => Promise.reject(new Error('getaddrinfo ENOTFOUND github.com')),
        });
        expect(target).to.equal(undefined);
        expect(messages.join('\n')).to.contain('ENOTFOUND');
    });

    it('should not download anything for a host the release does not cover', async () => {
        const target = await provideGo2rtc({
            dir,
            platform: 'aix',
            arch: 'ppc64',
            log,
            download: url => {
                downloads.push(url);
                return Promise.resolve(binary);
            },
        });
        expect(target).to.equal(undefined);
        expect(downloads).to.deep.equal([]);
    });

    it('should download again when an earlier write left an empty file', async () => {
        await fs.writeFile(path.join(dir, `go2rtc-${GO2RTC_VERSION}`), '');
        const target = await provide(binary, { name: 'go2rtc_linux_amd64', sha256: sha256(binary) });
        expect((await fs.readFile(target!)).equals(binary)).to.equal(true);
        expect(downloads).to.have.length(1);
    });
});
