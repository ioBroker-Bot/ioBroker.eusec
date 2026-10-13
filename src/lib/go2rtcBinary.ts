import { createHash } from 'node:crypto';
import { promises as fs } from 'node:fs';
import * as path from 'node:path';
import { inflateRawSync } from 'node:zlib';

/**
 * Provides the go2rtc binary from the upstream release.
 *
 * go2rtc-static stops at go2rtc 1.9.4, whose exec source calls cmd.Wait() twice when a stream
 * stops: if the wrong caller loses that race, it keeps the producer locked, and the stream - the
 * transcoded compatibility stream above all - answers no viewer anymore until go2rtc restarts.
 * Fixed upstream in 1.9.9 ("Rewrite exec handler"), so the adapter downloads a pinned release
 * once and keeps go2rtc-static only as the fallback for hosts that cannot reach GitHub.
 *
 * Deliberately free of adapter imports, so it stays testable without a running js-controller.
 */

export const GO2RTC_VERSION = '1.9.14';

export interface Go2rtcAsset {
    /** File name of the release asset. */
    name: string;
    /** SHA-256 of the asset as GitHub lists it for the release. */
    sha256: string;
}

const asset = (name: string, sha256: string): Go2rtcAsset => ({ name, sha256 });

/** Release assets of GO2RTC_VERSION by `<platform>-<arch>` of Node.js. */
const ASSETS: Record<string, Go2rtcAsset> = {
    'linux-x64': asset('go2rtc_linux_amd64', '32d616af226bd731678ffde328b94cfb94e30339bfefc469cfb76323144615a6'),
    'linux-arm64': asset('go2rtc_linux_arm64', '359fabade8a7a51e81a55fe6df6b0ef81764a5e1d63179577534eaaa71904b50'),
    'linux-arm': asset('go2rtc_linux_arm', '4d7e1639af5a2722a28e864468fd8099b3c1682565446c798bf9e3b38fde12e4'),
    'linux-armv6': asset('go2rtc_linux_armv6', '4dc20370556b29f3a90f4c7a09dcd95472c8f74cca56d4d1fb91f32bdd15174c'),
    'linux-ia32': asset('go2rtc_linux_i386', '12a114d19fc9fba1b3541cf7c6bb9b01896a6845f31285ec77269e2e7c613885'),
    'linux-mipsel': asset('go2rtc_linux_mipsel', '38156ffbd0e0d72674939b9d86f396f2388911418f2b0fc085eafc534f2503fb'),
    'win32-x64': asset('go2rtc_win64.zip', 'dd4167d75cb04abe618855b7c71f8658bd009f60c1a71835d134d2c11c939907'),
    'win32-ia32': asset('go2rtc_win32.zip', '6fafb817477f4d34e5edfd8bb3c547151dfc5c404bde41e274db146b17ed5c03'),
    'win32-arm64': asset('go2rtc_win_arm64.zip', '814be0f6d8669025c7bccdd1f026ffaf613abae5352239f4ec84de543b94594a'),
    'darwin-x64': asset('go2rtc_mac_amd64.zip', '9b0b9a27a4dc3a5b8b93376e7e8fc2787c6af624a512842622be84aec0171c7a'),
    'darwin-arm64': asset('go2rtc_mac_arm64.zip', '919b78adc759d6b3883d1e1b2ac915ac0985bb903ff1897b4d228527bd64690c'),
    'freebsd-x64': asset(
        'go2rtc_freebsd_amd64.zip',
        '99c0a534a485b385c57a5809b992a0cb5058e448cfbe44d1880a354fa1053174',
    ),
    'freebsd-arm64': asset(
        'go2rtc_freebsd_arm64.zip',
        'a2b0666a38c75ac84ea5814af31d875521832b67370270aa586e5845c628cf3f',
    ),
};

/** The largest asset is about 7.4 MB - anything far beyond is not the release. */
const MAX_DOWNLOAD = 64 * 1024 * 1024;
const DOWNLOAD_TIMEOUT = 120000;

/**
 * Picks the release asset for a host.
 *
 * @param platform process.platform
 * @param arch process.arch
 * @param armVersion process.config.variables.arm_version - 6 on a Raspberry Pi Zero or 1
 * @returns The asset, or undefined if the release has none for the host
 */
export const go2rtcAsset = (platform: string, arch: string, armVersion?: string): Go2rtcAsset | undefined =>
    ASSETS[`${platform}-${arch === 'arm' && armVersion === '6' ? 'armv6' : arch}`];

/**
 * Extracts one file from a zip archive, as the Windows, macOS and FreeBSD assets come. Only reads
 * what these archives use: stored or deflated entries, no ZIP64.
 *
 * @param zip The archive
 * @param name Name of the entry
 * @returns The content of the entry
 */
export const unzipFile = (zip: Buffer, name: string): Buffer => {
    // The end of central directory record is at least 22 bytes, followed by a comment.
    const end = zip.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
    if (end < 0 || end + 22 > zip.length) {
        throw new Error('not a zip archive');
    }
    const entries = zip.readUInt16LE(end + 10);
    let offset = zip.readUInt32LE(end + 16);
    for (let i = 0; i < entries; i++) {
        if (offset + 46 > zip.length || zip.readUInt32LE(offset) !== 0x02014b50) {
            throw new Error('broken zip central directory');
        }
        const method = zip.readUInt16LE(offset + 10);
        const size = zip.readUInt32LE(offset + 20);
        const nameLength = zip.readUInt16LE(offset + 28);
        const entryName = zip.toString('utf8', offset + 46, offset + 46 + nameLength);
        // Sizes are taken from the central directory: the local header holds zeros when the
        // archive was written with data descriptors, as Go does.
        const local = zip.readUInt32LE(offset + 42);
        offset += 46 + nameLength + zip.readUInt16LE(offset + 30) + zip.readUInt16LE(offset + 32);
        if (entryName !== name) {
            continue;
        }
        if (local + 30 > zip.length || zip.readUInt32LE(local) !== 0x04034b50) {
            throw new Error('broken zip entry');
        }
        const start = local + 30 + zip.readUInt16LE(local + 26) + zip.readUInt16LE(local + 28);
        const data = zip.subarray(start, start + size);
        if (method === 0) {
            return data;
        }
        if (method === 8) {
            return inflateRawSync(data);
        }
        throw new Error(`unsupported zip compression ${method}`);
    }
    throw new Error(`${name} not found in the zip archive`);
};

const downloadAsset = async (url: string): Promise<Buffer> => {
    const response = await fetch(url, { signal: AbortSignal.timeout(DOWNLOAD_TIMEOUT) });
    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }
    if (Number(response.headers.get('content-length') ?? 0) > MAX_DOWNLOAD) {
        throw new Error('download larger than expected');
    }
    return Buffer.from(await response.arrayBuffer());
};

export interface Go2rtcBinaryOptions {
    /** Directory the binary is kept in - the data directory of the instance. */
    dir: string;
    platform: string;
    arch: string;
    armVersion?: string;
    /** Fetches a URL, replaced in the tests. */
    download?: (url: string) => Promise<Buffer>;
    /** The asset to fetch instead of the one of the host, for the tests. */
    asset?: Go2rtcAsset;
    log: {
        info: (message: string) => void;
        warn: (message: string) => void;
    };
}

/**
 * Returns the go2rtc binary of GO2RTC_VERSION, downloading it on the first call. Binaries of other
 * versions in the directory are removed once the new one is in place.
 *
 * @param options Where to keep it and for which host
 * @returns Path of the binary, or undefined if there is none for the host or the download failed
 */
export const provideGo2rtc = async (options: Go2rtcBinaryOptions): Promise<string | undefined> => {
    const { dir, platform, log } = options;
    const found = options.asset ?? go2rtcAsset(platform, options.arch, options.armVersion);
    if (!found) {
        log.warn(`go2rtc ${GO2RTC_VERSION} has no release for ${platform}-${options.arch}`);
        return undefined;
    }
    const executable = platform === 'win32' ? 'go2rtc.exe' : 'go2rtc';
    const file = `go2rtc-${GO2RTC_VERSION}${platform === 'win32' ? '.exe' : ''}`;
    const target = path.join(dir, file);
    try {
        if ((await fs.stat(target)).size > 0) {
            return target;
        }
    } catch {
        // Not downloaded yet.
    }

    const url = `https://github.com/AlexxIT/go2rtc/releases/download/v${GO2RTC_VERSION}/${found.name}`;
    try {
        log.info(`Downloading go2rtc ${GO2RTC_VERSION} from ${url}`);
        const data = await (options.download ?? downloadAsset)(url);
        const sha256 = createHash('sha256').update(data).digest('hex');
        if (sha256 !== found.sha256) {
            throw new Error(`checksum ${sha256} does not match the release`);
        }
        const binary = found.name.endsWith('.zip') ? unzipFile(data, executable) : data;
        await fs.mkdir(dir, { recursive: true });
        // Written under another name first, so an interrupted write never passes as the binary.
        await fs.writeFile(`${target}.part`, binary, { mode: 0o755 });
        await fs.rename(`${target}.part`, target);
    } catch (error) {
        log.warn(`go2rtc ${GO2RTC_VERSION} could not be downloaded: ${(error as Error).message}`);
        await fs.rm(`${target}.part`, { force: true }).catch(() => {});
        return undefined;
    }

    for (const old of await fs.readdir(dir).catch(() => [])) {
        if (old.startsWith('go2rtc-') && old !== file) {
            await fs.rm(path.join(dir, old), { force: true }).catch(() => {});
        }
    }
    return target;
};
