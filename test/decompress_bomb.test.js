"use strict";

const { expect } = require("chai");
const zlib = require("zlib");
const Zip = require("../adm-zip");
const Utils = require("../util");

// Regression test for CVE-2026-39244:
// adm-zip allocated the entry output buffer from the attacker-declared
// uncompressed size (central-directory / local-header size field) before any
// validation. A tiny crafted archive could declare a ~4 GB size and force a
// matching Buffer.alloc, OOM-killing the process. The allocation must be bound
// by the data actually present in the archive, not by the declared size.

const u16 = (n) => {
    const b = Buffer.alloc(2);
    b.writeUInt16LE(n >>> 0);
    return b;
};
const u32 = (n) => {
    const b = Buffer.alloc(4);
    b.writeUInt32LE(n >>> 0);
    return b;
};

// Build a single-entry zip that declares `declaredSize` uncompressed bytes while
// only carrying `content` bytes of payload. The crc defaults to 0, which is
// deliberately wrong (alloc used to happen before the crc check); pass the real
// crc to build an entry that is valid apart from its declared size.
function craftBomb(declaredSize, method, content, crc = 0) {
    const name = Buffer.from("a");
    const lfh = Buffer.concat([
        u32(0x04034b50),
        u16(20),
        u16(0),
        u16(method),
        u16(0),
        u16(0),
        u32(crc),
        u32(content.length),
        u32(declaredSize),
        u16(name.length),
        u16(0),
        name,
        content
    ]);
    const cd = Buffer.concat([
        u32(0x02014b50),
        u16(20),
        u16(20),
        u16(0),
        u16(method),
        u16(0),
        u16(0),
        u32(crc),
        u32(content.length),
        u32(declaredSize),
        u16(name.length),
        u16(0),
        u16(0),
        u16(0),
        u16(0),
        u32(0),
        u32(0),
        name
    ]);
    const eocd = Buffer.concat([u32(0x06054b50), u16(0), u16(0), u16(1), u16(1), u32(cd.length), u32(lfh.length), u16(0)]);
    return Buffer.concat([lfh, cd, eocd]);
}

describe("decompression bomb (declared size) - CVE-2026-39244", () => {
    const DECLARED = 3 * 1024 * 1024 * 1024; // ~3 GB, far above any plausible RSS budget

    it("does not allocate the declared size for a STORED entry", () => {
        const zip = new Zip(craftBomb(DECLARED, 0 /* STORED */, Buffer.from("A")));
        const before = process.memoryUsage().rss;
        // invalid crc -> must throw, but crucially without committing gigabytes
        expect(() => zip.getEntries()[0].getData()).to.throw(/CRC32/);
        const grewMB = (process.memoryUsage().rss - before) / (1024 * 1024);
        expect(grewMB, "RSS growth must stay bounded by real data, not declared size").to.be.below(256);
    });

    it("does not allocate the declared size for a DEFLATED entry", () => {
        const zip = new Zip(craftBomb(DECLARED, 8 /* DEFLATED */, Buffer.from([0x00])));
        const before = process.memoryUsage().rss;
        // bogus deflate stream / crc -> must throw without a huge eager allocation
        expect(() => zip.getEntries()[0].getData()).to.throw();
        const grewMB = (process.memoryUsage().rss - before) / (1024 * 1024);
        expect(grewMB, "RSS growth must stay bounded by real data, not declared size").to.be.below(256);
    });

    it("still reads a legitimate STORED entry", () => {
        const zip = new Zip();
        zip.addFile("s.bin", Buffer.from([1, 2, 3, 4, 5]));
        const round = new Zip(zip.toBuffer());
        expect([...round.readFile("s.bin")]).to.eql([1, 2, 3, 4, 5]);
    });

    it("still reads a legitimate DEFLATED entry", () => {
        const zip = new Zip();
        const payload = Buffer.from("hello world ".repeat(5000));
        zip.addFile("d.txt", payload);
        const round = new Zip(zip.toBuffer());
        expect(round.readFile("d.txt").equals(payload)).to.equal(true);
    });
});

// Regression test for GHSA-c6fg-446q-cg94:
// the synchronous getData() path caps inflation at the entry's declared
// uncompressed size (zlib maxOutputLength), but the streaming inflater behind
// getDataAsync() ignores that option and decompressed without limit. A crafted
// archive declaring a tiny size (with a valid crc) was fully inflated and handed
// back by every async reader. The async path must enforce the same bound.
describe("decompression bomb (async size guard) - GHSA-c6fg-446q-cg94", () => {
    const payload = Buffer.alloc(1024 * 1024, 0x41); // 1 MB of real data
    const deflated = zlib.deflateRawSync(payload);
    const crc = Utils.crc32(payload);

    const expectSizeError = (data, err) => {
        expect(err, "async read must report an error").to.be.an("error");
        expect(err.message).to.match(/exceeds the declared uncompressed size/);
        expect(data.length, "no inflated bytes may be handed back").to.equal(0);
    };

    it("getDataAsync() rejects an entry that inflates past its declared size", (done) => {
        const zip = new Zip(craftBomb(16, 8 /* DEFLATED */, deflated, crc));
        zip.getEntries()[0].getDataAsync((data, err) => {
            try {
                expectSizeError(data, err);
                done();
            } catch (e) {
                done(e);
            }
        });
    });

    it("readFileAsync() surfaces the size error instead of the oversized data", (done) => {
        const zip = new Zip(craftBomb(16, 8 /* DEFLATED */, deflated, crc));
        zip.readFileAsync("a", (data, err) => {
            try {
                expectSizeError(data, err);
                done();
            } catch (e) {
                done(e);
            }
        });
    });

    it("readAsTextAsync() surfaces the size error instead of the oversized text", (done) => {
        const zip = new Zip(craftBomb(16, 8 /* DEFLATED */, deflated, crc));
        zip.readAsTextAsync("a", (data, err) => {
            try {
                expectSizeError(data, err);
                done();
            } catch (e) {
                done(e);
            }
        });
    });

    it("a declared size of 0 does not disable the async cap", (done) => {
        const zip = new Zip(craftBomb(0, 8 /* DEFLATED */, deflated, crc));
        zip.getEntries()[0].getDataAsync((data, err) => {
            try {
                expectSizeError(data, err);
                done();
            } catch (e) {
                done(e);
            }
        });
    });

    it("still reads an entry whose real size matches the declared size", (done) => {
        const zip = new Zip(craftBomb(payload.length, 8 /* DEFLATED */, deflated, crc));
        zip.getEntries()[0].getDataAsync((data, err) => {
            try {
                expect(err).to.equal(undefined);
                expect(data.equals(payload)).to.equal(true);
                done();
            } catch (e) {
                done(e);
            }
        });
    });

    it("still reads a genuinely empty DEFLATED entry declaring size 0", (done) => {
        const empty = Buffer.alloc(0);
        const zip = new Zip(craftBomb(0, 8 /* DEFLATED */, zlib.deflateRawSync(empty), Utils.crc32(empty)));
        const entry = zip.getEntries()[0];
        expect(entry.getData().length).to.equal(0);
        entry.getDataAsync((data, err) => {
            try {
                expect(err).to.equal(undefined);
                expect(data.length).to.equal(0);
                done();
            } catch (e) {
                done(e);
            }
        });
    });

    it("still reads a legitimate DEFLATED entry asynchronously", (done) => {
        const zip = new Zip();
        const text = Buffer.from("hello world ".repeat(5000));
        zip.addFile("d.txt", text);
        const round = new Zip(zip.toBuffer());
        round.readFileAsync("d.txt", (data, err) => {
            try {
                expect(err).to.equal(undefined);
                expect(data.equals(text)).to.equal(true);
                done();
            } catch (e) {
                done(e);
            }
        });
    });
});
