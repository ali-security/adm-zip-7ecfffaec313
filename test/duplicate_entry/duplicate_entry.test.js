"use strict";

// Regression test for GHSA-p634-w6r4-rjp2:
// A ZIP archive can declare the same entry name twice. adm-zip kept every
// entry in its entry list but only the last one in its name->entry table, so
// getEntry() returned the last duplicate while extractAllTo() wrote the first
// one to disk. An application validating an entry via getEntry() before
// extracting the archive could approve one content while different bytes were
// written under that name. Such archives must be rejected.

const assert = require("assert");
const fs = require("fs");
const os = require("os");
const pth = require("path");
const rimraf = require("rimraf");
const Zip = require("../../adm-zip");

const DUPLICATE = /Duplicate entry name/;

// Replace every occurrence of `from` with `to` (same length) inside `buf`.
function replaceAll(buf, from, to) {
    const out = Buffer.from(buf);
    const needle = Buffer.from(from);
    const replacement = Buffer.from(to);
    let pos = out.indexOf(needle);
    while (pos !== -1) {
        replacement.copy(out, pos);
        pos = out.indexOf(needle, pos + needle.length);
    }
    return out;
}

// PoC from the advisory: two entries "a.txt" (FIRST) and "b.txt" (SECOND),
// then rename "a.txt" to "b.txt" in the raw bytes (local + central headers).
function craftDuplicate() {
    const zip = new Zip({ noSort: true });
    zip.addFile("a.txt", Buffer.from("FIRST"));
    zip.addFile("b.txt", Buffer.from("SECOND"));
    return replaceAll(zip.toBuffer(), "a.txt", "b.txt");
}

describe("ADM-ZIP - duplicate entry names (GHSA-p634-w6r4-rjp2)", () => {
    let target;

    beforeEach(() => {
        target = fs.mkdtempSync(pth.join(os.tmpdir(), "adm-zip-dup-"));
    });

    afterEach(() => {
        rimraf.sync(target);
    });

    it("crafted archive really declares the same name twice", () => {
        const buf = craftDuplicate();
        // both central directory records now carry "b.txt"
        let count = 0;
        let pos = buf.indexOf(Buffer.from("b.txt"));
        while (pos !== -1) {
            count++;
            pos = buf.indexOf(Buffer.from("b.txt"), pos + 1);
        }
        assert.strictEqual(count, 4); // 2 local headers + 2 central headers
        assert.strictEqual(buf.indexOf(Buffer.from("a.txt")), -1);
    });

    it("getEntry() / readFile() refuse the ambiguous archive", () => {
        const zip = new Zip(craftDuplicate());
        assert.throws(() => zip.getEntry("b.txt"), DUPLICATE);
        assert.throws(() => zip.readFile("b.txt"), DUPLICATE);
    });

    it("getEntries() refuses the ambiguous archive", () => {
        const zip = new Zip(craftDuplicate());
        assert.throws(() => zip.getEntries(), DUPLICATE);
    });

    it("extractAllTo() refuses the archive and writes nothing", () => {
        const zip = new Zip(craftDuplicate());
        assert.throws(() => zip.extractAllTo(target), DUPLICATE);
        assert.strictEqual(fs.existsSync(pth.join(target, "b.txt")), false);
        assert.deepStrictEqual(fs.readdirSync(target), []);
    });

    it("extractAllTo() with overwrite refuses the archive and writes nothing", () => {
        const zip = new Zip(craftDuplicate());
        assert.throws(() => zip.extractAllTo(target, true), DUPLICATE);
        assert.deepStrictEqual(fs.readdirSync(target), []);
    });

    it("extractAllToAsync() rejects the archive and writes nothing", () => {
        const zip = new Zip(craftDuplicate());
        return zip.extractAllToAsync(target, true).then(
            () => assert.fail("extractAllToAsync should have rejected"),
            (err) => {
                assert.ok(DUPLICATE.test(err.message), err.message);
                assert.deepStrictEqual(fs.readdirSync(target), []);
            }
        );
    });

    it("validate-then-extract cannot be split between two contents", () => {
        const zip = new Zip(craftDuplicate());
        let validated = null;
        try {
            validated = zip.getEntry("b.txt").getData().toString();
        } catch (err) {
            assert.ok(DUPLICATE.test(err.message), err.message);
        }
        assert.strictEqual(validated, null);
        assert.throws(() => zip.extractAllTo(target), DUPLICATE);
        assert.strictEqual(fs.existsSync(pth.join(target, "b.txt")), false);
    });

    it("eager loading (readEntries: true) rejects the archive on open", () => {
        const buf = craftDuplicate();
        assert.throws(() => new Zip(buf, { readEntries: true }), DUPLICATE);
    });

    it("rejects a duplicated directory entry as well", () => {
        const zip = new Zip({ noSort: true });
        zip.addFile("aaa/", Buffer.alloc(0));
        zip.addFile("bbb/", Buffer.alloc(0));
        const buf = replaceAll(zip.toBuffer(), "aaa/", "bbb/");
        assert.throws(() => new Zip(buf).getEntries(), DUPLICATE);
    });

    it("accepts archives with distinct names, including Object.prototype keys", () => {
        const names = ["a.txt", "b.txt", "dir/", "dir/a.txt", "toString", "hasOwnProperty", "valueOf", "constructor", "__proto__"];
        const zip = new Zip();
        names.forEach((name) => zip.addFile(name, name.endsWith("/") ? Buffer.alloc(0) : Buffer.from("content of " + name)));
        const reopened = new Zip(zip.toBuffer());
        assert.deepStrictEqual(
            reopened
                .getEntries()
                .map((e) => e.entryName)
                .sort(),
            names.slice().sort()
        );
        assert.strictEqual(reopened.readFile("b.txt").toString(), "content of b.txt");
        assert.strictEqual(reopened.readFile("toString").toString(), "content of toString");
        assert.strictEqual(reopened.test(), true);
    });
});
