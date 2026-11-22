"use strict";

// Regression test for CVE-2026-76845 (symlink attack):
// sanitize() only checks that the textual extraction path stays under the target
// directory. When a component of that path already exists on disk as a symlink
// (or a Windows junction) pointing outside the target, mkdir()/open() follow it
// and the archive writes files outside the extraction root. Extraction must now
// refuse any path component strictly below the target that is a symlink.

const { expect } = require("chai");
const fs = require("fs");
const os = require("os");
const pth = require("path");
const rimraf = require("rimraf");
const Zip = require("../adm-zip");

const isWin = process.platform === "win32";

// Create a symlink, returning false when the platform refuses (e.g. EPERM on
// Windows without the symlink privilege) so the caller can skip the test.
// Directory links use a junction on Windows, which needs no extra privilege and
// which lstat() still reports as a symbolic link.
function makeLink(target, linkPath, isDir) {
    const type = isDir ? (isWin ? "junction" : "dir") : "file";
    try {
        fs.symlinkSync(target, linkPath, type);
        return true;
    } catch (e) {
        return false;
    }
}

function buildZip(entries) {
    const zip = new Zip();
    entries.forEach((e) => zip.addFile(e.name, e.content === undefined ? null : Buffer.from(e.content)));
    return new Zip(zip.toBuffer());
}

// first callback call only: extractAllToAsync may report more than once
function once(fn) {
    let called = false;
    return function () {
        if (called) return;
        called = true;
        fn.apply(this, arguments);
    };
}

describe("ADM-ZIP - extract through a pre-existing symlink (CVE-2026-76845)", () => {
    let tmpRoot;
    let target;
    let outside;
    let links;

    beforeEach(() => {
        tmpRoot = fs.mkdtempSync(pth.join(os.tmpdir(), "adm-zip-symlink-"));
        target = pth.join(tmpRoot, "target");
        outside = pth.join(tmpRoot, "outside");
        fs.mkdirSync(target);
        fs.mkdirSync(outside);
        links = [];
    });

    afterEach(() => {
        // remove the links themselves first so cleanup never walks through them
        links.forEach((l) => {
            try {
                fs.unlinkSync(l);
            } catch (e) {
                try {
                    fs.rmdirSync(l);
                } catch (e2) {
                    // ignore
                }
            }
        });
        rimraf.sync(tmpRoot);
    });

    // target/link -> outside
    function linkDirOutside(ctx) {
        const linkPath = pth.join(target, "link");
        if (!makeLink(outside, linkPath, true)) ctx.skip();
        links.push(linkPath);
        return linkPath;
    }

    // target/<name> -> outside/<outsideName>
    function linkFileOutside(ctx, name, outsideName) {
        const linkPath = pth.join(target, name);
        if (!makeLink(pth.join(outside, outsideName), linkPath, false)) ctx.skip();
        links.push(linkPath);
        return linkPath;
    }

    it("extractAllTo refuses to write a file through a symlinked directory", function () {
        linkDirOutside(this);
        const zip = buildZip([{ name: "link/evil.txt", content: "pwned" }]);

        expect(() => zip.extractAllTo(target, true)).to.throw(/There is a file in the way/);
        expect(fs.existsSync(pth.join(outside, "evil.txt"))).to.equal(false);
    });

    it("extractAllTo refuses to create a directory through a symlinked directory", function () {
        linkDirOutside(this);
        const zip = buildZip([{ name: "link/sub/" }]);

        expect(() => zip.extractAllTo(target, true)).to.throw(/There is a file in the way/);
        expect(fs.existsSync(pth.join(outside, "sub"))).to.equal(false);
    });

    it("extractAllTo refuses to overwrite a file through a symlinked file", function () {
        fs.writeFileSync(pth.join(outside, "victim.txt"), "original");
        linkFileOutside(this, "victim.txt", "victim.txt");
        const zip = buildZip([{ name: "victim.txt", content: "pwned" }]);

        expect(() => zip.extractAllTo(target, true)).to.throw(/There is a file in the way/);
        expect(fs.readFileSync(pth.join(outside, "victim.txt"), "utf8")).to.equal("original");
    });

    it("extractAllTo refuses to create a file through a dangling symlink", function () {
        linkFileOutside(this, "dangling.txt", "created.txt");
        const zip = buildZip([{ name: "dangling.txt", content: "pwned" }]);

        expect(() => zip.extractAllTo(target, false)).to.throw(/There is a file in the way/);
        expect(fs.existsSync(pth.join(outside, "created.txt"))).to.equal(false);
    });

    it("extractEntryTo refuses to write a single file through a symlinked directory", function () {
        linkDirOutside(this);
        const zip = buildZip([{ name: "link/evil.txt", content: "pwned" }]);

        expect(() => zip.extractEntryTo("link/evil.txt", target, true, true)).to.throw(/There is a file in the way/);
        expect(fs.existsSync(pth.join(outside, "evil.txt"))).to.equal(false);
    });

    it("extractEntryTo refuses to write through a symlink given as outFileName", function () {
        linkDirOutside(this);
        const zip = buildZip([{ name: "evil.txt", content: "pwned" }]);

        expect(() => zip.extractEntryTo("evil.txt", target, true, true, false, "link/renamed.txt")).to.throw(/There is a file in the way/);
        expect(fs.existsSync(pth.join(outside, "renamed.txt"))).to.equal(false);
    });

    it("extractEntryTo refuses to write directory children through a symlinked directory", function () {
        linkDirOutside(this);
        const zip = buildZip([{ name: "link/" }, { name: "link/evil.txt", content: "pwned" }]);

        expect(() => zip.extractEntryTo("link/", target, true, true)).to.throw(/There is a file in the way/);
        expect(fs.existsSync(pth.join(outside, "evil.txt"))).to.equal(false);
    });

    it("extractAllToAsync reports an error instead of writing a file through a symlinked directory", function (done) {
        linkDirOutside(this);
        const zip = buildZip([{ name: "link/evil.txt", content: "pwned" }]);

        zip.extractAllToAsync(
            target,
            true,
            false,
            once((err) => {
                try {
                    expect(err).to.be.an("error");
                    expect(err.message).to.match(/There is a file in the way/);
                    expect(fs.existsSync(pth.join(outside, "evil.txt"))).to.equal(false);
                    done();
                } catch (e) {
                    done(e);
                }
            })
        );
    });

    it("extractAllToAsync reports an error instead of creating a directory through a symlinked directory", function (done) {
        linkDirOutside(this);
        const zip = buildZip([{ name: "link/sub/" }]);

        zip.extractAllToAsync(
            target,
            true,
            false,
            once((err) => {
                try {
                    expect(err).to.be.an("error");
                    expect(fs.existsSync(pth.join(outside, "sub"))).to.equal(false);
                    done();
                } catch (e) {
                    done(e);
                }
            })
        );
    });

    it("extractAllToAsync [Promise] rejects instead of writing through a symlinked directory", function () {
        linkDirOutside(this);
        const zip = buildZip([{ name: "link/evil.txt", content: "pwned" }]);

        return zip.extractAllToAsync(target, true, false).then(
            () => {
                throw new Error("expected extractAllToAsync to reject");
            },
            (err) => {
                expect(err.message).to.match(/There is a file in the way/);
                expect(fs.existsSync(pth.join(outside, "evil.txt"))).to.equal(false);
            }
        );
    });

    it("extracting still works next to an unrelated symlink and when the target itself is a symlink", function () {
        linkDirOutside(this);
        const zip = buildZip([
            { name: "safe/" },
            { name: "safe/file.txt", content: "ok" }
        ]);

        zip.extractAllTo(target, true);
        expect(fs.readFileSync(pth.join(target, "safe", "file.txt"), "utf8")).to.equal("ok");

        // a symlink at the extraction root is the caller's own choice
        const rootLink = pth.join(tmpRoot, "rootlink");
        if (!makeLink(outside, rootLink, true)) this.skip();
        links.push(rootLink);
        zip.extractAllTo(rootLink, true);
        expect(fs.readFileSync(pth.join(outside, "safe", "file.txt"), "utf8")).to.equal("ok");
    });
});
