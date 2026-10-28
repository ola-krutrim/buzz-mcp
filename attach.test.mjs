// attach.test.mjs — `node attach.test.mjs`
// attach-hardening attachment policy (buzz_security ruling): narrow allow-list decided from the BYTES,
// extension forced to the sniffed type, sanitised display names, escaped link labels.
import { classifyAttachment, attachmentDisplayName, sanitizeAttachmentName, escapeLinkLabel, attachmentContentLine, checkAttachmentText, zipCentralDirectoryNames, mediaCapCheck, ATTACH_ALLOWED_FILE_TYPES, ATTACH_IMAGE_MIMES, ATTACH_VIDEO_MIMES, MEDIA_MB } from "./signer.mjs";

let pass = 0, fail = 0;
const ok = (c, m) => (c ? (pass++, console.log("  ✅ " + m)) : (fail++, console.log("  ❌ " + m)));
const reader = (buf) => (start, len) => buf.subarray(start, start + len);
const classify = (name, buf) => classifyAttachment({ name, size: buf.length, read: reader(buf) });
const refused = (name, buf) => { try { classify(name, buf); return null; } catch (e) { return e.message; } };

// A real stored ZIP with a central directory (what Office/LibreOffice and infer see).
function zip(entries) {
  const locals = [], central = [];
  let off = 0;
  for (const [name, data0] of entries) {
    const n = Buffer.from(name, "utf8"), data = Buffer.from(data0);
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4); lh.writeUInt32LE(data.length, 18); lh.writeUInt32LE(data.length, 22); lh.writeUInt16LE(n.length, 26);
    locals.push(lh, n, data);
    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(20, 4); ch.writeUInt16LE(20, 6); ch.writeUInt32LE(data.length, 20); ch.writeUInt32LE(data.length, 24); ch.writeUInt16LE(n.length, 28); ch.writeUInt32LE(off, 42);
    central.push(ch, n);
    off += 30 + n.length + data.length;
  }
  const cd = Buffer.concat(central);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0); eocd.writeUInt16LE(entries.length, 8); eocd.writeUInt16LE(entries.length, 10); eocd.writeUInt32LE(cd.length, 12); eocd.writeUInt32LE(off, 16);
  return Buffer.concat([...locals, cd, eocd]);
}
const ooxml = (dir, extra = []) => zip([[`${dir}/document.xml`, "<x/>"], ["[Content_Types].xml", "<Types/>"], ...extra]);
const odf = (mime, extra = []) => zip([["mimetype", mime], ["content.xml", "<office/>"], ...extra]);
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
ok(attachmentDisplayName("x.html", "application/octet-stream") === "x.txt", "any other text extension → .txt");
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

console.log(`\n${fail === 0 ? "ALL PASS" : "FAILURES"}: ${pass} passed, ${fail} failed`);
if (fail) process.exit(1);
