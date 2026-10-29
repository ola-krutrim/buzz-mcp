# Upload-policy fixtures (fork addition)

Real Office/ODF files for `src/upload_policy.rs` tests. `infer` 0.19 guesses
OOXML from ZIP entry order, so several of these sniff as plain
`application/zip`; the CLI must classify them from the ZIP central directory.

| File | Made with | Entry order | `infer` 0.19 says |
| --- | --- | --- | --- |
| `libreoffice.docx` | LibreOffice 25.2 `--convert-to docx` | `_rels/.rels`, `docProps/…`, `word/…` | application/zip |
| `python-docx.docx` | python-docx 1.2.0 | `[Content_Types].xml`, `_rels/.rels`, `docProps/core.xml`, `docProps/app.xml`, `word/document.xml` | application/zip |
| `docx-main-past-4k.docx` | `python-docx.docx` re-zipped (Python `zipfile`) with `word/document.xml` last, at offset 34870 | as above, main part past 4 KiB | application/zip (whole file and 4 KiB prefix) |
| `python-pptx.pptx` | python-pptx 1.0.2 | `[Content_Types].xml`, `_rels/.rels`, `docProps/…`, `ppt/presentation.xml` | application/zip |
| `xlsx-docprops-third.xlsx` | `openpyxl.xlsx` re-zipped as `[Content_Types].xml`, `_rels/.rels`, `docProps/app.xml`, `docProps/core.xml`, `xl/…` | | application/zip |
| `openpyxl.xlsx` | openpyxl 3.1.5 | `docProps/…`, `xl/…` | xlsx |
| `libreoffice.xlsx` | LibreOffice 25.2 `--convert-to xlsx` | `xl/…` first | xlsx |
| `libreoffice.odt` | LibreOffice 25.2 `--convert-to odt` | `mimetype` first | odt |

No genuine Microsoft Office output is included (none available on the build box).
