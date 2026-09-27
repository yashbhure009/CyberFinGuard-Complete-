"""Small dependency-free PDF renderer for assessment summaries."""
import textwrap
import unicodedata


def safe_text(value):
    text = str(value).replace("₹", "INR ")
    return unicodedata.normalize("NFKD", text).encode("ascii", "replace").decode("ascii")


def escape(value):
    return safe_text(value).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def pdf_from_lines(lines):
    wrapped = []
    for line in lines:
        wrapped.extend(textwrap.wrap(safe_text(line), width=92) or [""])
    pages = [wrapped[index:index + 57] for index in range(0, len(wrapped), 57)] or [[]]
    objects = [None, None, b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"]
    page_ids = []
    for page in pages:
        commands = ["BT /F1 10 Tf 50 790 Td 14 TL"]
        for index, line in enumerate(page):
            if index:
                commands.append("T*")
            commands.append(f"({escape(line)}) Tj")
        commands.append("ET")
        stream = "\n".join(commands).encode("ascii")
        stream_id = len(objects) + 1
        objects.append(f"<< /Length {len(stream)} >>\nstream\n".encode() + stream + b"\nendstream")
        page_id = len(objects) + 1
        objects.append(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 842] /Resources << /Font << /F1 3 0 R >> >> /Contents {stream_id} 0 R >>".encode())
        page_ids.append(page_id)
    objects[0] = b"<< /Type /Catalog /Pages 2 0 R >>"
    kids = " ".join(f"{identifier} 0 R" for identifier in page_ids)
    objects[1] = f"<< /Type /Pages /Kids [{kids}] /Count {len(page_ids)} >>".encode()
    output = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for identifier, obj in enumerate(objects, 1):
        offsets.append(len(output))
        output.extend(f"{identifier} 0 obj\n".encode() + obj + b"\nendobj\n")
    xref = len(output)
    output.extend(f"xref\n0 {len(objects)+1}\n0000000000 65535 f \n".encode())
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode())
    output.extend(f"trailer\n<< /Size {len(objects)+1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF".encode())
    return bytes(output)
