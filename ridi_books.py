import argparse
import os
import sys
import io
import re
import zipfile
from pathlib import Path
from xml.etree import ElementTree as ET
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from typing import Optional, List
from enum import Enum

class BookFormat(Enum):
    EPUB = "epub"
    PDF = "pdf"
    
    @classmethod
    def from_path(cls, path: Path) -> 'BookFormat':
        ext = path.suffix[1:].lower()
        if ext == "epub":
            return cls.EPUB
        elif ext == "pdf":
            return cls.PDF
        else:
            raise ValueError(f"not a book file: {path}")
    
    def extension(self) -> str:
        return self.value

class FileKind(Enum):
    BOOK = "book"
    DATA = "data"

class BookInfo:
    def __init__(self, path: Path):
        self.path = path
        self.id = self._get_id(path)
        self.format = self._get_format(path)
    
    def _get_id(self, path: Path) -> str:
        """Get the directory name as the book ID"""
        if not path.is_dir():
            raise ValueError(f"invalid id")
        return path.name
    
    def _get_format(self, path: Path) -> BookFormat:
        """Detect book format by looking at files in the directory"""
        for entry in path.iterdir():
            if entry.is_file():
                try:
                    return BookFormat.from_path(entry)
                except ValueError:
                    continue
        raise ValueError(f"not a book path: {path}")
    
    def file_path(self, kind: FileKind) -> Path:
        """Get the full path to the book or data file"""
        # Look for the actual files in the directory
        if kind == FileKind.BOOK:
            # Find the book file (id.*.epub or id.*.pdf)
            for entry in self.path.iterdir():
                if entry.is_file():
                    name = entry.name
                    # Check if it starts with the id and has the right extension
                    if (name.startswith(self.id) and 
                        entry.suffix[1:].lower() == self.format.extension()):
                        return entry
            # Fallback to expected name
            return self.path / f"{self.id}.{self.format.extension()}"
        
        elif kind == FileKind.DATA:
            # Find the .dat file
            for entry in self.path.iterdir():
                if entry.is_file():
                    name = entry.name
                    # Check if it starts with the id and ends with .dat
                    if name.startswith(self.id) and entry.suffix.lower() == '.dat':
                        return entry
            # Fallback to expected name
            return self.path / f"{self.id}.dat"
        
        else:
            raise ValueError("Unknown file kind")
    
    def file_name(self, kind: FileKind) -> str:
        """Get just the filename for the book or data file"""
        # Return just the base name without version info for output
        if kind == FileKind.BOOK:
            return f"{self.id}.{self.format.extension()}"
        return self.file_path(kind).name

def verify(device_id: str, user_idx: str):
    """Verify the arguments are valid"""
    if len(device_id) != 36:
        raise ValueError(f"invalid device id: {device_id}")
    if not user_idx:
        raise ValueError("invalid user idx")

def library_path(user_idx: str) -> Path:
    """Get the library path for the current OS"""
    if sys.platform == "darwin":  # macOS
        home = Path(os.environ.get("HOME", "~")).expanduser()
        return home / "Library" / "Application Support" / "Ridibooks" / "library" / f"_{user_idx}"
    elif sys.platform == "win32":  # Windows
        appdata = Path(os.environ.get("APPDATA", ""))
        if not appdata or not appdata.exists():
            raise ValueError("APPDATA environment variable not found")
        return appdata / "Ridibooks" / "library" / f"_{user_idx}"
    else:
        raise NotImplementedError("library_path() not implemented for this OS")

def book_infos(path: Path) -> List[BookInfo]:
    """Get BookInfo objects for all books in the library"""
    infos = []
    if not path.exists():
        return infos
    
    for entry in path.iterdir():
        if entry.is_dir():
            try:
                infos.append(BookInfo(entry))
            except ValueError:
                # Skip directories that aren't book directories
                continue
    return infos

def decrypt_key(book_info: BookInfo, device_id: str, debug: bool = False) -> bytes:
    """Decrypt the key from the .dat file"""
    data_file_path = book_info.file_path(FileKind.DATA)
    
    if not data_file_path.exists():
        raise FileNotFoundError(f"Data file not found: {data_file_path}")
    
    data_file = data_file_path.read_bytes()
    
    if debug:
        print(f"  Data file: {data_file_path}")
        print(f"  Data file size: {len(data_file)} bytes")
    
    # Use first 16 bytes of device_id as key
    key = device_id.encode('utf-8')[:16]
    
    # First 16 bytes of data file is IV
    iv = data_file[:16]
    
    if debug:
        print(f"  Key (from device_id): {key.hex()}")
        print(f"  IV: {iv.hex()}")
    
    # Create AES-CBC cipher
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    
    # Decrypt the data (skip first 16 bytes which is IV)
    decrypted = decryptor.update(data_file[16:]) + decryptor.finalize()
    
    # Unpad the decrypted data
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(decrypted) + unpadder.finalize()
    
    if debug:
        print(f"  Decrypted plaintext size: {len(plaintext)} bytes")
    
    # Extract session key exactly as the 16 ASCII bytes at positions 68..84 of the UTF-8 plaintext
    if len(plaintext) < 84:
        raise ValueError(f".dat plaintext too short: {len(plaintext)} bytes (need at least 84)")
    # Rust does: str::from_utf8(plaintext)[68..84].as_bytes()
    try:
        plain_str = plaintext.decode('utf-8')
    except Exception as e:
        raise ValueError(f".dat plaintext is not valid UTF-8: {e}")
    slice_str = plain_str[68:84]
    result_key = slice_str.encode('utf-8')
    if debug:
        print(f"  Extracted key (ascii slice 68..84): {slice_str}")
        print(f"  Session key (bytes): {result_key.hex()}")
    if len(result_key) != 16:
        raise ValueError(f"Derived key is not 16 bytes: {len(result_key)} bytes")
    return result_key

def _looks_like_valid_output(fmt: BookFormat, data: bytes) -> bool:
    if fmt == BookFormat.EPUB:
        # ZIP files begin with PK\x03\x04 or sometimes PK\x05\x06 (empty zip)
        return data.startswith(b"PK\x03\x04") or data.startswith(b"PK\x05\x06") or data.startswith(b"PK\x07\x08")
    if fmt == BookFormat.PDF:
        return data.startswith(b"%PDF")
    return False

def _sanitize_filename(name: str, max_len: int = 120) -> str:
    # Remove or replace characters invalid on Windows and most filesystems
    name = name.strip()
    # Replace forbidden characters with space
    name = re.sub(r"[\\/:*?\"<>|]", " ", name)
    # Collapse whitespace
    name = re.sub(r"\s+", " ", name).strip()
    # Trim length
    if len(name) > max_len:
        name = name[:max_len].rstrip()
    # Disallow reserved names on Windows
    reserved = {"CON","PRN","AUX","NUL","COM1","COM2","COM3","COM4","COM5","COM6","COM7","COM8","COM9","LPT1","LPT2","LPT3","LPT4","LPT5","LPT6","LPT7","LPT8","LPT9"}
    if name.upper() in reserved:
        name = f"_{name}"
    # Avoid empty name
    return name or "untitled"

def _extract_title_epub(data: bytes) -> Optional[str]:
    try:
        with zipfile.ZipFile(io.BytesIO(data), 'r') as zf:
            # container.xml tells us where the OPF is
            with zf.open('META-INF/container.xml') as f:
                container_xml = f.read()
            try:
                container = ET.fromstring(container_xml)
            except ET.ParseError:
                return None
            ns = {
                'c': 'urn:oasis:names:tc:opendocument:xmlns:container'
            }
            rootfile = container.find('.//c:rootfile', ns)
            if rootfile is None:
                return None
            opf_path = rootfile.attrib.get('full-path')
            if not opf_path:
                return None
            with zf.open(opf_path) as f:
                opf_xml = f.read()
            try:
                opf = ET.fromstring(opf_xml)
            except ET.ParseError:
                return None
            # Common namespaces
            ns = {
                'opf': 'http://www.idpf.org/2007/opf',
                'dc': 'http://purl.org/dc/elements/1.1/'
            }
            # Try metadata/dc:title
            title_el = opf.find('.//dc:title', ns)
            if title_el is not None and title_el.text:
                return title_el.text.strip()
            # Fallback: check without namespaces (non-compliant files)
            for el in opf.iter():
                if el.tag.lower().endswith('title') and el.text:
                    return el.text.strip()
            return None
    except Exception:
        return None

def _extract_title_pdf(data: bytes) -> Optional[str]:
    try:
        try:
            import PyPDF2  # type: ignore
        except Exception:
            return None
        reader = PyPDF2.PdfReader(io.BytesIO(data))
        meta = reader.metadata
        if meta and getattr(meta, 'title', None):
            return str(meta.title).strip()
        return None
    except Exception:
        return None

def extract_title(fmt: BookFormat, data: bytes) -> Optional[str]:
    if fmt == BookFormat.EPUB:
        return _extract_title_epub(data)
    if fmt == BookFormat.PDF:
        return _extract_title_pdf(data)
    return None

def decrypt_book(book_info: BookInfo, key: bytes, debug: bool = False) -> bytes:
    """Decrypt the book file using the decrypted key.

    Aligns with Rust reference: IV = first 16 bytes, ciphertext = rest, AES-128-CBC + PKCS7.
    If file already looks like a valid ZIP/PDF, returns as-is.
    """
    book_file_path = book_info.file_path(FileKind.BOOK)
    
    if not book_file_path.exists():
        raise FileNotFoundError(f"Book file not found: {book_file_path}")
    
    book_file = book_file_path.read_bytes()
    
    if debug:
        print(f"  Book file: {book_file_path}")
        print(f"  Book file size: {len(book_file)} bytes")
        print(f"  First 16 bytes: {book_file[:16].hex()}")
    
    # If the file already looks like a valid container, just return it as-is.
    # Some RIDI versions store plain EPUB/PDF without wrapping.
    if _looks_like_valid_output(book_info.format, book_file):
        if debug:
            print("  File already looks valid; copying as-is")
        return book_file
    
    # Simple: use IV at start and decrypt remainder
    if len(book_file) < 16:
        raise ValueError("Book file too small to contain IV")
    iv = book_file[:16]
    ciphertext = book_file[16:]
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(ciphertext) + decryptor.finalize()
    # PKCS7 unpad
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(decrypted) + unpadder.finalize()
    return plaintext

def decrypt(book_info: BookInfo, device_id: str, debug: bool = False):
    """Decrypt a book and save it to the current directory"""
    key = decrypt_key(book_info, device_id, debug)
    book_contents = decrypt_book(book_info, key, debug)
    # Determine title-based filename
    title = extract_title(book_info.format, book_contents)
    if title:
        safe = _sanitize_filename(title)
        out_name = f"{safe}.{book_info.format.extension()}"
    else:
        out_name = book_info.file_name(FileKind.BOOK)
    # Avoid overwriting by appending a suffix if needed
    target = Path(out_name)
    if target.exists():
        stem = target.stem
        suffix = target.suffix
        i = 1
        while target.exists() and i < 1000:
            target = Path(f"{stem} ({i}){suffix}")
            i += 1
    Path(target).write_bytes(book_contents)
    if debug:
        print(f"  Wrote output: {target}")

def decrypt_with_progress(book_info: BookInfo, device_id: str, debug: bool = False):
    """Decrypt a book with progress indicator"""
    file_name = book_info.file_name(FileKind.BOOK)
    
    print(f"⣿ Decrypting \"{file_name}\"", end="", flush=True)
    
    try:
        if debug:
            print()  # New line for debug output
        decrypt(book_info, device_id, debug)
        if not debug:
            print(f"\r⣿ Decrypting \"{file_name}\" ✔︎")
        else:
            print(f"⣿ Decrypting \"{file_name}\" ✔︎")
        return True
    except Exception as e:
        if not debug:
            print(f"\r⣿ Decrypting \"{file_name}\" ✘")
        else:
            print(f"⣿ Decrypting \"{file_name}\" ✘")
            print(f"  Error: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(
        description="Decrypt Ridibooks files",
        prog="ridibooks-decrypt"
    )
    parser.add_argument(
        "-d", "--device-id",
        required=True,
        dest="device_id",
        help="Device ID (36 characters)"
    )
    parser.add_argument(
        "-u", "--user-idx",
        required=True,
        dest="user_idx",
        help="User index"
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug output"
    )
    
    args = parser.parse_args()
    
    try:
        # Verify arguments
        verify(args.device_id, args.user_idx)
        
        # Get library path and book infos
        lib_path = library_path(args.user_idx)
        
        if args.debug:
            print(f"Library path: {lib_path}")
        
        if not lib_path.exists():
            print(f"Error: Library path does not exist: {lib_path}", file=sys.stderr)
            sys.exit(1)
        
        infos = book_infos(lib_path)
        
        if not infos:
            print("No books found in library")
            return
        
        if args.debug:
            print(f"Found {len(infos)} book(s)")
            print()
        
        # Decrypt all books with progress
        for book_info in infos:
            decrypt_with_progress(book_info, args.device_id, args.debug)
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()