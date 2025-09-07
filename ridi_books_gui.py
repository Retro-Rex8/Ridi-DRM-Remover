import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import queue
import sys
import io
from pathlib import Path

# Import all the functions from the original script
import argparse
import os
import re
import zipfile
from xml.etree import ElementTree as ET
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from typing import Optional, List
from enum import Enum

# ============ Original script classes and functions ============

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
        if kind == FileKind.BOOK:
            for entry in self.path.iterdir():
                if entry.is_file():
                    name = entry.name
                    if (name.startswith(self.id) and 
                        entry.suffix[1:].lower() == self.format.extension()):
                        return entry
            return self.path / f"{self.id}.{self.format.extension()}"
        
        elif kind == FileKind.DATA:
            for entry in self.path.iterdir():
                if entry.is_file():
                    name = entry.name
                    if name.startswith(self.id) and entry.suffix.lower() == '.dat':
                        return entry
            return self.path / f"{self.id}.dat"
        
        else:
            raise ValueError("Unknown file kind")
    
    def file_name(self, kind: FileKind) -> str:
        """Get just the filename for the book or data file"""
        if kind == FileKind.BOOK:
            return f"{self.id}.{self.format.extension()}"
        return self.file_path(kind).name

def verify(device_id: str, user_idx: str):
    """Verify the arguments are valid"""
    if len(device_id) != 36:
        raise ValueError(f"Invalid device ID: must be 36 characters (got {len(device_id)})")
    if not user_idx:
        raise ValueError("Invalid user index: cannot be empty")

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
                continue
    return infos

def decrypt_key(book_info: BookInfo, device_id: str, debug: bool = False) -> bytes:
    """Decrypt the key from the .dat file"""
    data_file_path = book_info.file_path(FileKind.DATA)
    
    if not data_file_path.exists():
        raise FileNotFoundError(f"Data file not found: {data_file_path}")
    
    data_file = data_file_path.read_bytes()
    
    key = device_id.encode('utf-8')[:16]
    iv = data_file[:16]
    
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    
    decrypted = decryptor.update(data_file[16:]) + decryptor.finalize()
    
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(decrypted) + unpadder.finalize()
    
    if len(plaintext) < 84:
        raise ValueError(f".dat plaintext too short: {len(plaintext)} bytes (need at least 84)")
    
    try:
        plain_str = plaintext.decode('utf-8')
    except Exception as e:
        raise ValueError(f".dat plaintext is not valid UTF-8: {e}")
    
    slice_str = plain_str[68:84]
    result_key = slice_str.encode('utf-8')
    
    if len(result_key) != 16:
        raise ValueError(f"Derived key is not 16 bytes: {len(result_key)} bytes")
    
    return result_key

def _looks_like_valid_output(fmt: BookFormat, data: bytes) -> bool:
    if fmt == BookFormat.EPUB:
        return data.startswith(b"PK\x03\x04") or data.startswith(b"PK\x05\x06") or data.startswith(b"PK\x07\x08")
    if fmt == BookFormat.PDF:
        return data.startswith(b"%PDF")
    return False

def _sanitize_filename(name: str, max_len: int = 120) -> str:
    name = name.strip()
    name = re.sub(r"[\\/:*?\"<>|]", " ", name)
    name = re.sub(r"\s+", " ", name).strip()
    if len(name) > max_len:
        name = name[:max_len].rstrip()
    reserved = {"CON","PRN","AUX","NUL","COM1","COM2","COM3","COM4","COM5","COM6","COM7","COM8","COM9","LPT1","LPT2","LPT3","LPT4","LPT5","LPT6","LPT7","LPT8","LPT9"}
    if name.upper() in reserved:
        name = f"_{name}"
    return name or "untitled"

def _extract_title_epub(data: bytes) -> Optional[str]:
    try:
        with zipfile.ZipFile(io.BytesIO(data), 'r') as zf:
            with zf.open('META-INF/container.xml') as f:
                container_xml = f.read()
            try:
                container = ET.fromstring(container_xml)
            except ET.ParseError:
                return None
            ns = {'c': 'urn:oasis:names:tc:opendocument:xmlns:container'}
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
            ns = {
                'opf': 'http://www.idpf.org/2007/opf',
                'dc': 'http://purl.org/dc/elements/1.1/'
            }
            title_el = opf.find('.//dc:title', ns)
            if title_el is not None and title_el.text:
                return title_el.text.strip()
            for el in opf.iter():
                if el.tag.lower().endswith('title') and el.text:
                    return el.text.strip()
            return None
    except Exception:
        return None

def _extract_title_pdf(data: bytes) -> Optional[str]:
    try:
        try:
            import PyPDF2
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
    """Decrypt the book file using the decrypted key."""
    book_file_path = book_info.file_path(FileKind.BOOK)
    
    if not book_file_path.exists():
        raise FileNotFoundError(f"Book file not found: {book_file_path}")
    
    book_file = book_file_path.read_bytes()
    
    if _looks_like_valid_output(book_info.format, book_file):
        return book_file
    
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
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(decrypted) + unpadder.finalize()
    return plaintext

def decrypt(book_info: BookInfo, device_id: str, output_dir: Path, debug: bool = False):
    """Decrypt a book and save it to the specified directory"""
    key = decrypt_key(book_info, device_id, debug)
    book_contents = decrypt_book(book_info, key, debug)
    title = extract_title(book_info.format, book_contents)
    if title:
        safe = _sanitize_filename(title)
        out_name = f"{safe}.{book_info.format.extension()}"
    else:
        out_name = book_info.file_name(FileKind.BOOK)
    
    target = output_dir / out_name
    if target.exists():
        stem = target.stem
        suffix = target.suffix
        i = 1
        while target.exists() and i < 1000:
            target = output_dir / f"{stem} ({i}){suffix}"
            i += 1
    
    target.write_bytes(book_contents)
    return target

# ============ GUI Application ============

class RidibooksDecryptorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Ridibooks Decryptor")
        self.root.geometry("700x600")
        
        # Set icon if on Windows
        if sys.platform == "win32":
            self.root.iconbitmap(default='')
        
        # Queue for thread communication
        self.queue = queue.Queue()
        
        self.setup_ui()
        self.root.after(100, self.process_queue)
        
    def setup_ui(self):
        # Main frame with padding
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        
        # Title
        title_label = ttk.Label(main_frame, text="Ridibooks Decryptor", 
                                font=('Helvetica', 16, 'bold'))
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))
        
        # Device ID input
        ttk.Label(main_frame, text="Device ID:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.device_id_var = tk.StringVar()
        device_id_entry = ttk.Entry(main_frame, textvariable=self.device_id_var, width=50)
        device_id_entry.grid(row=1, column=1, columnspan=2, sticky=(tk.W, tk.E), pady=5, padx=(5, 0))
        
        # Character count label for Device ID
        self.device_id_count = ttk.Label(main_frame, text="0/36 characters", foreground="gray")
        self.device_id_count.grid(row=2, column=1, sticky=tk.W, padx=(5, 0))
        self.device_id_var.trace('w', self.update_device_id_count)
        
        # User Index input
        ttk.Label(main_frame, text="User Index:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.user_idx_var = tk.StringVar()
        user_idx_entry = ttk.Entry(main_frame, textvariable=self.user_idx_var, width=50)
        user_idx_entry.grid(row=3, column=1, columnspan=2, sticky=(tk.W, tk.E), pady=5, padx=(5, 0))
        
        # Output directory selection
        ttk.Label(main_frame, text="Output Folder:").grid(row=4, column=0, sticky=tk.W, pady=5)
        self.output_dir_var = tk.StringVar(value=str(Path.cwd()))
        output_dir_entry = ttk.Entry(main_frame, textvariable=self.output_dir_var, width=40)
        output_dir_entry.grid(row=4, column=1, sticky=(tk.W, tk.E), pady=5, padx=(5, 0))
        
        browse_button = ttk.Button(main_frame, text="Browse...", command=self.browse_output_dir)
        browse_button.grid(row=4, column=2, pady=5, padx=(5, 0))
        
        # Debug mode checkbox
        self.debug_var = tk.BooleanVar(value=False)
        debug_check = ttk.Checkbutton(main_frame, text="Debug mode", variable=self.debug_var)
        debug_check.grid(row=5, column=0, columnspan=2, sticky=tk.W, pady=10)
        
        # Buttons frame
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=6, column=0, columnspan=3, pady=10)
        
        self.decrypt_button = ttk.Button(button_frame, text="Decrypt Books", 
                                         command=self.start_decryption)
        self.decrypt_button.grid(row=0, column=0, padx=5)
        
        self.stop_button = ttk.Button(button_frame, text="Stop", 
                                      command=self.stop_decryption, state='disabled')
        self.stop_button.grid(row=0, column=1, padx=5)
        
        # Progress bar
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress.grid(row=7, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=10)
        
        # Status label
        self.status_label = ttk.Label(main_frame, text="Ready", foreground="blue")
        self.status_label.grid(row=8, column=0, columnspan=3, pady=5)
        
        # Output text area with scrollbar
        output_frame = ttk.LabelFrame(main_frame, text="Output", padding="5")
        output_frame.grid(row=9, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=10)
        output_frame.columnconfigure(0, weight=1)
        output_frame.rowconfigure(0, weight=1)
        main_frame.rowconfigure(9, weight=1)
        
        self.output_text = scrolledtext.ScrolledText(output_frame, height=15, width=70, wrap=tk.WORD)
        self.output_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Clear button
        clear_button = ttk.Button(main_frame, text="Clear Output", command=self.clear_output)
        clear_button.grid(row=10, column=0, columnspan=3, pady=5)
        
        # Help text
        help_text = "Enter your 36-character Device ID and User Index to decrypt your Ridibooks library."
        help_label = ttk.Label(main_frame, text=help_text, foreground="gray", wraplength=650)
        help_label.grid(row=11, column=0, columnspan=3, pady=(10, 0))
        
        self.stop_flag = False
        
    def update_device_id_count(self, *args):
        """Update the character count label for Device ID"""
        count = len(self.device_id_var.get())
        self.device_id_count.config(text=f"{count}/36 characters")
        if count == 36:
            self.device_id_count.config(foreground="green")
        elif count > 36:
            self.device_id_count.config(foreground="red")
        else:
            self.device_id_count.config(foreground="gray")
    
    def browse_output_dir(self):
        """Open a directory browser"""
        from tkinter import filedialog
        directory = filedialog.askdirectory(initialdir=self.output_dir_var.get())
        if directory:
            self.output_dir_var.set(directory)
    
    def clear_output(self):
        """Clear the output text area"""
        self.output_text.delete(1.0, tk.END)
    
    def log(self, message, level="info"):
        """Add a message to the output text area"""
        self.queue.put(("log", message, level))
    
    def process_queue(self):
        """Process messages from the worker thread"""
        try:
            while True:
                item = self.queue.get_nowait()
                if item[0] == "log":
                    _, message, level = item
                    self.output_text.insert(tk.END, message + "\n")
                    self.output_text.see(tk.END)
                    
                    # Color based on level
                    if level == "error":
                        start = self.output_text.index(f"end-{len(message)+2}c")
                        end = self.output_text.index("end-1c")
                        self.output_text.tag_add("error", start, end)
                        self.output_text.tag_config("error", foreground="red")
                    elif level == "success":
                        start = self.output_text.index(f"end-{len(message)+2}c")
                        end = self.output_text.index("end-1c")
                        self.output_text.tag_add("success", start, end)
                        self.output_text.tag_config("success", foreground="green")
                        
                elif item[0] == "status":
                    _, message = item
                    self.status_label.config(text=message)
                    
                elif item[0] == "progress":
                    _, mode = item
                    if mode == "start":
                        self.progress.start(10)
                    else:
                        self.progress.stop()
                        
                elif item[0] == "done":
                    self.decrypt_button.config(state='normal')
                    self.stop_button.config(state='disabled')
                    self.progress.stop()
                    
        except queue.Empty:
            pass
        finally:
            self.root.after(100, self.process_queue)
    
    def start_decryption(self):
        """Start the decryption process in a separate thread"""
        device_id = self.device_id_var.get().strip()
        user_idx = self.user_idx_var.get().strip()
        output_dir = Path(self.output_dir_var.get())
        
        # Validate inputs
        try:
            verify(device_id, user_idx)
        except ValueError as e:
            messagebox.showerror("Invalid Input", str(e))
            return
        
        if not output_dir.exists():
            messagebox.showerror("Invalid Output Directory", 
                               "The selected output directory does not exist.")
            return
        
        # Update UI
        self.decrypt_button.config(state='disabled')
        self.stop_button.config(state='normal')
        self.stop_flag = False
        self.clear_output()
        
        # Start worker thread
        thread = threading.Thread(target=self.decrypt_worker, 
                                 args=(device_id, user_idx, output_dir, self.debug_var.get()))
        thread.daemon = True
        thread.start()
    
    def stop_decryption(self):
        """Stop the decryption process"""
        self.stop_flag = True
        self.queue.put(("status", "Stopping..."))
    
    def decrypt_worker(self, device_id, user_idx, output_dir, debug):
        """Worker thread for decryption"""
        try:
            self.queue.put(("progress", "start"))
            self.queue.put(("status", "Finding library..."))
            
            # Get library path and book infos
            lib_path = library_path(user_idx)
            
            if debug:
                self.log(f"Library path: {lib_path}")
            
            if not lib_path.exists():
                self.log(f"Error: Library path does not exist: {lib_path}", "error")
                self.queue.put(("status", "Library not found"))
                return
            
            infos = book_infos(lib_path)
            
            if not infos:
                self.log("No books found in library", "error")
                self.queue.put(("status", "No books found"))
                return
            
            self.log(f"Found {len(infos)} book(s) in library", "success")
            self.queue.put(("status", f"Decrypting {len(infos)} books..."))
            
            success_count = 0
            fail_count = 0
            
            # Decrypt all books
            for i, book_info in enumerate(infos):
                if self.stop_flag:
                    self.log("\nDecryption stopped by user", "error")
                    break
                    
                file_name = book_info.file_name(FileKind.BOOK)
                self.log(f"\nDecrypting {i+1}/{len(infos)}: {file_name}")
                
                try:
                    output_path = decrypt(book_info, device_id, output_dir, debug)
                    self.log(f"  ✓ Saved as: {output_path.name}", "success")
                    success_count += 1
                except Exception as e:
                    self.log(f"  ✗ Failed: {str(e)}", "error")
                    fail_count += 1
                    if debug:
                        import traceback
                        self.log(f"  Debug: {traceback.format_exc()}", "error")
            
            # Final summary
            self.log(f"\n{'='*50}")
            self.log(f"Decryption Complete!", "success")
            self.log(f"  Successful: {success_count} books", "success")
            if fail_count > 0:
                self.log(f"  Failed: {fail_count} books", "error")
            self.log(f"  Output folder: {output_dir}")
            
            self.queue.put(("status", f"Done - {success_count} succeeded, {fail_count} failed"))
            
        except Exception as e:
            self.log(f"\nError: {str(e)}", "error")
            if debug:
                import traceback
                self.log(f"Debug: {traceback.format_exc()}", "error")
            self.queue.put(("status", "Error occurred"))
            
        finally:
            self.queue.put(("progress", "stop"))
            self.queue.put(("done", None))

def main():
    root = tk.Tk()
    app = RidibooksDecryptorGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()