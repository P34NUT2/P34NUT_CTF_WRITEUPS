# V1t CTF 2025

# polyglot

## Forensics / Steganography

**Tags:** `steganography`, `polyglot`, `file-forensics`, `multimedia-analysis`

---

## Description
Look, read, and most importantly, WATCH the duck!

---

## Files
- `polyglot.png` - A polyglot file (works as multiple file types)
- Note: Challenge description says "File can only open in Windows" but this is false - everything can be done on Linux by opening with a browser or appropriate tools

---

## Analysis

First, I uploaded the image to CyberChef and noticed it contains multiple file signatures including `.mp4`, `.pdf`, and `.zip` markers. This is a classic case of **polyglot files** (files that are valid in multiple formats simultaneously).

The visible image shows:
<img width="893" height="939" alt="duck" src="https://github.com/user-attachments/assets/f434869d-0cfb-4d0f-9d65-0e4cd2c371e9" />


Thanks to CyberChef, we can confirm this is a classic case of **steganography** using polyglot file techniques. We just need to rename the file with different extensions (`.pdf`, `.zip`, `.mp4`, `.html`) and search for the flag in each format.

---

## Theory

To solve this challenge you need to understand:

### **Polyglot Files**
A polyglot file is a file that is valid in multiple file formats simultaneously. This is possible because different file formats have their magic bytes (signatures) at different offsets. For example:
- **PNG signature**: `89 50 4E 47` at offset 0
- **ZIP signature**: `50 4B 03 04` can be at any offset
- **PDF signature**: `25 50 44 46` at offset 0

By carefully crafting a file, you can make it valid as multiple formats at once. In this challenge, `polyglot.png` is simultaneously a valid PNG, MP4, PDF, HTML, and ZIP file.

### **Steganography**
The practice of hiding secret data within ordinary, non-secret files. Unlike encryption (which makes data unreadable), steganography hides the existence of the data itself. Common techniques include:
- **LSB (Least Significant Bit)** - Hiding data in the least significant bits of image pixels
- **EOF (End of File)** - Appending data after the normal file end marker
- **Metadata** - Hiding data in EXIF or other metadata fields

### **File Signatures (Magic Bytes)**
Every file format has a unique sequence of bytes at the beginning (or specific offsets) that identifies it:
```
PNG:  89 50 4E 47 0D 0A 1A 0A
JPEG: FF D8 FF
PDF:  25 50 44 46 (translates to "%PDF")
ZIP:  50 4B 03 04
MP4:  Various, typically "ftyp" box
```

The `file` command in Linux reads these bytes to identify file types, regardless of extension.

### **Steghide - Steganography Tool**
Steghide is a steganography program that hides data inside image and audio files. Key features:

**How it works:**
- Embeds data by replacing redundant bits in the cover file
- Uses password-based encryption (AES-128)
- Supports JPEG, BMP, WAV, and AU formats
- Compressed and encrypted before embedding

**Basic commands:**
```bash
# Hide data
steghide embed -cf cover_image.jpg -ef secret.txt -p password123

# Extract data
steghide extract -sf cover_image.jpg -p password123

# Get info without extracting
steghide info cover_image.jpg
```

**Important notes:**
- Always requires a password (even if empty string)
- Cannot detect if a file contains steghide data without trying to extract
- Changes file slightly, but imperceptible to human eye

### **FFmpeg - Multimedia Processing**
FFmpeg is a powerful command-line tool for handling video, audio, and multimedia files.

**Common operations:**
```bash
# Copy streams without re-encoding (fast, lossless)
ffmpeg -i input.mp4 -c copy output.mp4

# Extract audio from video
ffmpeg -i video.mp4 -vn -acodec copy audio.aac

# Convert formats
ffmpeg -i input.avi -c:v libx264 -c:a aac output.mp4

# Cut video
ffmpeg -i input.mp4 -ss 00:00:10 -t 00:00:30 -c copy output.mp4
```

In this challenge, we use `-c copy` to copy all streams without re-encoding, which repairs the "corrupted" polyglot MP4.

### **ZIP Archive Structure**
ZIP files have a flexible structure that allows them to be embedded within other files:
```
[Optional prepend data]  ← Other file formats can be here!
[Local file headers + compressed data]
[Central directory]
[End of central directory record]
```

This is why you can append ZIP data to other files and still extract them successfully.

### **File Analysis Tools**
- **`file`** - Identifies file type by reading magic bytes
- **`binwalk`** - Scans for embedded files and executable code
- **`exiftool`** - Reads and writes metadata in files
- **`strings`** - Extracts readable text from binary files
- **CyberChef** - Web-based tool for analyzing and transforming data

---

## Solution

### Step 1: Analyzing with CyberChef

CyberChef is a web-based tool for analyzing files. Upload the file and you'll see multiple file signatures:

```
89 50 4E 47  → PNG signature
25 50 44 46  → PDF signature  
50 4B 03 04  → ZIP signature
... ftyp ... → MP4 signature
```

This confirms it's a polyglot file. The visible image shows:
![Duck Image](./photos/duck.png)

**Why this works:** Different programs read files differently. PNG readers stop at PNG data, ZIP programs look for ZIP signatures anywhere in the file, etc.

### Step 2: HTML False Flag

First, rename the file to `.html` and open it:

```bash
cp polyglot.png polyglot.html
firefox polyglot.html
```

The HTML is a red herring designed to mislead:
<img width="795" height="165" alt="html" src="https://github.com/user-attachments/assets/1ebacd83-1b18-4195-9404-96b4b7d16697" />

**Analysis:** The browser interprets the beginning of the file as HTML. This is just a distraction, so we move on.

### Step 3: Extracting the MP4 Video

Next, rename to `.mp4`:

```bash
cp polyglot.png polyglot.mp4
vlc polyglot.mp4  # or any video player
```

**Problem:** The video cuts off early because the MP4 container is corrupted by the other file formats mixed in.

**Solution:** Use FFmpeg to repair and extract clean video:

```bash
ffmpeg -i polyglot.mp4 -c copy clean_duck.mp4
```

**What this does:**
- `-i polyglot.mp4` - Input file
- `-c copy` - Copy codec (no re-encoding, just copies valid streams)
- `clean_duck.mp4` - Output clean video

FFmpeg intelligently skips corrupted data and extracts valid MP4 streams.

Now we can watch the complete video. At the very end, it reveals a password:

**`HideTheDuck123@`**

We don't know what this password is for yet, so we continue.

### Step 4: PDF with Steghide Clue

Rename the file to `.pdf`:

```bash
cp polyglot.png polyglot.pdf
evince polyglot.pdf  # or any PDF reader
```

Opening the PDF reveals a poem. The title is crucial:
- **"The Zoo and the Steghide Secret"**

**Key insight:** The word **"Steghide"** tells us:
1. There's hidden data somewhere
2. It's protected with the Steghide tool
3. We'll need a password (which we found in the video!)

### Step 5: ZIP Archive Extraction

Rename to `.zip` and extract:

```bash
cp polyglot.png polyglot.zip
unzip polyglot.zip
```

**Output:**
```
Archive:  polyglot.zip
  extracting: angri.jpg
```

This extracts an image file:
![angri](https://github.com/user-attachments/assets/1d208fc7-67ed-40a2-9694-79bd40e35407)

**Analysis:** This image looks normal, but given the Steghide clue from the PDF, we know it contains hidden data.

### Step 6: Steghide Extraction (Final Step)

Now we use Steghide with the password from the video:

```bash
steghide extract -sf angri.jpg -p HideTheDuck123@
```

**Command breakdown:**
- `extract` - Extract hidden data
- `-sf angri.jpg` - Stegofile (file containing hidden data)
- `-p HideTheDuck123@` - Password for extraction

**Output:**
```
wrote extracted data to "flag.txt".
```

Read the flag:
```bash
cat flag.txt
v1t{duck_l0v3_w4tch1ng_p2r3}
```

**What happened:** Steghide decrypted and extracted data that was hidden in the LSB (Least Significant Bits) of the image pixels. This data was compressed and encrypted, making it impossible to detect without the password.

**CHALLENGE SOLVED!** 🦆

---

## Flag
> **v1t{duck_l0v3_w4tch1ng_p2r3}**

---

## How to avoid

To prevent **steganography-based data exfiltration** and **polyglot file attacks** like this in a production environment:

### 1. **File Type Validation**
- **Never trust file extensions** - always validate based on file signatures (magic bytes)
- Use multiple validation layers: extension, MIME type, and content analysis
- Reject polyglot files that have multiple valid file signatures

**Example Implementation:**
```python
import magic
import mimetypes
from pathlib import Path

def validate_file_upload(file_path, allowed_types):
    """
    Secure file validation using multiple methods
    """
    # Check file extension
    extension = Path(file_path).suffix.lower()
    
    # Get MIME type from content (not extension)
    mime = magic.from_file(file_path, mime=True)
    
    # Get expected MIME from extension
    expected_mime, _ = mimetypes.guess_type(file_path)
    
    # Reject if MIME doesn't match extension
    if mime != expected_mime:
        raise ValueError(f"File signature mismatch: {mime} != {expected_mime}")
    
    # Check against allowlist
    if mime not in allowed_types:
        raise ValueError(f"File type {mime} not allowed")
    
    return True

# Usage
ALLOWED_TYPES = ['image/png', 'image/jpeg', 'application/pdf']
validate_file_upload('upload.png', ALLOWED_TYPES)
```

### 2. **Content Sanitization**
- Strip metadata from uploaded files using tools like `exiftool`
- Re-encode images to remove embedded data
- Convert files to safe formats before storage

**Example with PIL (Python Imaging Library):**
```python
from PIL import Image
import io

def sanitize_image(input_path, output_path):
    """
    Re-encode image to strip hidden data
    """
    # Open and immediately save to new file
    # This removes metadata and embedded content
    img = Image.open(input_path)
    
    # Remove EXIF data
    data = list(img.getdata())
    image_without_exif = Image.new(img.mode, img.size)
    image_without_exif.putdata(data)
    
    # Save as new file
    image_without_exif.save(output_path, quality=95, optimize=True)
    
    return output_path
```

### 3. **Polyglot Detection**
- Scan for multiple file signatures in a single file
- Use tools like `binwalk` to detect embedded files
- Implement entropy analysis to detect hidden data

**Example Polyglot Detection:**
```python
import subprocess
import re

def detect_polyglot(file_path):
    """
    Detect if file contains multiple format signatures
    """
    # Use binwalk to find embedded files
    result = subprocess.run(
        ['binwalk', '-e', file_path],
        capture_output=True,
        text=True
    )
    
    # Count detected signatures
    signatures = re.findall(r'\d+\s+0x[0-9A-F]+\s+([^\n]+)', result.stdout)
    
    if len(signatures) > 1:
        raise ValueError(f"Polyglot file detected: {signatures}")
    
    return True
```

### 4. **Steganography Detection**
- Implement statistical analysis to detect steganographic content
- Use tools like `stegdetect` or `zsteg` in your upload pipeline
- Monitor file entropy levels

**Example Entropy Check:**
```python
import math
from collections import Counter

def calculate_entropy(file_path):
    """
    Calculate Shannon entropy to detect hidden data
    """
    with open(file_path, 'rb') as f:
        data = f.read()
    
    if not data:
        return 0
    
    # Calculate byte frequency
    entropy = 0
    counter = Counter(data)
    length = len(data)
    
    for count in counter.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    
    return entropy

# High entropy (close to 8) may indicate encryption or steganography
entropy = calculate_entropy('suspicious_file.png')
if entropy > 7.5:
    print("Warning: High entropy detected - possible hidden data")
```

### 5. **Network-Level Protections**
- Implement Data Loss Prevention (DLP) systems
- Monitor outbound traffic for unusual file transfers
- Block known steganography tools at the network level
- Use web application firewalls (WAF) with file upload inspection

### 6. **Security Best Practices**
```python
from werkzeug.utils import secure_filename
import os
import hashlib

def secure_file_upload(file, upload_folder, max_size_mb=5):
    """
    Comprehensive secure file upload implementation
    """
    # 1. Validate file exists
    if not file or file.filename == '':
        raise ValueError("No file provided")
    
    # 2. Secure the filename
    filename = secure_filename(file.filename)
    
    # 3. Check file size
    file.seek(0, os.SEEK_END)
    size = file.tell()
    file.seek(0)
    
    max_size = max_size_mb * 1024 * 1024
    if size > max_size:
        raise ValueError(f"File too large: {size} bytes")
    
    # 4. Generate unique filename to prevent overwrites
    file_hash = hashlib.sha256(file.read()).hexdigest()[:16]
    file.seek(0)
    
    name, ext = os.path.splitext(filename)
    unique_filename = f"{name}_{file_hash}{ext}"
    
    # 5. Save to secure location
    filepath = os.path.join(upload_folder, unique_filename)
    file.save(filepath)
    
    # 6. Validate file type
    validate_file_upload(filepath, ALLOWED_TYPES)
    
    # 7. Sanitize content
    sanitize_image(filepath, filepath)
    
    # 8. Check for polyglots
    detect_polyglot(filepath)
    
    return unique_filename
```

### 7. **Detection Tools**
- **Binwalk**: Detect embedded files and file signatures
- **Exiftool**: View and remove metadata
- **Stegdetect**: Detect steganographic content in images
- **Zsteg**: Detect LSB steganography in PNG and BMP
- **Steghide**: Test if files contain steghide-hidden data

**Example Security Scan Script:**
```bash
#!/bin/bash
# scan_upload.sh - Comprehensive file security scan

FILE=$1

echo "[+] Scanning file: $FILE"

# Check file type
echo "[*] File type analysis:"
file $FILE
echo ""

# Detect embedded files
echo "[*] Searching for embedded content:"
binwalk $FILE
echo ""

# Check for steganography
echo "[*] Steganography detection:"
stegdetect $FILE
zsteg $FILE
echo ""

# View metadata
echo "[*] Metadata analysis:"
exiftool $FILE
echo ""

# Calculate entropy
echo "[*] Entropy analysis:"
ent $FILE

echo "[+] Scan complete"
```

### References:
- [OWASP: File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
- [Binwalk Documentation](https://github.com/ReFirmLabs/binwalk)
- [Steganography Detection Techniques](https://www.garykessler.net/library/file_sigs.html)
- [NIST Guide to Malware Incident Prevention](https://csrc.nist.gov/publications/detail/sp/800-83/rev-1/final)
- [File Signature Database](https://www.filesignatures.net/)

---

> **Author:** Jose Antonio Villafaña Montes de Oca
