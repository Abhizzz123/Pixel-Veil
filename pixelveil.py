#!/usr/bin/env python3

import os
import sys
from pathlib import Path

# --- Textual Imports ---
from textual.app import App, ComposeResult
from textual.containers import Container, VerticalScroll, Horizontal
from textual.widgets import Button, Header, Footer, Static, Input, RichLog, DirectoryTree, Select
from textual.worker import Worker
from textual import on, work

# --- Third-party Library Imports ---
try:
    from PIL import Image
    import numpy as np
except ImportError:
    print("Error: Required libraries not found.")
    print("Please run: pip install Pillow numpy")
    exit(1)

def _bin2str(binstr: str) -> str:
    """Convert a string of '0'/'1' into text bytes (UTF-8).
    binstr length may not be multiple of 8; tail bits ignored."""
    # collect bytes
    bytes_out = []
    for i in range(0, len(binstr) - 7, 8):
        byte = binstr[i:i+8]
        try:
            bytes_out.append(int(byte, 2))
        except Exception:
            pass
    try:
        return bytes(bytes_out).decode('utf-8', errors='ignore')
    except Exception:
        return ""

def _str2bin(s: str) -> str:
    """Convert text to continuous bitstring (e.g. 'A' -> '01000001')."""
    return ''.join(format(b, '08b') for b in s.encode('utf-8'))

import re
_printable_re = re.compile(rb'[\x20-\x7E]{4,}')  # bytes printable sequences >=4
def _extract_printable(byte_data: bytes, min_len: int = 6):
    """Return list of printable ASCII substrings of at least min_len."""
    return [m.decode('ascii', errors='ignore') for m in re.findall(_printable_re, byte_data) if len(m) >= min_len]

def text_to_bits(text: str):
    """Convert text string to list of bits."""
    bits = []
    for c in text:
        b = format(ord(c), '08b')
        bits.extend([int(bit) for bit in b])
    return bits

def bits_to_text(bits):
    """Convert a list of bits back into text (UTF-8)."""
    chars = []
    for i in range(0, len(bits), 8):
        byte = bits[i:i+8]
        if len(byte) < 8:
            break
        chars.append(chr(int(''.join(map(str, byte)), 2)))
    return ''.join(chars)

def lsb_encode(image_path, message, output_path):
    """Encodes a message using the LSB method with proper termination."""
    try:
        yield f" Opening image: '{image_path}'..."
        img = Image.open(image_path).convert("RGB")
        img_array = np.array(img)
        yield " Converting secret message to binary..."
        message_with_delimiter = message + "::END::"
        message_bits = text_to_bits(message_with_delimiter)
        total_pixels = img_array.size
        if len(message_bits) > total_pixels:
            yield f"[bold red] Error: Message too large! Need {len(message_bits)} bits but image only has {total_pixels} pixels.[/]"
            return
        yield f" Embedding {len(message_bits)} bits into image LSBs..."
        flat = img_array.flatten()
        for i, bit in enumerate(message_bits):
            flat[i] = (flat[i] & 0xFE) | bit
        encoded = flat.reshape(img_array.shape)
        stego_img = Image.fromarray(encoded.astype(np.uint8))
        yield f" Saving encoded image to '{output_path}'..."
        stego_img.save(output_path)
        yield f"[bold green] SUCCESS! Steganographic image saved to: {output_path}[/]"
    except FileNotFoundError:
        yield f"[bold red] Error: Image file '{image_path}' not found![/]"
    except Exception as e:
        yield f"[bold red] Encoding failed: {str(e)}[/]"

def lsb_decode(image_path):
    """Decodes a message from the LSB method."""
    try:
        yield f" Opening image: '{image_path}'..."
        img = Image.open(image_path).convert("RGB")
        img_array = np.array(img)
        yield " Extracting bits from image LSBs..."
        flat = img_array.flatten()
        bits = [flat[i] & 1 for i in range(len(flat))]
        message = ''
        for i in range(0, len(bits), 8):
            byte = bits[i:i+8]
            if len(byte) < 8:
                break
            char = chr(sum(byte[j] << (7 - j) for j in range(8)))
            message += char
            if message.endswith("::END::"):
                message = message[:-7]  # Remove delimiter
                break
        yield f"[bold green] SUCCESS! Decoded message: {message}[/]"
    except FileNotFoundError:
        yield f"[bold red] Error: Image file '{image_path}' not found![/]"
    except Exception as e:
        yield f"[bold red] Decoding failed: {str(e)}[/]"

def pvd_encode(image_path, message, output_path):
    """Enhanced RGB PVD encoder (Wu & Tsai style) with overflow handling."""
    import math
    try:
        yield f" Opening image: '{image_path}'..."
        img = Image.open(image_path).convert("RGB")
        arr = np.array(img, dtype=int)

        message_bits = text_to_bits(message + "::END::")
        bit_idx = 0

        # Wu & Tsai range table
        ranges = [(0, 7), (8, 15), (16, 31), (32, 63), (64, 127), (128, 255)]
        h, w, c = arr.shape

        yield " Embedding message using enhanced RGB PVD..."

        # Precompute range lookup for speed
        range_list = []
        for (lk, uk) in ranges:
            width = uk - lk + 1
            t = int(math.floor(math.log2(width)))
            range_list.append((lk, uk, t))

        # iterate channels then rows for cache friendliness
        for channel in range(c):
            for i in range(h):
                j = 0
                while j < w - 1 and bit_idx < len(message_bits):
                    p = int(arr[i, j, channel])
                    q = int(arr[i, j + 1, channel])
                    d = abs(q - p)

                    # find appropriate range
                    found = False
                    for (lk, uk, t) in range_list:
                        if lk <= d <= uk:
                            found = True
                            break
                    if not found:
                        j += 2
                        continue

                    # how many bits we can embed
                    t_used = min(t, len(message_bits) - bit_idx)
                    if t_used <= 0:
                        break

                    bits_segment = message_bits[bit_idx: bit_idx + t_used]
                    b = int("".join(map(str, bits_segment)), 2)
                    d_prime = lk + b
                    m = d_prime - d  # needed change in difference

                    # Try several adjustment strategies to avoid overflow
                    attempts = []
                    # preserve sign strategy
                    if q >= p:
                        attempts.append((p - (m // 2), q + ((m + 1) // 2)))
                        attempts.append((p - m, q))
                        attempts.append((p, q + m))
                    else:
                        attempts.append((p + (m // 2), q - ((m + 1) // 2)))
                        attempts.append((p + m, q))
                        attempts.append((p, q - m))

                    applied = False
                    for (p_new, q_new) in attempts:
                        p_new = int(round(p_new))
                        q_new = int(round(q_new))
                        if 0 <= p_new <= 255 and 0 <= q_new <= 255 and abs(q_new - p_new) == d_prime:
                            arr[i, j, channel] = p_new
                            arr[i, j + 1, channel] = q_new
                            bit_idx += t_used
                            applied = True
                            break

                    # If none matching the exact difference, try clipped version (best-effort)
                    if not applied:
                        # clipped attempt: clamp and accept small diff change
                        p_try = max(0, min(255, int(round(attempts[0][0])))) if attempts else p
                        q_try = max(0, min(255, int(round(attempts[0][1])))) if attempts else q
                        # only accept if difference moved towards target; avoid huge distortion
                        if abs(abs(q_try - p_try) - d_prime) <= 1:
                            arr[i, j, channel] = p_try
                            arr[i, j + 1, channel] = q_try
                            bit_idx += t_used
                        # else skip this pair (no embedding)
                    j += 2

                if bit_idx >= len(message_bits):
                    break
            if bit_idx >= len(message_bits):
                break

        if bit_idx < len(message_bits):
            yield f"[bold red] Warning: Not all bits embedded. Capacity exhausted. Embedded {bit_idx}/{len(message_bits)} bits.[/]"
        stego_img = Image.fromarray(arr.astype(np.uint8))
        stego_img.save(output_path)
        yield f"[bold green] SUCCESS! Enhanced RGB PVD encoded image saved to: {output_path}[/]"
    except FileNotFoundError:
        yield f"[bold red] Error: Image file '{image_path}' not found![/]"
    except Exception as e:
        yield f"[bold red] Encoding failed: {str(e)}[/]"


def pvd_decode(image_path, channels="RGB", zigzag=True):
    """
    Extract hidden data using PVD (based on gist stegopvd.extract).
    channels: string containing some of 'R','G','B' (e.g. "RGB", "B", "RG")
    zigzag: if True, apply zig-zag row traversal (reverse every odd row)
    This yields log messages and finally yields the decoded string.
    """
    try:
        yield f" Opening image: '{image_path}'..."
        img = Image.open(image_path).convert('RGB')
        w, h = img.size
        iobj = img  # pillow image
        data_bits = ""  # accumulate '0'/'1' chars

        yield f" Image size: {w}x{h}, Channels: {channels}, Zigzag: {zigzag}"

        # iterate rows
        for y in range(h):
            # traversal: x from 1 to w-1 step 2, optionally zigzag flips x for odd rows
            for raw_x in range(1, w, 2):
                x = (-raw_x) % w if (zigzag and (y % 2 == 1)) else raw_x
                try:
                    pixel = dict(zip("RGB", iobj.getpixel((x, y))))
                    prev_pixel = dict(zip("RGB", iobj.getpixel(((x - 1) % w, y))))
                except Exception:
                    continue

                # for each selected channel append extracted bits determined by d ranges
                for c in channels:
                    d = int(abs(pixel[c] - prev_pixel[c]))
                    if 0 <= d <= 7:
                        b, lower = 3, 0
                    elif 8 <= d <= 15:
                        b, lower = 3, 8
                    elif 16 <= d <= 31:
                        b, lower = 4, 16
                    elif 32 <= d <= 63:
                        b, lower = 5, 32
                    elif 64 <= d <= 127:
                        b, lower = 6, 64
                    elif 128 <= d <= 255:
                        b, lower = 7, 128
                    else:
                        continue
                    # append b bits representing d-lower
                    val = d - lower
                    data_bits += format(val, 'b').zfill(b)

        # convert collected bitstring to text and return
        decoded = _bin2str(data_bits)
        yield f"[bold green] SUCCESS! Extracted data length (chars): {len(decoded)}[/]"
        yield decoded
    except FileNotFoundError:
        yield f"[bold red] Error: Image file '{image_path}' not found![/]"
    except Exception as e:
        yield f"[bold red] Extraction failed: {str(e)}[/]"

def pixel_indicator_encode(image_path, message, output_path):
    """Pixel Indicator method:
       groups of 4 pixels: [indicator, p1, p2, p3]
       indicator's blue LSB = 1 => next 3 pixels contain one byte across RGB LSBs (9 bits; use first 8).
    """
    try:
        yield f" Opening image: '{image_path}'..."
        img = Image.open(image_path).convert("RGB")
        arr = np.array(img, dtype=np.uint8)
        h, w, c = arr.shape
        total_pixels = h * w

        bytes_data = message.encode('utf-8') + b"::END::"
        bits = []
        for b in bytes_data:
            bits.extend([int(x) for x in format(b, '08b')])

        group_size = 4
        max_bytes = total_pixels // group_size
        if len(bytes_data) > max_bytes:
            yield f"[bold red] Error: message too large for Pixel Indicator capacity ({max_bytes} bytes).[/]"
            return

        bit_idx = 0
        pix_idx = 0  # linear pixel index
        while bit_idx < len(bits) and (pix_idx + 3) < total_pixels:
            # indicator pixel coordinates
            i = pix_idx // w
            j = pix_idx % w
            # set indicator blue LSB = 1
            arr[i, j, 2] = (arr[i, j, 2] & 0xFE) | 1

            # collect 8 bits from next 3 pixels' RGB LSBs (9 lsb available; take first 8)
            data_bits = []
            for k in range(1, 4):
                pix = pix_idx + k
                ii = pix // w
                jj = pix % w
                # order: R,G,B
                data_bits.append(arr[ii, jj, 0] & 1)
                data_bits.append(arr[ii, jj, 1] & 1)
                data_bits.append(arr[ii, jj, 2] & 1)

            # fill next 8 bits (overwrite the LSBs of those 3 pixels)
            for bpos in range(8):
                pix = pix_idx + 1 + (bpos // 3)
                ii = pix // w
                jj = pix % w
                channel = bpos % 3
                arr[ii, jj, channel] = (arr[ii, jj, channel] & 0xFE) | bits[bit_idx]
                bit_idx += 1
                if bit_idx >= len(bits):
                    break

            pix_idx += group_size

        Image.fromarray(arr).save(output_path)
        yield f"[bold green] SUCCESS! Pixel-Indicator encoded image saved to: {output_path}[/]"
    except FileNotFoundError:
        yield f"[bold red] Error: Image file '{image_path}' not found![/]"
    except Exception as e:
        yield f"[bold red] Encoding failed: {str(e)}[/]"


def pixel_indicator_decode(image_path):
    """Decode Pixel Indicator method."""
    try:
        yield f" Opening image: '{image_path}'..."
        img = Image.open(image_path).convert("RGB")
        arr = np.array(img, dtype=np.uint8)
        h, w, c = arr.shape
        total_pixels = h * w

        group_size = 4
        bytes_out = []
        bits = []

        pix_idx = 0
        while (pix_idx + 3) < total_pixels:
            i = pix_idx // w
            j = pix_idx % w
            indicator_blue_lsb = arr[i, j, 2] & 1
            if indicator_blue_lsb == 1:
                # read next 8 bits from next 3 pixels' RGB LSBs
                byte_bits = []
                for bpos in range(8):
                    pix = pix_idx + 1 + (bpos // 3)
                    ii = pix // w
                    jj = pix % w
                    channel = bpos % 3
                    byte_bits.append(arr[ii, jj, channel] & 1)
                bits.extend(byte_bits)
                # convert to byte
                if len(bits) >= 8:
                    byte = int(''.join(str(x) for x in bits[:8]), 2)
                    bytes_out.append(byte)
                    bits = bits[8:]
                    # quick END check every few bytes
                    if len(bytes_out) >= 7:  # ::END:: length is 7
                        try:
                            s = bytes(bytes_out).decode('utf-8', errors='ignore')
                            if "::END::" in s:
                                s = s.split("::END::")[0]
                                yield f"[bold green] SUCCESS! Decoded message: {s}[/]"
                                return
                        except Exception:
                            pass
            pix_idx += group_size

        # final decode
        s = bytes(bytes_out).decode('utf-8', errors='ignore')
        if "::END::" in s:
            s = s.split("::END::")[0]
        yield f"[bold green] SUCCESS! Decoded message: {s}[/]"
    except FileNotFoundError:
        yield f"[bold red] Error: Image file '{image_path}' not found![/]"
    except Exception as e:
        yield f"[bold red] Decoding failed: {str(e)}[/]"

class PixelVeil(App):
    """A modern terminal-based steganography tool."""

    # --- UPDATED: Clean styling with proper Textual CSS ---
    CSS = """
    Screen {
        background: $surface;
    }

    #main-container {
        layout: grid;
        grid-size: 2 2;
        grid-columns: 1fr 3fr;
        grid-rows: 2fr 1fr;
        grid-gutter: 1;
        padding: 0 1;
        margin-top: 1;
        height: 100%;
    }

    #menu-pane {
        border: heavy $primary;
        background: $surface;
        padding: 1;
    }

    #content-pane {
        border: heavy $accent;
        background: $surface;
        padding: 1;
    }

    #log-pane {
        column-span: 2;
        border: heavy $secondary;
        background: $surface;
        padding: 1;
    }

    #menu-title, #log-title {
        text-align: center;
        text-style: bold;
        margin-bottom: 1;
        color: $text;
    }

    .menu-button {
        width: 100%;
        margin: 1 0;
    }

    #controls-info {
        text-align: center;
        color: $text;
        margin-top: 2;
        padding: 1;
        border: round $secondary;
    }

    #file-info {
        background: $primary-background;
        color: $primary;
        padding: 1;
        margin: 1 0;
        border-left: thick $primary;
    }

    #message-input {
        margin: 1 0;
    }

    #result-display {
        text-align: center;
        padding: 2;
        margin-top: 1;
        background: $background;
        border: double $success;
    }

    DirectoryTree {
        max-height: 15;
        border: solid $primary;
        margin-bottom: 1;
    }

    .hidden {
        display: none;
    }

    #method-description {
        margin-bottom: 1;
        padding: 1;
        border: solid $secondary;
    }
    """
    BINDINGS = [
        ("d", "toggle_dark", "Dark Mode"),
        ("q", "quit", "Quit"),
        ("r", "reset", "Reset UI"),
    ]

    def __init__(self):
        super().__init__()
        self.mode = None
        self.submode = None  
        self.selected_file = None
        self.method_descriptions = {
            "lsb": "Least Significant Bit (LSB) encoding hides the message by replacing the least significant bits of the image pixels with the message bits.",
            "alpha": "Alpha Channel encoding embeds the message into the alpha (transparency) channel of the image.",
            "pvd": "Pixel Value Differencing (PVD) hides data based on the differences between consecutive pixel values, suitable for medium-level CTFs.",
            "pixel": "Pixel Indicator (PIT) marks indicator pixels whose neighbors contain encoded bits — simple, fast, and great for CTFs."
        }

    def compose(self) -> ComposeResult:
        """Create child widgets for the app."""
        yield Header()
        with Container(id="main-container"):
            with VerticalScroll(id="menu-pane") as vs:
                vs.border_title = "Menu"
                yield Static("[b]PixelVeil[/b]", id="menu-title")
                yield Button("LSB", id="lsb", classes="menu-button", variant="primary")
                yield Button("Alpha Channel", id="alpha", classes="menu-button", variant="success")
                yield Button("Pixel Value Differencing", id="pvd", classes="menu-button", variant="warning")
                yield Button("Pixel Indicator", id="pixel", classes="menu-button", variant="success")
                yield Static(
                    "[b]Keyboard Shortcuts[/b]\n" +
                    "• [cyan]Tab/Shift+Tab[/cyan] - Navigate\n" +
                    "• [cyan]Arrow Keys[/cyan] - Move\n" +
                    "• [cyan]Enter[/cyan] - Select\n" +
                    "• [cyan]R[/cyan] - Reset",
                    id="controls-info"
                )
            with VerticalScroll(id="content-pane") as vs:
                vs.border_title = "Content"
                yield Static("Welcome to PixelVeil!\n\nSelect a method to get started.", id="welcome-message")
                yield Static("", id="method-description", classes="hidden")
                yield DirectoryTree("./", id="file-tree", classes="hidden")
                with Horizontal(classes="hidden", id="submode-buttons"):
                    yield Button("Encode", id="encode-choice", variant="success")
                    yield Button("Decode", id="decode-choice", variant="primary")
                yield Static("Enter your secret message:", id="input-label", classes="hidden")
                yield Input(placeholder="Type here...", id="message-input", classes="hidden")
                yield Input(placeholder="Enter output filename (without extension)...", id="output-name", classes="hidden")
                with Horizontal(classes="hidden", id="button-container"):
                    yield Button("Process", id="process-button", variant="success")
                    yield Button("Reset", id="reset-button-content", variant="default")
                yield Static(id="result-display", classes="hidden")
            with Container(id="log-pane") as c:
                c.border_title = "Log"
                yield RichLog(id="log", wrap=True, highlight=True, markup=True)
        yield Footer()

    def write_log(self, message: str):
        """Add message to log panel."""
        self.query_one("#log", RichLog).write(message)

    def action_reset(self):
        """Reset the application to initial state."""
        self.reset_ui()

    def reset_ui(self):
     """Reset the content pane to welcome screen."""
     for widget_id in ["method-description", "file-tree", "submode-buttons", "input-label", "message-input", "button-container", "result-display"]:
        self.query_one(f"#{widget_id}").add_class("hidden")
        self.query_one("#welcome-message").remove_class("hidden")
        self.query_one("#message-input").value = ""
        self.mode = None
        self.submode = None
        self.selected_file = None
        self.query_one("#menu-pane").focus()
        self.write_log(":: Application reset. Ready for new operation.")
 
    @on(Button.Pressed, ".menu-button")
    def handle_menu_selection(self, event: Button.Pressed):
     """Handle method selection."""
     self.mode = event.button.id
     method_name = {
        "lsb": "LSB",
        "alpha": "Alpha Channel",
        "pvd": "Pixel Value Differencing",
        "dct": "DCT",
        "spread": "Spread Spectrum"
     }.get(self.mode, "Unknown")
     self.query_one("#welcome-message").add_class("hidden")
     desc_widget = self.query_one("#method-description")
     desc_widget.update(self.method_descriptions.get(self.mode, "No description available."))
     desc_widget.remove_class("hidden")
    
     # Show file tree directly instead of submode select
     self.query_one("#file-tree").remove_class("hidden")
     self.query_one("#file-tree").focus()
    
     self.write_log(f"Selected method: [bold cyan]{method_name}[/bold cyan]")
     self.write_log("Please select an image file.")

    @on(Button.Pressed, "#encode-choice, #decode-choice")
    def handle_submode_selection(self, event: Button.Pressed):
        """Handle encode/decode selection."""
        self.submode = "encode" if event.button.id == "encode-choice" else "decode"

        # Hide the submode buttons
        self.query_one("#submode-buttons").add_class("hidden")

        self.write_log(f"Selected action: [bold cyan]{self.submode.capitalize()}[/bold cyan]")

        if self.submode == "encode":
            self.query_one("#input-label").remove_class("hidden")
            self.query_one("#message-input").remove_class("hidden")
            self.query_one("#output-name").remove_class("hidden")  # <-- new field
            self.query_one("#message-input").focus()

        self.query_one("#button-container").remove_class("hidden")
        if self.submode == "decode":
            self.query_one("#process-button").focus()

    @on(DirectoryTree.FileSelected)
    def handle_file_selection(self, event: DirectoryTree.FileSelected):
        """Handle file selection from directory tree."""
        file_path = event.path
        valid_extensions = [".png", ".jpg", ".jpeg", ".bmp", ".tiff"]
        if file_path.is_file() and file_path.suffix.lower() in valid_extensions:
           self.selected_file = file_path
                # Hide file tree once a file is chosen
           self.query_one("#file-tree").add_class("hidden")
        # Show encode/decode buttons
           self.query_one("#submode-buttons").remove_class("hidden")
           self.query_one("#encode-choice").focus()
  
           self.write_log(f"File selected: [bold green]{file_path.name}[/bold green]")
           self.write_log("Please choose encode or decode.")
        else:
           self.write_log(f"[bold red]Invalid file type.[/bold red]")

    @on(Button.Pressed, "#process-button")
    def start_process(self):
        """Start the encoding or decoding process."""
        if not self.selected_file:
            self.write_log("[bold red]Error: File must be selected![/bold red]")
            return

        # Get message and filename only for encoding mode
        if self.submode == "encode":
            message = self.query_one("#message-input").value.strip()
            output_name = self.query_one("#output-name").value.strip()

            if not message:
                self.write_log("[bold red]Error: Message must be provided for encoding![/bold red]")
                return
        else:
            message = None
            output_name = None

        # Hide input widgets
        for widget_id in ["input-label", "message-input", "output-name"]:
            self.query_one(f"#{widget_id}").add_class("hidden")

        for widget_id in ["button-container"]:
            self.query_one(f"#{widget_id}").add_class("hidden")

        method_name = {
            "lsb": "LSB",
            "alpha": "Alpha Channel",
            "pvd": "Pixel Value Differencing",
            "dct": "DCT",
            "spread": "Spread Spectrum"
        }.get(self.mode, "Unknown")

        action = self.submode.capitalize()
        self.write_log(f"🚀 [bold blue]Starting {method_name} {action}...[/bold blue]")
        self.perform_process(message)


    @on(Button.Pressed, "#reset-button-content")
    def handle_reset_button(self):
        self.reset_ui()

    @work(exclusive=True, thread=True)
    def perform_process(self, message: str, output_name: str = None):
        """Worker thread for processing."""
        try:
            base_name = self.selected_file.stem
            output_file = None
            if self.submode == "encode":
                if self.submode == "encode":
                    custom_name = self.query_one("#output-name").value.strip()
                    if custom_name:
                       output_file = f"{custom_name}{self.selected_file.suffix}"
                    else:
                        output_file = f"{base_name}_{self.mode}_{self.submode}ed{self.selected_file.suffix}"
                if self.mode == "lsb":
                    processor = lsb_encode(str(self.selected_file), message, output_file)
                elif self.mode == "alpha":
                    processor = alpha_encode(str(self.selected_file), message, output_file)
                elif self.mode == "pvd":
                    processor = pvd_encode(str(self.selected_file), message, output_file)
                elif self.mode == "pixel":
                    processor = pixel_indicator_encode(str(self.selected_file), message, output_file)
                else:
                    raise ValueError("Unknown mode")
            else:  # decode
                if self.mode == "lsb":
                    processor = lsb_decode(str(self.selected_file))
                elif self.mode == "alpha":
                    processor = alpha_decode(str(self.selected_file))
                elif self.mode == "pvd":
                    processor = pvd_decode(str(self.selected_file))
                elif self.mode == "pixel":
                    processor = pixel_indicator_decode(str(self.selected_file))
                else:
                    raise ValueError("Unknown mode")

            success = False
            final_message = ""
            decoded_text = ""
            for step_message in processor:
                self.call_from_thread(self.write_log, step_message)
                if "SUCCESS" in step_message:
                    success = True
                    if self.submode == "decode":
                        # Extract decoded message from the last yield
                        decoded_text = step_message.split("Decoded message: ")[-1].strip("[/]")
                    else:
                        final_message = f"Output File: [bold cyan]{output_file}[/bold cyan]"

            self.call_from_thread(self.show_result, success, final_message or decoded_text)
        except Exception as e:
            error_msg = f" [bold red]Worker failed: {str(e)}[/bold red]"
            self.call_from_thread(self.write_log, error_msg)
            self.call_from_thread(self.show_result, False, "")

    def show_result(self, success: bool, result_text: str):
        """Display result in the content pane."""
        result_widget = self.query_one("#result-display")
        if success:
            if self.submode == "encode":
                result_widget.update(
                    f"[bold green]Encoding Successful![/bold green]\n\n" +
                    result_text
                )
            else:
                result_widget.update(
                    f"[bold green]Decoding Successful![/bold green]\n\n" +
                    f"Decoded Message: [bold cyan]{result_text}[/bold cyan]"
                )
        else:
            result_widget.update(
                f"[bold red]Process Failed[/bold red]\n\n" +
                f"Check the log for details."
            )
        result_widget.remove_class("hidden")
        self.query_one("#button-container").remove_class("hidden")
        self.query_one("#reset-button-content").focus()

if __name__ == "__main__":
    app = PixelVeil()
    app.run()
