# Pixel-Veil Advanced Steganography Tool (TUI)


PixelVeil is a powerful, terminal-based user interface (TUI) application designed for robust image steganography using Python's Textual framework. It is built for security enthusiasts, students, and CTF players, offering multiple encoding and decoding methods for hiding data within image files.

### Features & Methods
----

It is designed to handle common CTF and steganography challenges with the following included methods:
- LSB
- Alpha Channel Hiding
- Pixel Value Differencing
- Pixel Indicator

### Installation
----
### Prerequisites
- python 3.8+
- python venv (optional)

### Setting up environment
----

## Method A: Using Virutal Environment ( Recommended )

- #### create virtual environment
```yaml
python3 -m venv .venv
```
### activate venv
----
linux:
```yaml
source .venv/bin/activate
```
Windows CMD:
```yaml
.venv\Scripts\activate.bat
```
Windows Powershell:
```yaml
.\venv\Scripts\Activate.ps1
```
### Install Dependencies:
----
```yaml
pip install -r requirements.txt
```
## Method B: Global Install

```yaml
pip install -r requirements.txt --break-system-packages
```
Note: we recommend using method A, as using ```--break-system-packages``` can lead to dependency conflicts with your operating system's core libraries.

## Usage
```yaml
python3 pixelveil.py
```
## Screenshots
### Menu
![PixelVeil Homescreen](assets/homescreen.png?raw=true)
### Method Selection and File Selection:
![Method and File Selection](assets/fileListing.png?raw=true)
### LSB encoding demo:
![LSB Encoding Demo](assets/encoding.png?raw=true)
### Verifying
![Log and Verification](assets/log.png?raw=true)
