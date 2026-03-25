# Ridi_DRM_Remover

`Ridi_DRM_Remover` is a command-line interface and GUI tool that extracts the ebooks you've purchased from Ridi and converts them into DRM-free files, enabling you to read them with your preferred ebook readers. It currently only supports EPUB and PDF formats.

> **Disclaimer**
> 
> All goods obtained through the use of this software must not be shared with, distributed to, or sold for any purpose to others, in any form, under any circumstances. Any consequences resulting from the violation of this provision are solely your responsibility, and the developers of this software bear no responsibility whatsoever. Use at your own risk!

## Prerequisites

To use `Ridi_DRM_Remover`, you need the following:

*   Ridi App
*   Python 3.8 or higher

>If you have windows OS, you can run the .exe directly by downloading it from the releases.

## Installation

1.  **Clone the repository (if you haven't already):**
    ```bash
    git clone https://github.com/Retro-Rex8/Ridi-DRM-Remover
    cd Ridi-DRM-Remover
    ```

2.  **Create a virtual environment (recommended):**
    ```bash
    python -m venv venv
    ```

3.  **Activate the virtual environment:**
    *   **On Windows:**
        ```bash
        .\venv\Scripts\activate
        ```
    *   **On macOS/Linux:**
        ```bash
        source venv/bin/activate
        ```

4.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

## How to Use

### Step 1: Prepare Your Ridi Books

1.  Run the Ridi app installed on your computer.
2.  Download the books you want from the purchases screen.

### Step 2: Decrypt Your Books

You can use either the Graphical User Interface (GUI) or the Command-Line Interface (CLI) to decrypt your books.

(Note: it assumes Default Path for the downloaded books).

#### Using the GUI (Recommended)

Run the GUI application:

```bash
python ridi_books_gui.py
```

1. Click the **"🔍 Auto Detect Credentials"** button to automatically fill in your Device ID and User Index.
2. Select an **Output Folder**.
3. Click **"Decrypt Books"**.

*(If auto-detect fails, you can fill them manually. See "Manual Credential Retrieval" below).*

#### Using the CLI

Run the command-line tool with the `--auto` flag to automatically detect your credentials and decrypt everything:

```bash
python ridi_books.py --auto
```

*(You can also use `--debug` for detailed output: `python ridi_books.py --auto --debug`)*

### Manual Credential Retrieval (Fallback)

If the auto-detection fails, you will need to find your credentials manually:
1. Open a browser, go to <https://ridibooks.com/account/login> and log in.
2. Go to <https://account.ridibooks.com/api/user-devices/app> to get the device information.
3. In the JSON result, find and note down the `user_idx` for your specific device.

Then, supply them manually:
*   **GUI**: Enter them directly into the text fields.
*   **CLI**: `python ridi_books.py --device-id YOUR_DEVICE_ID --user-idx YOUR_USER_INDEX`

## References
* https://github.com/hsj1/ridiculous