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
    git clone https://https://github.com/meherpraveen/Ridi_DRM_Remover
    cd Ridi_DRM_Remover
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

### Step 2: Get Device Information

1.  Open a browser, go to <https://ridibooks.com/account/login> and log in.
2.  After successfully logging in, go to <https://account.ridibooks.com/api/user-devices/app> to get the device information. Then, in the JSON result, find and note down the values of the fields `device_id` and `user_idx` for the specific device that you use whcih has Ridi app Installed. 

### Step 3: Decrypt Your Books

You can use either the Graphical User Interface (GUI) or the Command-Line Interface (CLI) to decrypt your books.

(Note: it assumes Default Path for the downloaded books).

#### Using the GUI

Run the GUI application:

```bash
python ridi_books_gui.py
```

Enter your `Device ID` and `User Index` in the respective fields, select an `Output Folder`, and click "Decrypt Books".

#### Using the CLI

Run the command-line tool with your `device_id` and `user_idx`:

```bash
python ridi_books.py --device-id YOUR_DEVICE_ID --user-idx YOUR_USER_INDEX
```

*   Replace `YOUR_DEVICE_ID` with the `device_id` you obtained.
*   Replace `YOUR_USER_INDEX` with the `user_idx` you obtained.
*   Add `--debug` flag for detailed output:
    ```bash
    python ridi_books.py --device-id YOUR_DEVICE_ID --user-idx YOUR_USER_INDEX --debug
    ```

## References

* https://github.com/hsj1/ridiculous
