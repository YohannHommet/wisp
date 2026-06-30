# Wisp CLI — User Guide

This guide describes how to install and use the Wisp command-line tool, whether you are a developer or a general user.

---

## 1. Installation

Choose the installation method that fits your environment:

### Method A: For General Users (Pre-Compiled Binary)
You do **not** need Rust or Cargo installed to use this method.

1. Go to the **GitHub Releases** page for Wisp.
2. Download the binary that matches your operating system and architecture:
   * **Linux:** `wisp-linux-amd64`
   * **macOS:** `wisp-macos-universal` (supports M1/M2/M3 Apple Silicon and Intel)
   * **Windows:** `wisp-windows-amd64.exe`
3. Make the downloaded file executable:
   * **Linux/macOS:** Open a terminal and run `chmod +x wisp`
4. Move the binary into your system's PATH (so you can run it from any directory):
   * **Linux/macOS:** `sudo mv wisp /usr/local/bin/`
   * **Windows:** Move the `.exe` file to a folder (e.g., `C:\Program Files\Wisp`) and add that folder to your System Environment Path.

---

### Method B: For Rust Developers (Cargo Install)
If you have the Rust toolchain installed, you can compile and install Wisp directly:

* **From Source Clone:**
  ```bash
  git clone https://github.com/YohannHommet/wisp.git
  cd wisp
  cargo install --path crates/wisp-cli
  ```

---

## 2. Using Wisp

Wisp operates in two modes: **LAN** (local network, same Wi-Fi/Ethernet) and **WAN** (different networks, over the internet via a relay).

### Case A: Sending Files on the Same Local Network (LAN)
No servers or configuration needed. Wisp uses local multicast (mDNS) to discover the receiver.

1. **On the Sender Machine:**
   Run the `send` command followed by the path of the file:
   ```bash
   wisp send photo.jpg
   ```
   This will print a secure, temporary pairing code:
   ```
     ✦ wisp ready  (LAN)
       file   photo.jpg (3.4 MB)
       from   192.168.1.42:51023
       blake3 a3f9c12e8b4d7…

       on the other machine, run:
         wisp recv 7-tiger-saturn

     waiting for a receiver…
   ```

2. **On the Receiver Machine:**
   Run the `recv` command followed by the pairing code:
   ```bash
   wisp recv 7-tiger-saturn
   ```
   Wisp will authenticate, verify integrity, and save the file in your current folder.

---

### Case B: Sending Files Over the Internet (WAN)
To transfer files across different networks, Wisp uses a stateless rendezvous relay.

1. **Specify a Relay on the Command Line:**
   * **Sender:**
     ```bash
     wisp send --relay http://relay.example.com:7777 photo.jpg
     ```
   * **Receiver:**
     ```bash
     wisp recv --relay http://relay.example.com:7777 7-tiger-saturn
     ```

2. **Make it Easier with a Configuration File (Optional):**
   Instead of typing `--relay` every time, you can save it in a configuration file:
   * Create `config.toml` in your configuration folder:
     * **Linux/macOS:** `~/.config/wisp/config.toml`
     * **Windows:** `%APPDATA%\wisp\config.toml`
   * Add the following content:
     ```toml
     default_relay = "http://relay.example.com:7777"
     default_download_dir = "~/Downloads"
     ```
   * Now, you can run simple commands across the WAN without flags:
     * **Sender:** `wisp send photo.jpg`
     * **Receiver:** `wisp recv 7-tiger-saturn`

---

## 3. Useful Commands & Tips

* **Change the Saved Filename:**
  If you want the receiver to receive the file under a different name, use the `--name` flag:
  ```bash
  wisp send confidential_invoice_v2_draft.pdf --name "invoice.pdf"
  ```
* **Change the Download Folder:**
  By default, files are saved to your current directory (or `default_download_dir` if configured). You can override this dynamically:
  ```bash
  wisp recv 7-tiger-saturn --dir ~/Desktop
  ```
* **Automatic File De-confliction:**
  If you receive a file named `data.txt` and it already exists in your destination folder, Wisp will automatically save it as `data (1).txt` or `data (2).txt` to prevent overwriting your existing data.
