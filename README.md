# rfid_card_reader

## Overview
The `rfid_card_reader` script is designed to read information from RFID cards using an NFC/RFID reader. It supports various card types and works with compatible readers, including the **ACS ACR122U** RFID reader. The script uses the `pyscard` library for communication with the card reader and can be extended to handle specific RFID card operations, such as reading card data and interacting with card applications.

## Purpose
This script connects to an RFID reader (e.g., ACS ACR122U) and reads data from an RFID card when presented to the reader. It is compatible with other NFC/RFID readers that support the PCSC (Personal Computer/Smart Card) standard, ensuring flexibility with different hardware.

## Installation

### Prerequisites
Before running the script, make sure you have the following software and hardware:
- **ACS ACR122U RFID Reader** (or any PCSC-compatible RFID reader)
- **Python versions >=3.9,<3.13 are supported**
- **pyscard** library to interact with the RFID reader

### Steps to Install
1. **Install dependencies:**

   First, you'll need to install the `pyscard` library, which enables Python to communicate with the smartcard reader.

```bash
   sudo apt update
   sudo apt install libpcsclite-dev pcscd swig gcc
   sudo systemctl enable --now pcscd
```
   
2. **Create and activate a Python 3.10 virtual environment:**

```bash
   python -m venv .rfid_env
   source .rfid_env/bin/activate
```

3. **Install Python dependencies:**

```bash
   pip install --upgrade pip
   pip install -r requirements.txt
```
