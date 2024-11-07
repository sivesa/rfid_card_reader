# rfid_card_reader

## Overview
The `rfid_card_reader` script is designed to read information from RFID cards using an NFC/RFID reader. It supports various card types and works with compatible readers, including the **ACS ACR122U** RFID reader. The script uses the `pyscard` library for communication with the card reader and can be extended to handle specific RFID card operations, such as reading card data and interacting with card applications.

## Purpose
This script connects to an RFID reader (e.g., ACS ACR122U) and reads data from an RFID card when presented to the reader. It is compatible with other NFC/RFID readers that support the PCSC (Personal Computer/Smart Card) standard, ensuring flexibility with different hardware.

## Installation

### Prerequisites
Before running the script, make sure you have the following software and hardware:
- **ACS ACR122U RFID Reader** (or any PCSC-compatible RFID reader)
- **Python 3.6+**
- **pyscard** library to interact with the RFID reader

### Steps to Install
1. **Install dependencies:**

   First, you'll need to install the `pyscard` library, which enables Python to communicate with the smartcard reader.

   ```bash
   pip install -r requiremens.txt

