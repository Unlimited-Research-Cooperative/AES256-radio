



<h1 align="center">AES256 two way radio, pc-based
<br>
<br>

</div>
<div align="center">
  <a href="https://discord.gg/mJECK72VhD">
    <img src="https://img.shields.io/static/v1?label=Unlimited%20Research%20Cooperative&message=Join%20Now&color=7289DA&logo=discord&style=for-the-badge" alt="Discord server">
  </a>
</div>


<br>
<br>


<br>
<br>

## Overview
### Features

-    AES-256 Encryption: Ensures the confidentiality of transmitted messages.
-    Reed-Solomon Error Correction: Enhances the reliability of data transmission by correcting errors introduced during transmission.
-    AFSK Modulation: Converts digital data to audio signals for transmission over standard radio frequencies.
-    Graphical User Interface: Simplifies user interaction and setup.

### Prerequisites

-    Python 3.6 or higher
-    Required Python packages: numpy, sounddevice, reedsolo, cryptography, tkinter
-    Audio input and output devices for testing and operation

### Installation

Install Python 3.6 or higher.
Install the required packages:
pip install numpy sounddevice reedsolo cryptography
<br>

## Usage
### Running the Application

Save the provided Python script in a file named AES256_radio.py.

Execute the script:

python AES256_radio.py

### Interface Description

- Password Entry: Enter a password to generate the encryption key.
- Device Selection: Select audio input and output devices for both user and radio interfaces.
- Start Communication: Begin the encrypted voice communication process.
<br>

## Main Functions
### Key Generation and Derivation

- generate_key_from_password(password: str) -> str
- get_key_from_password(password: str, encoded_key: str) -> bytes

### Encryption and Decryption

- encrypt_message(message: bytes, key: bytes) -> str
- decrypt_message(encrypted_message: str, key: bytes) -> bytes

### AFSK Modulation

- text_to_afsk(text, baud_rate=1200, mark_freq=1200, space_freq=2200, sample_rate=48000)
- afsk_to_text(signal, baud_rate=1200, mark_freq=1200, space_freq=2200, sample_rate=48000)

### Reed-Solomon Encoding

- encode_reed_solomon(data)
- decode_reed_solomon(data)

### Preamble Handling

- add_preamble(data, preamble="101010101010")
- remove_preamble(data, preamble="101010101010")

### Transmission and Reception

- transmit_message(key, message_text)
- receive_message(key, afsk_signal)

### Example Workflow

- Key Generation: Generates an encryption key from the provided password.
- Message Encryption: Encrypts the input message.
- Error Correction: Applies Reed-Solomon encoding.
- Preamble Addition: Adds a preamble for synchronization.
- Modulation: Converts the message to an AFSK signal for transmission.
- Reception: Receives the AFSK signal and reverses the above steps to retrieve the original message.

### Important Notes

Ensure that the same password is used on both the transmitting and receiving ends to generate matching encryption keys.

Test the system thoroughly in a controlled environment before deploying it in real-world scenarios.

The system relies on proper selection of audio devices for effective operation. Verify device configurations and compatibility.


<br>
<br>
<br>
<br>

    