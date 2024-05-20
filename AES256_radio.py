import numpy as np
import sounddevice as sd
import threading
import reedsolo
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from base64 import urlsafe_b64encode, urlsafe_b64decode
import os
import tkinter as tk
from tkinter import ttk

# Key generation and derivation functions
def generate_key_from_password(password: str) -> str:
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(password.encode())
    return urlsafe_b64encode(salt + key).decode()

def get_key_from_password(password: str, encoded_key: str) -> bytes:
    decoded_key = urlsafe_b64decode(encoded_key.encode())
    salt = decoded_key[:16]
    stored_key = decoded_key[16:]
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(password.encode())
    if key != stored_key:
        raise ValueError("The provided password does not match the stored key.")
    return key

# Encryption and decryption functions
def encrypt_message(message: bytes, key: bytes) -> str:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(message) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    encrypted_message = urlsafe_b64encode(iv + ciphertext).decode()
    return encrypted_message

def decrypt_message(encrypted_message: str, key: bytes) -> bytes:
    encrypted_data = urlsafe_b64decode(encrypted_message.encode())
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    message = unpadder.update(padded_data) + unpadder.finalize()
    return message

# AFSK encoding and decoding functions
def text_to_afsk(text, baud_rate=1200, mark_freq=1200, space_freq=2200, sample_rate=48000):
    bits = ''.join(format(ord(c), '08b') for c in text)
    bit_duration = 1 / baud_rate
    t = np.arange(0, len(bits) * bit_duration, 1 / sample_rate)
    signal = np.zeros_like(t)
    for i, bit in enumerate(bits):
        freq = mark_freq if bit == '1' else space_freq
        signal[i * int(bit_duration * sample_rate):(i + 1) * int(bit_duration * sample_rate)] = np.sin(2 * np.pi * freq * t[:int(bit_duration * sample_rate)])
    return signal

def afsk_to_text(signal, baud_rate=1200, mark_freq=1200, space_freq=2200, sample_rate=48000):
    bit_duration = 1 / baud_rate
    num_bits = int(len(signal) / (bit_duration * sample_rate))
    bits = ''
    for i in range(num_bits):
        chunk = signal[i * int(bit_duration * sample_rate):(i + 1) * int(bit_duration * sample_rate)]
        freq = np.fft.fftfreq(len(chunk), 1 / sample_rate)
        fft = np.abs(np.fft.fft(chunk))
        peak_freq = freq[np.argmax(fft)]
        if abs(peak_freq - mark_freq) < abs(peak_freq - space_freq):
            bits += '1'
        else:
            bits += '0'
    text = ''.join(chr(int(bits[i:i + 8], 2)) for i in range(0, len(bits), 8))
    return text

# Reed-Solomon encoding and decoding
def encode_reed_solomon(data):
    rs = reedsolo.RSCodec(10)  # Adds 10 bytes of Reed-Solomon error correction
    return rs.encode(data.encode('utf-8')).decode('latin1')

def decode_reed_solomon(data):
    rs = reedsolo.RSCodec(10)
    return rs.decode(data.encode('latin1')).decode('utf-8')

# Preamble functions
def add_preamble(data, preamble="101010101010"):
    return preamble + data

def remove_preamble(data, preamble="101010101010"):
    if data.startswith(preamble):
        return data[len(preamble):]
    else:
        raise ValueError("Preamble not found")

# Transmitting and receiving functions
def transmit_message(key, user_mic, radio_mic, radio_output):
    def callback(indata, frames, time, status):
        if status:
            print(status)
        try:
            message = encrypt_message(indata.tobytes(), key)
            rs_encoded_message = encode_reed_solomon(message)
            preamble_message = add_preamble(rs_encoded_message)
            afsk_signal = text_to_afsk(preamble_message)
            sd.play(afsk_signal, samplerate=48000, device=radio_output)
        except Exception as e:
            print(f"Error during transmission: {e}")

    with sd.InputStream(callback=callback, channels=1, device=radio_mic):
        sd.sleep(-1)  # Runs indefinitely

def receive_message(key, radio_input, user_output):
    def callback(indata, frames, time, status):
        if status:
            print(status)
        received_signal = indata.flatten()
        received_message = afsk_to_text(received_signal)
        try:
            preamble_removed_message = remove_preamble(received_message)
            rs_decoded_message = decode_reed_solomon(preamble_removed_message)
            decrypted_message = decrypt_message(rs_decoded_message, key)
            sd.play(np.frombuffer(decrypted_message, dtype=np.int16), samplerate=48000, device=user_output)
        except Exception as e:
            print(f"Error decoding message: {e}")
    
    with sd.InputStream(callback=callback, channels=1, device=radio_input):
        sd.sleep(-1)  # Runs indefinitely

def main(key, user_mic, user_headphones, radio_mic, radio_headphones):
    tx_thread = threading.Thread(target=transmit_message, args=(key, user_mic, radio_mic, radio_headphones))
    rx_thread = threading.Thread(target=receive_message, args=(key, radio_mic, user_headphones))

    tx_thread.start()
    rx_thread.start()

    tx_thread.join()
    rx_thread.join()

# GUI implementation
def start_communication():
    password = password_entry.get()
    encoded_key = generate_key_from_password(password)
    key = get_key_from_password(password, encoded_key)
    key_label.config(text="Encrypted Voice Communication Active")
    key_frame.pack_forget()
    active_frame.pack(fill='both', expand=True)
    main(key, user_mic_device.get(), user_headphones_device.get(), radio_mic_device.get(), radio_headphones_device.get())

def populate_device_list():
    devices = sd.query_devices()
    device_names = [device['name'] for device in devices]
    for device_name in device_names:
        user_mic_device['values'] = device_names
        user_headphones_device['values'] = device_names
        radio_mic_device['values'] = device_names
        radio_headphones_device['values'] = device_names

# Create the GUI
root = tk.Tk()
root.title("Encrypted Voice Communication")

key_frame = tk.Frame(root)
key_frame.pack(padx=10, pady=10)

tk.Label(key_frame, text="Enter Password:").pack(side='left')
password_entry = tk.Entry(key_frame, show='*')
password_entry.pack(side='left', padx=5)
tk.Button(key_frame, text="OK", command=start_communication).pack(side='left', padx=5)

device_frame = tk.Frame(root)
device_frame.pack(padx=10, pady=10)

tk.Label(device_frame, text="User Mic Device:").pack(side='left')
user_mic_device = ttk.Combobox(device_frame)
user_mic_device.pack(side='left', padx=5)

tk.Label(device_frame, text="User Headphones Device:").pack(side='left')
user_headphones_device = ttk.Combobox(device_frame)
user_headphones_device.pack(side='left', padx=5)

tk.Label(device_frame, text="Radio Mic Device:").pack(side='left')
radio_mic_device = ttk.Combobox(device_frame)
radio_mic_device.pack(side='left', padx=5)

tk.Label(device_frame, text="Radio Headphones Device:").pack(side='left')
radio_headphones_device = ttk.Combobox(device_frame)
radio_headphones_device.pack(side='left', padx=5)

populate_device_list()

active_frame = tk.Frame(root)
key_label = tk.Label(active_frame, text="")

root.mainloop()
