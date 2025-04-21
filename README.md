# Secure-USB

SFORM is a secure desktop application for encrypting, decrypting, compressing, and managing files on USB drives with military-grade AES-256 encryption. The tool provides an intuitive GUI for protecting sensitive data on removable media.

Key Features ✨
Military-Grade Encryption: AES-256 CFB mode encryption for maximum security

Password Protection: SHA-256 hashed master password system

Cloud Backup: Optional Google Drive integration for secure backups

Compression: Built-in file compression using GZIP algorithm

Cross-Platform: Works on Windows, Linux, and macOS

Modern UI: Clean, dark-themed interface using CustomTkinter

Batch Processing: Encrypt/decrypt entire drives or selected files

Secure Password Management: PBKDF2 key derivation with 100,000 iterations
Technical Implementation ⚙️
Encryption: AES-256 via Cryptography library (PBKDF2 key derivation)

Hashing: SHA-256 for password security

Compression: GZIP implementation

Cloud Integration: Google Drive API v3

UI Framework: CustomTkinter for modern interface

Installation 📦
pip install -r requirements.txt
python USB_Protection.py
