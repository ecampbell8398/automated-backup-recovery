# Automated Backup and Recovery System

A secure, command-line backup tool that creates encrypted backups of files and folders and restores them safely.

## Project Objectives
- Create reliable backups of important files and folders
- Protect backup data with strong encryption
- Verify backup integrity before and after restore
- Provide a simple menu-driven interface for non-technical users

## Features
- **Encrypted Backups:** AES-256-GCM encryption
- **Secure Key Derivation:** Password-based key derivation with salt
- **Integrity Checking:** SHA-256 hashing to detect corrupted or tampered backups
- **Backup and Restore:** Create a backup and restore it to a chosen folder
- **List Backups:** View all available backups with date, size, and file count
- **Validation:** Validates backup format and integrity before restore
- **Logging:** Logs backup and restore operations to the `logs/` folder
- **Menu Interface:** Simple options: 1. Create Backup, 2. Restore Backup, 3. View Backups, 4. Exit

## Project Structure