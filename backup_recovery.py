
import os
import json
import tarfile
import hashlib
import logging
import secrets
import struct

from pathlib import Path
from datetime import datetime
from getpass import getpass
from io import BytesIO

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


# ==========================================
# AUTOMATED BACKUP AND RECOVERY SYSTEM
# ==========================================

BASE_DIR = Path(__file__).resolve().parent
BACKUP_DIR = BASE_DIR / "backups"
RESTORE_DIR = BASE_DIR / "restored_files"
LOG_DIR = BASE_DIR / "logs"

for directory in (BACKUP_DIR, RESTORE_DIR, LOG_DIR):
    directory.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    filename=LOG_DIR / "backup_activity.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

MAGIC = b"SBACKUP1"
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32

MANIFEST_NAME = "backup_manifest.json"


# ==========================================
# KEY DERIVATION
# ==========================================

def derive_key(password, salt):
    """Derive a 256-bit encryption key using Scrypt."""

    kdf = Scrypt(
        salt=salt,
        length=KEY_SIZE,
        n=2**14,
        r=8,
        p=1
    )

    return kdf.derive(password.encode("utf-8"))


# ==========================================
# SHA-256 HASHING
# ==========================================

def calculate_hash(file_path):
    """Calculate the SHA-256 hash of a file."""

    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            sha256.update(chunk)

    return sha256.hexdigest()


# ==========================================
# BACKUP CREATION
# ==========================================

def create_backup():

    source_input = input(
        "\nEnter the full path of the file or folder to back up: "
    ).strip()

    source = Path(source_input).expanduser()

    if not source.exists() or source.is_symlink():
        print("Error: Source does not exist or is a symbolic link.")
        return

    if not source.is_file() and not source.is_dir():
        print("Error: Only regular files and folders are supported.")
        return

    # Collect files without following symbolic links.
    files = []

    if source.is_file():
        files = [source]
    else:
        for root, dirs, filenames in os.walk(
            source, followlinks=False
        ):
            root_path = Path(root)

            dirs[:] = [
                name for name in dirs
                if not (root_path / name).is_symlink()
            ]

            for filename in filenames:
                file_path = root_path / filename

                if file_path.is_symlink():
                    continue

                if file_path.is_file():
                    files.append(file_path)

    if not files:
        print("No regular files found to back up.")
        return

    # Build the SHA-256 manifest.
    manifest = {}

    for file_path in files:
        relative_path = file_path.relative_to(source.parent)
        manifest[str(relative_path)] = calculate_hash(file_path)

    # Create an unencrypted tar archive in memory.
    archive_buffer = BytesIO()

    with tarfile.open(fileobj=archive_buffer, mode="w") as archive:

        for file_path in files:
            archive.add(
                file_path,
                arcname=str(file_path.relative_to(source.parent)),
                recursive=False
            )

        manifest_data = json.dumps(
            manifest, indent=4
        ).encode("utf-8")

        info = tarfile.TarInfo(MANIFEST_NAME)
        info.size = len(manifest_data)
        info.mode = 0o600

        archive.addfile(info, BytesIO(manifest_data))

    archive_data = archive_buffer.getvalue()

    # Encrypt using AES-256-GCM.
    password = getpass("Create or enter backup encryption password: ")

    if len(password) < 12:
        print("Use a password with at least 12 characters.")
        return

    confirm = getpass("Confirm password: ")

    if password != confirm:
        print("Passwords do not match.")
        return

    salt = secrets.token_bytes(SALT_SIZE)
    nonce = secrets.token_bytes(NONCE_SIZE)

    key = derive_key(password, salt)

    aesgcm = AESGCM(key)

    ciphertext = aesgcm.encrypt(
        nonce,
        archive_data,
        MAGIC + salt
    )

    # Save encrypted backup.
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    backup_name = f"backup_{timestamp}.sbak"
    backup_path = BACKUP_DIR / backup_name

    with open(backup_path, "xb") as backup_file:
        backup_file.write(
            MAGIC + salt + nonce + ciphertext
        )

    try:
        os.chmod(backup_path, 0o600)
    except OSError:
        pass

    logging.info(
        "Backup created: %s | Files: %d",
        backup_name,
        len(files)
    )

    print("\nBACKUP COMPLETED SUCCESSFULLY")
    print("Backup file:", backup_path)
    print("Files backed up:", len(files))
    print("Encryption: AES-256-GCM")
    print("Integrity: SHA-256")


# ==========================================
# BACKUP LISTING
# ==========================================

def list_backups():

    backups = sorted(BACKUP_DIR.glob("*.sbak"))

    print("\nAVAILABLE BACKUPS")

    if not backups:
        print("No backups found.")
        return

    for index, backup in enumerate(backups, 1):
        size = backup.stat().st_size

        print(
            f"{index}. {backup.name} "
            f"({size / 1024:.2f} KB)"
        )


# ==========================================
# SAFE ARCHIVE PATH VALIDATION
# ==========================================

def validate_member_name(name):

    path = Path(name)

    if (
        not name
        or "\x00" in name
        or path.is_absolute()
        or "\\" in name
        or any(part in ("", ".", "..") for part in name.split("/"))
    ):
        raise ValueError("Unsafe archive path detected.")

    return path


# ==========================================
# BACKUP RECOVERY
# ==========================================

def restore_backup():

    backups = sorted(BACKUP_DIR.glob("*.sbak"))

    if not backups:
        print("\nNo backups available.")
        return

    print("\nAVAILABLE BACKUPS")

    for index, backup in enumerate(backups, 1):
        print(f"{index}. {backup.name}")

    try:
        choice = int(input("\nSelect backup number: "))

        if choice < 1 or choice > len(backups):
            print("Invalid selection.")
            return

    except ValueError:
        print("Please enter a valid number.")
        return

    selected_backup = backups[choice - 1]

    password = getpass("Enter backup encryption password: ")

    try:
        encrypted_data = selected_backup.read_bytes()

        minimum_size = len(MAGIC) + SALT_SIZE + NONCE_SIZE + 16

        if len(encrypted_data) < minimum_size:
            raise ValueError("Backup file is incomplete.")

        if not encrypted_data.startswith(MAGIC):
            raise ValueError("Invalid backup file format.")

        offset = len(MAGIC)

        salt = encrypted_data[offset:offset + SALT_SIZE]
        offset += SALT_SIZE

        nonce = encrypted_data[offset:offset + NONCE_SIZE]
        offset += NONCE_SIZE

        ciphertext = encrypted_data[offset:]

        key = derive_key(password, salt)

        aesgcm = AESGCM(key)

        # Decrypt and authenticate the backup.
        archive_data = aesgcm.decrypt(
            nonce,
            ciphertext,
            MAGIC + salt
        )

        print("\nDecryption and authentication successful.")

        # Read the archive without extracting it directly.
        with tarfile.open(
            fileobj=BytesIO(archive_data),
            mode="r:"
        ) as archive:

            members = archive.getmembers()

            manifest_members = [
                member for member in members
                if member.name == MANIFEST_NAME
            ]

            if len(manifest_members) != 1:
                raise ValueError("Missing or duplicate manifest.")

            if not manifest_members[0].isfile():
                raise ValueError("Invalid manifest.")

            manifest_file = archive.extractfile(
                manifest_members[0]
            )

            if manifest_file is None:
                raise ValueError("Cannot read manifest.")

            manifest = json.load(manifest_file)

            if not isinstance(manifest, dict) or not manifest:
                raise ValueError("Invalid or empty manifest.")

            if len(members) != len(manifest) + 1:
                raise ValueError("Archive contents do not match manifest.")

            member_map = {}

            for member in members:

                if member.name == MANIFEST_NAME:
                    continue

                path = validate_member_name(member.name)

                if not member.isfile():
                    raise ValueError(
                        "Unsupported archive entry detected."
                    )

                if member.name in member_map:
                    raise ValueError("Duplicate archive path.")

                if member.name not in manifest:
                    raise ValueError("Unexpected archive file.")

                member_map[member.name] = member

            if set(member_map) != set(manifest):
                raise ValueError("Manifest and archive do not match.")

            # Verify every file before restoring any file.
            verified_files = {}

            for name, expected_hash in manifest.items():

                if not isinstance(expected_hash, str):
                    raise ValueError("Invalid SHA-256 entry.")

                if len(expected_hash) != 64:
                    raise ValueError("Invalid SHA-256 length.")

                try:
                    bytes.fromhex(expected_hash)
                except ValueError:
                    raise ValueError("Invalid SHA-256 format.")

                file_object = archive.extractfile(
                    member_map[name]
                )

                if file_object is None:
                    raise ValueError("Cannot read backup file.")

                data = file_object.read()

                actual_hash = hashlib.sha256(data).hexdigest()

                if not secrets.compare_digest(
                    actual_hash,
                    expected_hash
                ):
                    raise ValueError(
                        f"INTEGRITY FAILURE: {name}"
                    )

                verified_files[name] = data

        print("SHA-256 verification successful.")
        print("All files passed integrity verification.")

        # Restore only after all files pass verification.
        destination = RESTORE_DIR

        print("\nRestore destination:", destination)

        for name in verified_files:
            target = destination.joinpath(
                *validate_member_name(name).parts
            )

            resolved_target = target.resolve()
            resolved_root = destination.resolve()

            if not resolved_target.is_relative_to(resolved_root):
                raise ValueError("Restore path escapes destination.")

            if target.exists() or target.is_symlink():
                raise FileExistsError(
                    f"Refusing to overwrite existing file: {target}"
                )

            if any(
                parent.is_symlink()
                for parent in target.parents
                if parent != destination.parent
            ):
                raise ValueError("Symbolic link in restore path.")

        for name, data in verified_files.items():

            target = destination.joinpath(
                *validate_member_name(name).parts
            )

            target.parent.mkdir(parents=True, exist_ok=True)

            with open(target, "xb") as restored_file:
                restored_file.write(data)

        logging.info(
            "Backup restored: %s | Files: %d",
            selected_backup.name,
            len(verified_files)
        )

        print("\nRECOVERY COMPLETED SUCCESSFULLY")
        print("Files restored:", len(verified_files))
        print("Restored location:", destination)

    except Exception as error:

        logging.error(
            "Recovery failed for %s: %s",
            selected_backup.name,
            error
        )

        print("\nRECOVERY FAILED")
        print("Reason:", error)
        print("No files were intentionally restored before verification.")


# ==========================================
# MAIN MENU
# ==========================================

def main():

    while True:

        print("\n================================")
        print(" AUTOMATED BACKUP AND RECOVERY")
        print("================================")

        print("1. Create encrypted backup")
        print("2. Restore backup")
        print("3. View available backups")
        print("4. Exit")

        choice = input("\nSelect an option: ").strip()

        if choice == "1":
            create_backup()

        elif choice == "2":
            restore_backup()

        elif choice == "3":
            list_backups()

        elif choice == "4":
            print("Exiting backup system.")
            break

        else:
            print("Invalid option. Please try again.")


if __name__ == "__main__":
    main()
