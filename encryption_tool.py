
from pathlib import Path
import base64
import binascii

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding


# -------------------- FILE NAMES --------------------

KEY_FILE = "secret.key"
RSA_PRIVATE_KEY = "rsa_private.pem"
RSA_PUBLIC_KEY = "rsa_public.pem"


# -------------------- FERNET KEY MANAGEMENT --------------------

def generate_key():
    if Path(KEY_FILE).exists():
        confirm = input(
            "A key already exists. Replace it? (yes/no): "
        ).strip().lower()

        if confirm not in ("yes", "y"):
            print("Existing key kept.")
            return

    key = Fernet.generate_key()
    Path(KEY_FILE).write_bytes(key)

    print("Encryption key generated successfully.")
    print("Keep secret.key private and safe.")


def load_key():
    key_path = Path(KEY_FILE)

    if not key_path.is_file():
        raise FileNotFoundError(
            "secret.key not found. Generate a key using option 1."
        )

    return key_path.read_bytes()


# -------------------- FERNET MESSAGE ENCRYPTION --------------------

def encrypt_message():
    cipher = Fernet(load_key())
    message = input("Enter the message to encrypt: ")

    encrypted = cipher.encrypt(message.encode("utf-8"))

    print("\nEncrypted message:")
    print(encrypted.decode("utf-8"))


def decrypt_message():
    cipher = Fernet(load_key())
    encrypted = input("Enter the encrypted message: ").strip()

    decrypted = cipher.decrypt(encrypted.encode("utf-8"))

    print("\nDecrypted message:")
    print(decrypted.decode("utf-8"))


# -------------------- FERNET FILE ENCRYPTION --------------------

def encrypt_file():
    file_path = Path(
        input("Enter the file path to encrypt: ").strip().strip('"')
    )

    if not file_path.is_file():
        print("File not found.")
        return

    output_path = Path(str(file_path) + ".encrypted")

    if output_path.exists():
        print("Encrypted output already exists. Choose another filename.")
        return

    cipher = Fernet(load_key())
    data = file_path.read_bytes()
    encrypted_data = cipher.encrypt(data)

    output_path.write_bytes(encrypted_data)

    print("File encrypted successfully:")
    print(output_path)


def decrypt_file():
    file_path = Path(
        input("Enter the encrypted file path: ").strip().strip('"')
    )

    if not file_path.is_file():
        print("File not found.")
        return

    if not file_path.name.endswith(".encrypted"):
        print("Choose a file ending in .encrypted.")
        return

    output_path = file_path.with_name(
        file_path.name[:-len(".encrypted")] + ".decrypted"
    )

    if output_path.exists():
        print("Decrypted output already exists. Choose another filename.")
        return

    cipher = Fernet(load_key())
    encrypted_data = file_path.read_bytes()
    decrypted_data = cipher.decrypt(encrypted_data)

    output_path.write_bytes(decrypted_data)

    print("File decrypted successfully:")
    print(output_path)


# -------------------- RSA KEY GENERATION --------------------

def generate_rsa_keys():
    if (
        Path(RSA_PRIVATE_KEY).exists()
        or Path(RSA_PUBLIC_KEY).exists()
    ):
        confirm = input(
            "RSA keys already exist. Replace them? (yes/no): "
        ).strip().lower()

        if confirm not in ("yes", "y"):
            print("Existing RSA keys kept.")
            return

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    Path(RSA_PRIVATE_KEY).write_bytes(private_bytes)
    Path(RSA_PUBLIC_KEY).write_bytes(public_bytes)

    print("RSA keys generated successfully.")
    print("Public key:", RSA_PUBLIC_KEY)
    print("Private key:", RSA_PRIVATE_KEY)
    print("Never share or upload your RSA private key.")


def load_rsa_public_key():
    key_path = Path(RSA_PUBLIC_KEY)

    if not key_path.is_file():
        raise FileNotFoundError(
            "RSA public key not found. Generate RSA keys using option 7."
        )

    return serialization.load_pem_public_key(key_path.read_bytes())


def load_rsa_private_key():
    key_path = Path(RSA_PRIVATE_KEY)

    if not key_path.is_file():
        raise FileNotFoundError(
            "RSA private key not found. Generate RSA keys using option 7."
        )

    return serialization.load_pem_private_key(
        key_path.read_bytes(),
        password=None
    )


# -------------------- RSA MESSAGE ENCRYPTION --------------------

def rsa_encrypt_message():
    public_key = load_rsa_public_key()
    message = input("Enter a short message to encrypt using RSA: ")

    message_bytes = message.encode("utf-8")

    # A 2048-bit RSA key with OAEP and SHA-256
    # supports messages up to 190 bytes.
    maximum_length = (
        public_key.key_size // 8 - 2 * hashes.SHA256.digest_size - 2
    )

    if len(message_bytes) > maximum_length:
        print(
            f"Message is too long for RSA. "
            f"Maximum size: {maximum_length} bytes."
        )
        print("Use the Fernet message encryption option instead.")
        return

    encrypted = public_key.encrypt(
        message_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    print("\nRSA encrypted message:")
    print(base64.b64encode(encrypted).decode("ascii"))


# -------------------- RSA MESSAGE DECRYPTION --------------------

def rsa_decrypt_message():
    private_key = load_rsa_private_key()

    encrypted_text = input(
        "Enter the RSA encrypted message: "
    ).strip()

    encrypted = base64.b64decode(
        encrypted_text,
        validate=True
    )

    decrypted = private_key.decrypt(
        encrypted,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    print("\nRSA decrypted message:")
    print(decrypted.decode("utf-8"))


# -------------------- MAIN MENU --------------------

def main():
    while True:
        print("\n==============================================")
        print("   DATA ENCRYPTION AND DECRYPTION TOOL")
        print("==============================================")
        print("1. Generate Fernet encryption key")
        print("2. Encrypt message")
        print("3. Decrypt message")
        print("4. Encrypt file")
        print("5. Decrypt file")
        print("6. Generate RSA keys")
        print("7. Encrypt message using RSA")
        print("8. Decrypt message using RSA")
        print("9. Exit")
        print("==============================================")

        choice = input("Choose an option: ").strip()

        try:
            if choice == "1":
                generate_key()

            elif choice == "2":
                encrypt_message()

            elif choice == "3":
                decrypt_message()

            elif choice == "4":
                encrypt_file()

            elif choice == "5":
                decrypt_file()

            elif choice == "6":
                generate_rsa_keys()

            elif choice == "7":
                rsa_encrypt_message()

            elif choice == "8":
                rsa_decrypt_message()

            elif choice == "9":
                print("Exiting program.")
                break

            else:
                print("Invalid option. Please choose 1 to 9.")

        except FileNotFoundError as error:
            print("File error:", error)

        except InvalidToken:
            print(
                "Decryption failed. The encrypted data or key "
                "is incorrect."
            )

        except (ValueError, binascii.Error) as error:
            print("Invalid input or decryption failed:", error)

        except Exception as error:
            print("Operation failed:", error)


if __name__ == "__main__":
    main()
