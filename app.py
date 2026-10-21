from flask import Flask, render_template, request, send_file
from PIL import Image
# from cryptography.fernet import Fernet
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from io import BytesIO
import base64
import secrets
import struct

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5 MB upload limit

MAGIC = b"SG01"
SALT_SIZE = 16
ITERATIONS = 600_000


def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
    )
    key = base64.urlsafe_b64encode(
        kdf.derive(password.encode("utf-8"))
    )
    return Fernet(key)


def hide_data(image, data):
    # Store the payload length before the payload itself.
    payload = struct.pack(">I", len(data)) + data
    bits = [
        (byte >> shift) & 1
        for byte in payload
        for shift in range(7, -1, -1)
    ]

    image = image.convert("RGB")
    pixels = list(image.getdata())

    if len(bits) > len(pixels) * 3:
        raise ValueError(
            "Message is too large for this image. Choose a larger image."
        )

    encoded_pixels = []
    bit_index = 0

    for pixel in pixels:
        new_pixel = list(pixel)

        for channel in range(3):
            if bit_index < len(bits):
                new_pixel[channel] = (
                    (new_pixel[channel] & 254) | bits[bit_index]
                )
                bit_index += 1

        encoded_pixels.append(tuple(new_pixel))

    image.putdata(encoded_pixels)
    return image


def extract_data(image):
    image = image.convert("RGB")
    pixels = list(image.getdata())
    capacity = len(pixels) * 3

    if capacity < 32:
        raise ValueError("Image is too small to contain a message.")

    # Read one hidden bit from each color channel.
    def read_bits(start, count):
        bits = []
        for index in range(start, start + count):
            pixel = pixels[index // 3]
            channel = index % 3
            bits.append(pixel[channel] & 1)
        return bits

    # The first 32 bits store the payload length.
    header_bits = read_bits(0, 32)
    length = 0

    for bit in header_bits:
        length = (length << 1) | bit

    if length == 0 or 32 + length * 8 > capacity:
        raise ValueError("No valid hidden message was found.")

    # Recover the hidden bytes.
    payload_bits = read_bits(32, length * 8)
    payload = bytearray()

    for start in range(0, len(payload_bits), 8):
        value = 0
        for bit in payload_bits[start:start + 8]:
            value = (value << 1) | bit
        payload.append(value)

    return bytes(payload)


@app.route("/extract", methods=["GET", "POST"])
def extract():
    if request.method == "GET":
        return render_template("extract.html")

    uploaded = request.files.get("image")
    password = request.form.get("password", "")

    if not uploaded or not uploaded.filename:
        return render_template(
            "extract.html", error="Please select the encoded PNG image."
        )

    if not password:
        return render_template(
            "extract.html", error="Please enter your password."
        )

    try:
        image = Image.open(uploaded.stream)

        # JPEG compression destroys the hidden LSB data.
        if image.format != "PNG":
            return render_template(
                "extract.html",
                error="Please upload the encoded PNG file."
            )

        image.load()
        payload = extract_data(image)

        # Check the payload format and recover the salt.
        if not payload.startswith(MAGIC):
            raise ValueError("No valid STEGANO GUARD message was found.")

        salt_start = len(MAGIC)
        salt = payload[salt_start:salt_start + SALT_SIZE]
        encrypted_message = payload[salt_start + SALT_SIZE:]

        if len(salt) != SALT_SIZE or not encrypted_message:
            raise ValueError("The hidden data is incomplete.")

        # Decrypt with the supplied password.
        cipher = derive_key(password, salt)
        message = cipher.decrypt(encrypted_message).decode("utf-8")

        return render_template("extract.html", message=message)

    except InvalidToken:
        return render_template(
            "extract.html",
            error="Incorrect password or corrupted hidden data."
        )
    except (OSError, ValueError, UnicodeDecodeError):
        return render_template(
            "extract.html",
            error="Unable to extract the message. Check the PNG file."
        )


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/hide", methods=["GET", "POST"])
def hide():
    if request.method == "GET":
        return render_template("hide.html")

    uploaded = request.files.get("image")
    message = request.form.get("message", "").strip()
    password = request.form.get("password", "")

    if not uploaded or not uploaded.filename:
        return "Please select an image.", 400

    if not message or not password:
        return "Message and password are required.", 400

    try:
        # Accept only PNG, JPG, and JPEG image files.
        image = Image.open(uploaded.stream)
        if image.format not in ("PNG", "JPEG"):
            return "Please upload a PNG, JPG, or JPEG image.", 400

        image.load()
        image = image.convert("RGB")

        # Encrypt the message using a password-derived key.
        salt = secrets.token_bytes(SALT_SIZE)
        cipher = derive_key(password, salt)
        encrypted_message = cipher.encrypt(message.encode("utf-8"))

        # Payload format: marker + salt + encrypted message.
        payload = MAGIC + salt + encrypted_message

        # Embed the encrypted payload into the image.
        encoded_image = hide_data(image, payload)

        # Always save the encoded image as PNG.
        output = BytesIO()
        encoded_image.save(output, format="PNG")
        output.seek(0)

        return send_file(
            output,
            mimetype="image/png",
            as_attachment=True,
            download_name="stegano_guard.png",
        )

    except (OSError, ValueError) as error:
        return f"Unable to process image: {error}", 400


if __name__ == "__main__":
    app.run(debug=True)
