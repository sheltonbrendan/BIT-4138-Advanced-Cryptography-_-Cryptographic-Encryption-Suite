from flask import Flask, render_template, request
import hashlib
import time
import random
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

from spn_cipher import (
    encrypt_block,
    encrypt_text,
    decrypt_text,
    text_to_blocks,
    avalanche_test,
    hamming_distance,
)

from cryptanalysis_toolkit import (
    differential_trace,
    linear_approximation_bias,
    frequency_table,
    avalanche_statistics,
    algebraic_attack_xor,
)

app = Flask(__name__)
app.secret_key = "crypto_project_secret_key"


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/hashing', methods=['GET', 'POST'])
def hashing_page():
    result = ""
    if request.method == 'POST':
        text = request.form['text']
        result = hashlib.sha256(text.encode()).hexdigest()
    return render_template('hashing.html', result=result)


@app.route('/symmetric', methods=['GET', 'POST'])
def symmetric():
    encrypted = ""
    decrypted = ""
    aes_time = 0
    filename_used = ""

    key = Fernet.generate_key()
    cipher = Fernet(key)

    if request.method == 'POST':
        uploaded_file = request.files.get('file_input')

        if uploaded_file and uploaded_file.filename != '':
            message_bytes = uploaded_file.read()
        else:
            message_text = request.form.get('message', '')
            message_bytes = message_text.encode()

        if message_bytes:
            start_time = time.time()
            encrypted_bytes = cipher.encrypt(message_bytes)
            decrypted_bytes = cipher.decrypt(encrypted_bytes)
            aes_time = round((time.time() - start_time) * 1000, 4)

            encrypted = encrypted_bytes.decode()
            decrypted = decrypted_bytes.decode()

    return render_template('symmetric.html',
                           encrypted=encrypted,
                           decrypted=decrypted,
                           aes_time=aes_time,
                           filename_used=filename_used)


@app.route('/asymmetric', methods=['GET', 'POST'])
def asymmetric():
    encrypted = ""
    decrypted = ""

    if request.method == 'POST':
        message = request.form['message']

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()

        encrypted_bytes = public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        decrypted_bytes = private_key.decrypt(
            encrypted_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        encrypted = encrypted_bytes.hex()
        decrypted = decrypted_bytes.decode()

    return render_template('asymmetric.html',
                           encrypted=encrypted,
                           decrypted=decrypted)


# =========================
# WEEK 6: SPN ROUTE (ADDED)
# =========================
@app.route("/spn", methods=["GET", "POST"])
def spn():
    result = None
    trace = None
    avalanche = None
    error = None

    if request.method == "POST":
        action = request.form.get("action", "encrypt")
        key = int(request.form.get("key", 43981))
        rounds = int(request.form.get("rounds", 4))
        plaintext = request.form.get("plaintext", "")

        try:
            if action == "encrypt":
                blocks = encrypt_text(plaintext, key, rounds)
                result = {
                    "ciphertext_hex": [f"0x{b:04X}" for b in blocks],
                    "ciphertext_blocks": blocks,
                }

                first_block = text_to_blocks(plaintext)[0]
                _, trace = encrypt_block(first_block, key, rounds, trace=True)

                avalanche = avalanche_test(
                    first_block, key, rounds,
                    flip_bit=0,
                    flip_target="plaintext"
                )

            elif action == "decrypt":
                raw_blocks = [b.strip() for b in plaintext.split(",") if b.strip()]
                blocks = [int(b, 16) for b in raw_blocks]
                decrypted_text = decrypt_text(blocks, key, rounds)
                result = {"plaintext": decrypted_text}

        except Exception as exc:
            error = str(exc)

    return render_template("spn.html",
                           result=result,
                           trace=trace,
                           avalanche=avalanche,
                           error=error)


# =========================
# WEEK 7: CRYPTANALYSIS ROUTE (ADDED)
# =========================
@app.route('/cryptanalysis', methods=['GET', 'POST'])
def cryptanalysis():
    diff_result = None
    freq_result = None
    linear_result = None
    avalanche_result = None
    algebraic_result = None

    if request.method == "POST":
        tool = request.form.get("tool")

        if tool == "algebraic":
            p = int(request.form.get("plaintext_alg", 12))
            k = int(request.form.get("key_alg", 5))
            c = p ^ k
            algebraic_result = {
                "plaintext": p,
                "key": k,
                "ciphertext": c,
                "recovered_key": algebraic_attack_xor(p, c),
            }

        elif tool == "difference":
            p1 = int(request.form.get("plaintext1", 18533))
            p2 = int(request.form.get("plaintext2", 18532))
            key = int(request.form.get("key", 43981))
            rounds = int(request.form.get("rounds", 4))
            diff_result = differential_trace(p1, p2, key, rounds)

        elif tool == "linear":
            key = int(request.form.get("key", 43981))
            rounds = int(request.form.get("rounds", 4))
            linear_result = linear_approximation_bias(
                key, rounds, num_samples=5000, seed=42
            )

        elif tool == "frequency":
            text = request.form.get("text", "")
            freq_result = frequency_table(text)

        elif tool == "avalanche":
            key = int(request.form.get("key", 43981))
            rounds = int(request.form.get("rounds", 4))
            avalanche_result = avalanche_statistics(
                key, rounds, num_samples=500, seed=42
            )

    return render_template("cryptanalysis.html",
                           diff_result=diff_result,
                           freq_result=freq_result,
                           linear_result=linear_result,
                           avalanche_result=avalanche_result,
                           algebraic_result=algebraic_result)


@app.route('/classical', methods=['GET', 'POST'])
def classical():
    return render_template("classical.html")


@app.route('/stream', methods=['GET', 'POST'])
def stream():
    return render_template("stream.html")


@app.route('/threats')
def threats():
    return render_template('threats.html')


if __name__ == '__main__':
    app.run(debug=True)