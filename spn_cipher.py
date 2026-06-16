"""
spn_cipher.py
Substitution-Permutation Network (SPN) implementation.
"""

# S-BOX

SBOX = [0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD,
        0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2]

INV_SBOX = [0] * 16
for i, val in enumerate(SBOX):
    INV_SBOX[val] = i


# SUBSTITUTION

def substitute(state, sbox=SBOX):
    result = 0
    for shift in (12, 8, 4, 0):
        nibble = (state >> shift) & 0xF
        result |= sbox[nibble] << shift
    return result


# PERMUTATION

def _get_bit(state, pos):
    return (state >> (15 - pos)) & 1


def permute(state):
    result = 0
    for i in range(4):
        for j in range(4):
            bit = _get_bit(state, 4 * i + j)
            new_pos = 4 * j + i
            result |= bit << (15 - new_pos)
    return result


# KEY SCHEDULE

def generate_round_keys(key, rounds):
    key &= 0xFFFF
    round_keys = []

    for r in range(rounds + 1):
        shift = (3 * r) % 16

        if shift == 0:
            rk = key
        else:
            rk = ((key << shift) | (key >> (16 - shift))) & 0xFFFF

        round_keys.append(rk)

    return round_keys


# ENCRYPTION

def encrypt_block(plaintext, key, rounds=4, trace=False):
    round_keys = generate_round_keys(key, rounds)

    state = plaintext & 0xFFFF
    steps = [("Plaintext", 0, state)]

    for r in range(rounds):

        state ^= round_keys[r]
        steps.append((f"Round {r + 1}: Key Mixing", r + 1, state))

        state = substitute(state, SBOX)
        steps.append((f"Round {r + 1}: S-Box", r + 1, state))

        if r < rounds - 1:
            state = permute(state)
            steps.append((f"Round {r + 1}: Permutation", r + 1, state))

    state ^= round_keys[rounds]
    steps.append(("Final Key Mixing", rounds, state))

    if trace:
        return state, steps

    return state


# DECRYPTION

def decrypt_block(ciphertext, key, rounds=4, trace=False):
    round_keys = generate_round_keys(key, rounds)

    state = ciphertext & 0xFFFF
    steps = [("Ciphertext", rounds, state)]

    state ^= round_keys[rounds]
    steps.append(("Undo Final Key Mixing", rounds, state))

    state = substitute(state, INV_SBOX)
    steps.append((f"Round {rounds}: Inverse Substitution", rounds, state))

    for r in range(rounds - 1, 0, -1):

        state ^= round_keys[r]
        steps.append((f"Round {r + 1}: Undo Key Mixing", r, state))

        state = permute(state)
        steps.append((f"Round {r}: Inverse Permutation", r, state))

        state = substitute(state, INV_SBOX)
        steps.append((f"Round {r}: Inverse Substitution", r, state))

    state ^= round_keys[0]
    steps.append(("Undo Initial Key Mixing", 0, state))

    if trace:
        return state, steps

    return state


# TEXT HELPERS

def text_to_blocks(text):
    if len(text) % 2 != 0:
        text += " "

    blocks = []

    for i in range(0, len(text), 2):
        block = (ord(text[i]) << 8) | ord(text[i + 1])
        blocks.append(block)

    return blocks


def blocks_to_text(blocks):
    chars = []

    for block in blocks:
        chars.append(chr((block >> 8) & 0xFF))
        chars.append(chr(block & 0xFF))

    return "".join(chars)


def encrypt_text(text, key, rounds=4):
    return [encrypt_block(block, key, rounds)
            for block in text_to_blocks(text)]


def decrypt_text(blocks, key, rounds=4):
    return blocks_to_text(
        [decrypt_block(block, key, rounds)
         for block in blocks]
    )


# AVALANCHE EFFECT

def hamming_distance(a, b):
    return bin(a ^ b).count("1")


def avalanche_test(
        plaintext,
        key,
        rounds=4,
        flip_bit=0,
        flip_target="plaintext"):

    original_cipher = encrypt_block(
        plaintext,
        key,
        rounds
    )

    if flip_target == "key":

        modified_key = key ^ (1 << flip_bit)

        modified_cipher = encrypt_block(
            plaintext,
            modified_key,
            rounds
        )

    else:

        modified_plaintext = plaintext ^ (1 << flip_bit)

        modified_cipher = encrypt_block(
            modified_plaintext,
            key,
            rounds
        )

    diff_bits = hamming_distance(
        original_cipher,
        modified_cipher
    )

    return {
        "original_cipher": original_cipher,
        "modified_cipher": modified_cipher,
        "differing_bits": diff_bits,
        "percentage_changed": round(
            (diff_bits / 16) * 100,
            2
        )
    }