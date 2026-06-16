from collections import Counter
import random

from spn_cipher import encrypt_block, hamming_distance


def algebraic_attack_xor(plaintext, ciphertext):
    return plaintext ^ ciphertext


def xor_difference(a, b):
    diff = a ^ b
    return {
        "value_a": a,
        "value_b": b,
        "difference": diff,
        "differing_bits": bin(diff).count("1"),
    }


def differential_trace(plaintext1, plaintext2, key, rounds=4):
    c1 = encrypt_block(plaintext1, key, rounds)
    c2 = encrypt_block(plaintext2, key, rounds)

    input_diff = xor_difference(plaintext1, plaintext2)
    output_diff = xor_difference(c1, c2)

    return {
        "plaintext1": plaintext1,
        "plaintext2": plaintext2,
        "ciphertext1": c1,
        "ciphertext2": c2,
        "input_difference": input_diff,
        "output_difference": output_diff,
    }


def linear_approximation_bias(key, rounds=4, num_samples=2000, seed=None):
    if seed is not None:
        random.seed(seed)

    k0 = (key >> 15) & 1
    matches = 0

    for _ in range(num_samples):
        p = random.randint(0, 0xFFFF)
        c = encrypt_block(p, key, rounds)

        p0 = (p >> 15) & 1
        pf = p & 1
        c0 = (c >> 15) & 1

        if (p0 ^ pf ^ c0) == k0:
            matches += 1

    probability = matches / num_samples
    bias = abs(probability - 0.5)

    return {
        "samples": num_samples,
        "matches": matches,
        "probability": round(probability, 4),
        "bias": round(bias, 4),
    }


def frequency_analysis(data):
    return Counter(data)


def frequency_table(data):
    counts = frequency_analysis(data)
    total = sum(counts.values())

    table = [
        (symbol, count, round((count / total) * 100, 2))
        for symbol, count in counts.items()
    ]

    table.sort(key=lambda row: row[1], reverse=True)
    return table


def avalanche_statistics(key, rounds=4, num_samples=200, seed=None):
    if seed is not None:
        random.seed(seed)

    percentages = []

    for _ in range(num_samples):
        p = random.randint(0, 0xFFFF)
        bit = random.randint(0, 15)

        c1 = encrypt_block(p, key, rounds)
        c2 = encrypt_block(p ^ (1 << bit), key, rounds)

        diff_bits = hamming_distance(c1, c2)
        percentages.append((diff_bits / 16) * 100)

    return {
        "samples": num_samples,
        "average_percent_changed": round(sum(percentages) / len(percentages), 2),
        "minimum_percent_changed": round(min(percentages), 2),
        "maximum_percent_changed": round(max(percentages), 2),
    }


ATTACK_MODELS = {
    "Ciphertext-Only Attack": "Attacker only has ciphertext.",
    "Known Plaintext Attack": "Attacker knows some plaintext/ciphertext pairs.",
    "Chosen Plaintext Attack": "Attacker chooses plaintexts and observes ciphertext.",
    "Chosen Ciphertext Attack": "Attacker chooses ciphertexts and observes decrypted output.",
}