# Cryptographic Encryption Suite

**Unit:** BIT 4138 – Advanced Cryptography
**Student:** Brendan Shelton
**Admission Number:** BSCCS/2024/55872
**Course:** Bachelor of Science in Computer Science (Year 3, Semester 2)
**Lecturer:** Mr. Michael Nyoro

## Project Overview

This project was developed as part of the Advanced Cryptography unit to demonstrate the practical application of various encryption techniques. The system is a web-based application built using Python and Flask that allows users to perform encryption and decryption using both classical and modern cryptographic algorithms.

The project covers concepts learned throughout the semester, including classical ciphers, stream ciphers, block ciphers, and public key cryptography.

## Technologies Used

* Python
* Flask
* Cryptography Library
* HTML
* CSS
* OpenSSL
* Git and GitHub

## Features Implemented

### Week 1: Environment Setup

During this week, I installed and configured the development environment required for the project. This included setting up Python, Visual Studio Code, cryptographic libraries, OpenSSL, and the GitHub repository.

### Week 2: Classical Cryptography

I implemented the Caesar Cipher and Vigenère Cipher algorithms. The system supports both encryption and decryption while validating user input and displaying the cipher processes correctly.

### Week 3: Stream Ciphers and Randomness

This section focused on stream cipher concepts. I implemented a Linear Feedback Shift Register (LFSR) for pseudorandom sequence generation and the RC4 stream cipher. Randomness tests were also performed on generated sequences.

### Week 4: Block Cipher Design and AES

I implemented AES-based encryption and decryption using the Fernet module. The application supports both text and file encryption while securely generating and managing encryption keys.

### Week 5: Public Key Cryptography

The final phase involved implementing RSA cryptography. The system generates public and private key pairs, encrypts messages using the public key, and decrypts them using the private key. OAEP padding was used to improve security.

## Repository Structure

Cryptographic-Encryption-Suite/

* source-code/

  * Application source files
  * Flask routes
  * Cryptographic modules

* documentation/

  * Project report
  * Supporting documents

* logbook/

  * Weekly progress records

* screenshots/

  * Project implementation screenshots

* README.md

## Running the Project

Clone the repository:

git clone https://github.com/sheltonbrendan/Cryptographic-Encryption-Suite.git

Move into the project folder:

cd Cryptographic-Encryption-Suite

Install the required packages:

pip install flask cryptography

Run the application:

python app.py

Open the application in a browser:

http://localhost:5000

## Documentation

The repository contains the complete project source code, project report, weekly logbook, screenshots, and other supporting files used during development.

## Conclusion

This project helped me understand how different cryptographic techniques work and how they can be applied in real applications. Through the implementation of classical ciphers, stream ciphers, AES, and RSA, I gained practical experience in encryption, decryption, key management, and secure communication.

## Author

Brendan Shelton
BSCCS/2024/55872
Bachelor of Science in Computer Science
BIT 4138 – Advanced Cryptography
