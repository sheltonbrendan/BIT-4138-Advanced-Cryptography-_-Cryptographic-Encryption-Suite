import hashlib

# Dictionary to store usernames and hashed passwords
users = {}

while True:
    print("\n===== HASHING SHA-256 =====")
    print("1. Generate SHA-256 Hash")
    print("2. Register User")
    print("3. Login")
    print("4. Verify Hash")
    print("5. Password Security Test")
    print("6. Exit")

    choice = input("Choose an option: ")

    if choice == "1":
        text = input("Enter text to hash: ")
        hash_value = hashlib.sha256(text.encode()).hexdigest()

        print("\nSHA-256 Hash:")
        print(hash_value)

    elif choice == "2":
        username = input("Enter username: ")
        password = input("Create password: ")

        password_hash = hashlib.sha256(password.encode()).hexdigest()

        users[username] = password_hash

        print("\nUser registered successfully.")
        print("Stored Password Hash:")
        print(password_hash)

    elif choice == "3":
        username = input("Enter username: ")
        password = input("Enter password: ")

        entered_hash = hashlib.sha256(password.encode()).hexdigest()

        if username in users and users[username] == entered_hash:
            print("\nAccess Granted")
        else:
            print("\nAccess Denied")

    elif choice == "4":
        text = input("Enter text to verify: ")

        original_hash = hashlib.sha256(text.encode()).hexdigest()

        print("\nGenerated Hash:")
        print(original_hash)

        entered_hash = input("\nPaste hash to compare: ")

        if original_hash == entered_hash:
            print("\nHash Verification Successful")
        else:
            print("\nHashes Do Not Match")

    elif choice == "5":
        password1 = input("Enter first password: ")
        password2 = input("Enter second password: ")

        hash1 = hashlib.sha256(password1.encode()).hexdigest()
        hash2 = hashlib.sha256(password2.encode()).hexdigest()

        print("\nPassword 1 Hash:")
        print(hash1)

        print("\nPassword 2 Hash:")
        print(hash2)

        if hash1 == hash2:
            print("\nHashes are identical.")
        else:
            print("\nHashes are completely different.")

    elif choice == "6":
        print("\nExiting program...")
        break

    else:
        print("\nInvalid option. Please try again.")