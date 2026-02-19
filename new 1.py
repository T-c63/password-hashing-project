import hashlib
import re

# -----------------------------
# Class 1: PasswordSecurity
# Handles password strength checking and hashing
# -----------------------------
class PasswordSecurity:

    def hash_password(self, password):
        """
        Converts plain text password into a secure SHA-256 hash.
        This ensures we DO NOT store plain-text passwords.
        """
        return hashlib.sha256(password.encode()).hexdigest()

    def check_strength(self, password):
        """
        Validates password strength based on:
        - Minimum length (>=8)
        - At least one uppercase letter
        - At least one lowercase letter
        - At least one number
        """

        if len(password) < 8:
            return False, "Password must be at least 8 characters long."

        if not re.search(r"[A-Z]", password):
            return False, "Password must contain at least one uppercase letter."

        if not re.search(r"[a-z]", password):
            return False, "Password must contain at least one lowercase letter."

        if not re.search(r"[0-9]", password):
            return False, "Password must contain at least one number."

        return True, "Password is strong."


# -----------------------------
# Class 2: User
# Represents a system user
# -----------------------------
class User:

    def __init__(self, username, hashed_password):
        """
        Stores username and hashed password only.
        Plain-text password is NEVER stored.
        """
        self.username = username
        self.hashed_password = hashed_password


# -----------------------------
# Class 3: AuthenticationSystem
# Handles registration and login logic
# -----------------------------
class AuthenticationSystem:

    def __init__(self):
        # Dictionary used for secure storage (username -> User object)
        self.users = {}
        self.security = PasswordSecurity()
        self.failed_attempts = {}

    def register(self):
        """
        Captures user input and registers user securely.
        """
        username = input("Enter username: ").strip()

        # Input validation
        if username == "":
            print("Username cannot be empty.")
            return

        if username in self.users:
            print("Username already exists.")
            return

        password = input("Enter password: ")

        # Check password strength
        is_strong, message = self.security.check_strength(password)
        if not is_strong:
            print("Weak Password:", message)
            return

        # Hash password before storing
        hashed_password = self.security.hash_password(password)

        # Create and store user securely
        user = User(username, hashed_password)
        self.users[username] = user

        print("User registered successfully!")

    def login(self):
        """
        Authenticates user by comparing hashed passwords.
        Demonstrates access control logic.
        """

        username = input("Enter username: ").strip()
        password = input("Enter password: ")

        if username not in self.users:
            print("User not found.")
            return

        # Optional: Lock account after 3 failed attempts
        if self.failed_attempts.get(username, 0) >= 3:
            print("Account locked due to multiple failed attempts.")
            return

        # Hash input password for comparison
        hashed_input = self.security.hash_password(password)

        stored_user = self.users[username]

        if hashed_input == stored_user.hashed_password:
            print("Login successful. Access granted.")
            self.failed_attempts[username] = 0  # reset counter
        else:
            print("Incorrect password.")
            self.failed_attempts[username] = self.failed_attempts.get(username, 0) + 1


# -----------------------------
# Main Program Execution
# -----------------------------
def main():
    system = AuthenticationSystem()

    while True:
        print("\n==== SIMPLE AUTHENTICATION SYSTEM ====")
        print("1. Register")
        print("2. Login")
        print("3. Exit")

        choice = input("Select option: ")

        if choice == "1":
            system.register()
        elif choice == "2":
            system.login()
        elif choice == "3":
            print("Exiting system...")
            break
        else:
            print("Invalid option. Try again.")


if __name__ == "__main__":
    main()
