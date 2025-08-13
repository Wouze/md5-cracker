import hashlib
import string
import threading
import time

# ================== CONFIGURATION ==================
class Config:
    # Character sets to include in the brute-force attempt
    WITH_LOWERCASE = True
    WITH_UPPERCASE = True
    WITH_DIGITS    = True
    WITH_SYMBOLS   = False

    # Password length range to check
    MIN_LENGTH = 1
    MAX_LENGTH = 8

    # Target hash to crack (5d41402abc4b2a76b9719d911017c592 -> "hello")
    TARGET_HASH = "5d41402abc4b2a76b9719d911017c592"

# ================== CRACKER CLASS ==================
class Cracker:
    def __init__(self):
        self.charset = self._build_charset()
        self.target_hash = Config.TARGET_HASH
        
        # Shared resources for threads
        self.password_found = False
        self.found_password = ""
        self.lock = threading.Lock() # Equivalent to std::mutex

    def _build_charset(self):
        """Builds the character set based on the configuration."""
        charset = ""
        if Config.WITH_LOWERCASE:
            charset += string.ascii_lowercase
        if Config.WITH_UPPERCASE:
            charset += string.ascii_uppercase
        if Config.WITH_DIGITS:
            charset += string.digits
        if Config.WITH_SYMBOLS:
            charset += string.punctuation
        return charset
        
    def _md5(self, s):
        """Calculates the MD5 hash of a string."""
        return hashlib.md5(s.encode('utf-8')).hexdigest()

    def _brute_force_recursive(self, current_string, max_depth):
        """The recursive core for each thread."""
        # --- Early exit if another thread found the password ---
        if self.password_found:
            return

        # --- Base case: reached the desired length ---
        if len(current_string) == max_depth:
            if self._md5(current_string) == self.target_hash:
                # Use a lock to safely modify shared variables
                with self.lock:
                    # Double-check after acquiring the lock
                    if not self.password_found:
                        self.password_found = True
                        self.found_password = current_string
            return

        # --- Recursive step ---
        for char in self.charset:
            # Check again before starting the next recursive call
            if self.password_found:
                return
            
            self._brute_force_recursive(current_string + char, max_depth)

    def run(self):
        """Starts the brute-force attack."""
        start_time = time.time()
        
        print(f"[*] Charset: {self.charset} (Size: {len(self.charset)})")
        print(f"[*] Target MD5: {self.target_hash}")

        for length in range(Config.MIN_LENGTH, Config.MAX_LENGTH + 1):
            if self.password_found:
                break

            print(f"[*] Trying length: {length}")
            threads = []
            
            # Partition the work: each thread handles a different starting character
            for char in self.charset:
                # The worker function is the recursive part itself
                thread = threading.Thread(target=self._brute_force_recursive, args=(char, length))
                threads.append(thread)
                thread.start()

            # Wait for all threads for the current length to finish
            for t in threads:
                t.join()

        end_time = time.time()
        print(f"\n[*] Total time: {end_time - start_time:.2f} seconds")

        if self.password_found:
            print("\n[+] SUCCESS! 🎉")
            print(f"    Password: {self.found_password}")
        else:
            print("\n[-] FAILED. Password not found in the given range.")

# ================== MAIN ==================
if __name__ == '__main__':
    cracker = Cracker()
    cracker.run()