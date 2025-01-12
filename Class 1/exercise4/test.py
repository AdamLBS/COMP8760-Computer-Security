import hashlib
from itertools import permutations

# Input data
hash_value = "91077079768edba10ac0c93b7108bc639d778d67"
personal_info = ["a", "b", "c", "d", "e", "f", "g", "h", "i"]

# Define invalid swipe rules
invalid_swipes = {
    ("a", "c"): "b", ("a", "i"): "e", ("a", "g"): "d",
    ("b", "h"): "e", ("c", "g"): "e", ("c", "i"): "f",
    ("d", "f"): "e", ("g", "i"): "h",
    # Add reversed rules for symmetry
    ("c", "a"): "b", ("i", "a"): "e", ("g", "a"): "d",
    ("h", "b"): "e", ("g", "c"): "e", ("i", "c"): "f",
    ("f", "d"): "e", ("i", "g"): "h",
}

# Check if a pattern is valid
def is_valid_pattern(pattern):
    visited = set()
    for i in range(len(pattern) - 1):
        start, end = pattern[i], pattern[i + 1]
        if (start, end) in invalid_swipes or (end, start) in invalid_swipes:
            middle = invalid_swipes.get((start, end), invalid_swipes.get((end, start)))
            if middle not in visited:
                return False
        visited.add(start)
    visited.add(pattern[-1])
    return True

# Hash a password with SHA-1
def hash_with_salt(password):
    return hashlib.sha1(password.encode()).hexdigest()

# Attempt to crack the hash
def crack_pattern(hash_value):
    for r in range(1, 10):  # Pattern lengths from 1 to 9
        for pattern in permutations(personal_info, r):
            pattern_str = "".join(pattern)
            if is_valid_pattern(pattern) and hash_with_salt(pattern_str) == hash_value:
                return pattern_str
    return None

# Find the unlock pattern
unlock_pattern = crack_pattern(hash_value)
if unlock_pattern:
    print(f"Unlock pattern found: {unlock_pattern}")
else:
    print("Unlock pattern not found.")
