import hashlib
from itertools import permutations, product

# Input data
hash_value = "3281e6de7fa3c6fd6d6c8098347aeb06bd35b0f74b96f173c7b2d28135e14d45"
salt = "5UA@/Mw^%He]SBaU"

personal_info = [
    "laplusbelle", "Marie", "Curie", "Woof", "2January1980", "UKC",
    "JeanNeoskour", "JvaistFairecourir", "Eltrofor", "29December1981",
    "MarieCurie", "Marie1980", "Eltrofor1981", "Woof1980", "UKC1980",
    "marie", "curie", "woof", "ukc", "jeanneoskour", "jvaistfairecourir",
    "02", "01", "80", "1980", "Jean" "Neoskour", "Jvaist", "Fairecourir",
    "Eltrofor", "29", "12", "81", "1981"
]

# Common substitutions
substitutions = {
    'a': '@',
    'e': '3',
    'i': '1',
    'o': '0',
    's': '$',
}

# Generate variations with substitutions
def generate_variations(word):
    variations = {word}  # Start with the original word
    for original, sub in substitutions.items():
        variations.update(word.replace(original, sub) for original in substitutions)
    return list(variations)

# Generate personalised dictionary
def generate_personalised_dictionary(info):
    dictionary = set()
    for word in info:
        dictionary.update(generate_variations(word))  # Add variations
        dictionary.update(f"{word}{num}" for num in range(100))  # Add numbers as suffix
    # Generate permutations and combinations of words
    for r in range(2, 6):  # Generate combinations of 2 to 5 elements
        for combo in product(info, repeat=r):
            dictionary.add("".join(combo))
    return list(dictionary)

# Hash a password with the given salt
def hash_with_salt(password, salt):
    return hashlib.sha256((password + salt).encode()).hexdigest()

# Attempt to crack the hash
def crack_password(dictionary, salt, target_hash):
    for password in dictionary:
        if hash_with_salt(password, salt) == target_hash:
            return password
    return None

# Generate dictionary and crack password
personalised_dict = generate_personalised_dictionary(personal_info)
print(f"Generated {len(personalised_dict)} passwords.")
password = crack_password(personalised_dict, salt, hash_value)

if password:
    print(f"Password found: {password}")
else:
    print("Password not found.")