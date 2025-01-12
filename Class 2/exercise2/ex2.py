import hashlib

hash=""
username=""



def hashFile(filepath):
    import hashlib
    BLOCKSIZE = 65536
    hasher = hashlib.sha1()
    with open(filepath, 'rb') as afile:
        buf = afile.read(BLOCKSIZE)
        if len(buf) < 30:
            return None
        while len(buf) > 0:
            hasher.update(buf)
            buf = afile.read(BLOCKSIZE)
            if len(buf) > 4000:
                break
    return hasher.hexdigest()


def login(user, filepath):
    global hash
    global username
    myHash = hashFile(filepath)
    if myHash == None:
        return False
    myUser = user
    if (myUser == user and myHash == hash):
        return True
    return False

def register(user, filepath):
    global hash
    global username
    hash = hashFile(filepath)
    username = user
    print("Registered user: " + user + " with file hash: " + hash)

print("Welcome to the login system")
while (1) :
    print("Please select an option:")
    print("1. Register")
    print("2. Login")
    option = input()
    if option == "1":
        print("Please enter a username:")
        user = input()
        print("Please enter a filepath:")
        filepath = input()
        register(user, filepath)
    elif option == "2":
        print("Please enter a username:")
        user = input()
        print("Please enter a filepath:")
        filepath = input()
        if login(user, filepath):
            print("Login successful")
        else:
            print("Login failed")
    else:
        print("Invalid option")
