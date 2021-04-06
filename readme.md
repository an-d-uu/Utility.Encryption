# Utility.Encryption
***
This class uses a symmetric key algorithm (Rijndael/AES) to encrypt and
decrypt data. As long as it is initialized with the same constructor
parameters, the class will use the same key. Before performing encryption,
the class can prepend random bytes to plain text and generate different
encrypted values from the same plain text, encryption key, initialization
vector, and other parameters. This class is thread-safe.
