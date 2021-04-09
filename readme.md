# Utility.Encryption
***
A Utility that allows you to encrypt data using Rijndael/AES and validate/hash signatures for signing data coming from or sending to a 3rd party.


### Available Classes

#### RijndaelEnhanced
***
This class uses a symmetric key algorithm (Rijndael/AES) to encrypt and
decrypt data. As long as it is initialized with the same constructor
parameters, the class will use the same key. Before performing encryption,
the class can prepend random bytes to plain text and generate different
encrypted values from the same plain text, encryption key, initialization
vector, and other parameters. This class is thread-safe.

#### SignatureValidation
***
This class allows users to use the following hashing algorithms to hash data and verify hashed data.
* HMACMD5
* HMACRIPEMD160
  * unavailable in .NET 5 and greater
* HMACSHA1
* HMACSHA256
* HMACSHA384
* HMACSHA512
  * unavailable in .NET 4.0
