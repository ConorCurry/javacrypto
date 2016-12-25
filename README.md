## Explanation of how to compile and run the program:

Compilation requires no special options, besides the inclusion of the BouncyCastle package.
Because of the extra credit, there are a few different ways to use the program.
Once the executable is run, the program will ask if you want to run a performance test.
This performance test is the extra credit comparison of encryption/decryption speeds
of 100 random 32 character strings. Answering y will run the performance test.

Answering n to the performance test will prompt the user for the text they would like to encrypt.
The program will then encrypt/decrypt with AES, Blowfish, and RSA. Note that RSA is not capable
of encrypting long strings.
A RSA signature will also be computed over the supplied method, and verified for correctness.