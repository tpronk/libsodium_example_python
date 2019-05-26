# Example of libsodium in Python
The scripts in this repo show how to:
* generate a public and secret key
* encrypt a sealed box via a public key
* decrypt a sealed box via a secret key

For portability, all keys and encrypted data are stored in base64.

# Required packages
* [sodium](https://cran.r-project.org/web/packages/sodium/index.html)
* [base64enc](https://cran.r-project.org/web/packages/base64enc/index.html)
