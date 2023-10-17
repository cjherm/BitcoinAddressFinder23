# BitcoinAddressFinder23

Copyright (c) 2017-2021 Bernard Ladenthin.

## Requirments
* Java 17 LTS is necessary
* Device (e.g. Graphic card or CPU) with support of OpenCL 2.0 or higher

## General
* This project is a fork from the [BitcoinAddressFinder](https://github.com/bernardladenthin/BitcoinAddressFinder) started by Bernard Ladenthin.
* In this forkt I expanded the implementation using OpenCL to generate a Bitcoin addres.
* While the initial BitcoinAddressFinder only executed the Elliptic curve point multiplication to calculate the coordinates of the public key with OpenCL, it is possible now to generate a complete address (RIPEMD-160 hash or with version byte and checksum) using high-performant OpenCL kernels.
* This project offers a variety of functionalites and the possibility to run a benchmark.

## Supported functionalites
* gridNumBits (g): Sets the size (n) of results per single run: n = 2^g. 
* chunkMode: To calculate n results per single run, you can feed the software with 1 (chunkMode = true) or n (chunkMode = false) private key/s. If activated, all n-1 private keys will be derived from the initial key by bitwise OR-operation.
* kernelMode: Determines to which point the OpenCL kernel should run and if intermediate results are required. For more info listed at "kernelModes".


## KernelModes
Determines what the OpenCL kernel will return to the host:
* kernelMode = 0: GEN_XY_COORDINATES_ONLY_MODE, set by default, will return x,y coordinates
* kernelMode = 1: GEN_PUBLIC_KEY_ONLY_MODE, will return the private key & public key (parity byte + x + y)
* kernelMode = 2: GEN_RIPEMD160_ONLY_MODE, will return the private key & RIPEMD-160 hash 
* kernelMode = 3: GEN_ADDRESSES_ONLY_MODE, will return the private key & complete address (version byte + RIPEMD-160 hash + checksum) 
* kernelMode = 4: GEN_UNTIL_1ST_SHA256_MODE, will return every intermediate result until and including the first SHA-256 hash
* kernelMode = 5: GEN_UNTIL_RIPEMD160_MODE, will return every intermediate result until and including the RIPEMD-160 hash
* kernelMode = 6: GEN_UNTIL_2ND_SHA256_MODE, will return every intermediate result until and including the second SHA-256 hash
* kernelMode = 7: GEN_UNTIL_3RD_SHA256_MODE, will return every intermediate result until and including the third SHA-256 hash
* kernelMode = 8: GEN_UNTIL_1ST_SHA256_MODE, will return every intermediate result until and including the complete address

## How to get started to run a Benchmark:
* Use "build.bat" to create executable JAR
* execute JAR with a single argument, that argument shall be a JSON containing the configuration (Look into "examples" directory to try out)
* there are some example .bat to start the JAR with an existing JSON configurations 

-----
## Legal
This project is for scientific use only and should not be configured or used to receive access to balances from others.
Additional remarks from [BitcoinAddressFinder](https://github.com/bernardladenthin/BitcoinAddressFinder):
* This software should not be configured and used to find (Bitcoin/Altcoin) address hash (RIPEMD-160) collisions and use (steal) credit from third-party (Bitcoin/Altcoin) addresses.
* This mode might be allowed to recover lost private keys of your own public addresses only.
* Another mostly legal use case is a check if the (Bitcoin/Altcoin) addresses hash (RIPEMD-160) is already in use to prevent yourself from a known hash (RIPEMD-160) collision and double use.

Some configurations are not allowed in some countries (definitely not complete):
* Germany: § 202c Vorbereiten des Ausspähens und Abfangens von Daten
* United States of America (USA): Computer Fraud and Abuse Act (CFAA)

## License
It is licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for the full license text.
Some subprojects have a different license.



[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fbernardladenthin%2FBitcoinAddressFinder.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Fbernardladenthin%2FBitcoinAddressFinder?ref=badge_large)