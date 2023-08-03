# BitcoinAddressFinder23

Copyright (c) 2017-2021 Bernard Ladenthin.

## Requirments
* Java 11 or newer. Java 8 is not supported anymore.

## General
* This project is a fork from the [BitcoinAddressFinder](https://github.com/bernardladenthin/BitcoinAddressFinder) started by Bernard Ladenthin.
* In this side project I am trying to increase the overall performance of the BitcoinAddressFinder by relocating the generation of a BTC address from a given public key totally to the OpenCL kernel.
* More information will follow.

## Known issues
If you have a laptop like HP ZBook G3/G4/G5 "hybrid graphics" mode is very slow because of the shared memory. Please select in the BIOS "discrete graphics".

-----
## Legal
This software should not be configured and used to find (Bitcoin/Altcoin) address hash (RIPEMD-160) collisions and use (steal) credit from third-party (Bitcoin/Altcoin) addresses.
This mode might be allowed to recover lost private keys of your own public addresses only.

Another mostly legal use case is a check if the (Bitcoin/Altcoin) addresses hash (RIPEMD-160) is already in use to prevent yourself from a known hash (RIPEMD-160) collision and double use.

Some configurations are not allowed in some countries (definitely not complete):
* Germany: § 202c Vorbereiten des Ausspähens und Abfangens von Daten
* United States of America (USA): Computer Fraud and Abuse Act (CFAA)

## License

It is licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for the full license text.
Some subprojects have a different license.



[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fbernardladenthin%2FBitcoinAddressFinder.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Fbernardladenthin%2FBitcoinAddressFinder?ref=badge_large)