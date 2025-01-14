<div align="center">
  <h1>🏛️ Delphi 🔮</h1>
  <p><i>Made by <a href="https://www.brunorochamoura.com/about/">BRM</a>.</i></p>
  <br />
</div>

**Delphi** is a Python library for conducting **CBC padding oracle attacks**.

This library simplifies the creation of Padding Oracle Attack proof-of-concept scripts by providing generic encryption and decryption attack functions. Simply define your custom oracle checking function and use the provided utilities.

## Features

- **Decryption Attacks:** Recover plaintext from encrypted messages.
- **Encryption Attacks:** Forge ciphertexts that decrypt to any desired plaintext.
- **Flexible IV Control:** Supports both scenarios where the Initialization Vector is controllable and where it isn’t.
- **Seamless Integration:** Easily incorporate into PoC scripts tailored to your target.

## How To Use

Integrating Delphi into your PoC script is straightforward.

First, clone the repository to your local machine and install the dependencies:

```sh
git clone https://github.com/BrunoRochaDev/Delphi.git
cd Delphi
pip install -r requirements.txt
```

Next, create your own Python script within this directory. To use Delphi, follow these steps:

1. Import the `encrypt` and/or `decrypt` functions from Delphi as needed.
2. Implement your own function that communicates with the padding oracle and returns `True` if the oracle indicates the padding is valid, or `False` otherwise.
3. Call the `encrypt` and/or `decrypt` functions from Delphi, supplying the necessary arguments.

The [`example.py`](https://github.com/BrunoRochaDev/Delphi/blob/main/example.py) file is included to illustrate how Delphi's functions, defined in `delphi.py`, can be utilized in a practical PoC.

## Disclaimer

**Delphi is intended for educational and research purposes only.**

Use this library responsibly. Unauthorized usage against systems without explicit permission may breach laws and ethical standards. The author assumes no responsibility for misuse.

## License

This project is distributed under the AGPLv3 License. See the [LICENSE](https://github.com/BrunoRochaDev/Delphi/blob/main/LICENSE) file for details.
