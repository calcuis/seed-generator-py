import bisect, hashlib, itertools, os, secrets, unicodedata
from typing import AnyStr, List, Optional, Sequence, TypeVar, Union

class ConfigurationError(Exception):
    pass

_T = TypeVar("_T")
PBKDF2_ROUNDS = 2048

def binary_search(
    a: Sequence[_T],
    x: _T,
    lo: int = 0,
    hi: Optional[int] = None,
    ) -> int:
    hi = hi if hi is not None else len(a)
    pos = bisect.bisect_left(a, x, lo, hi)
    return pos if pos != hi and a[pos] == x else -1

def b58encode(v: bytes) -> str:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    p, acc = 1, 0
    for c in reversed(v):
        acc += p * c
        p = p << 8
    string = ""
    while acc:
        acc, idx = divmod(acc, 58)
        string = alphabet[idx : idx + 1] + string
    return string

class Mnemonic(object):
    def __init__(self, language: str):
        self.language = language
        self.radix = 2048
        with open(
            "%s.txt" % language, "r", encoding="utf-8"
        ) as f:
            self.wordlist = [w.strip() for w in f.readlines()]
        if len(self.wordlist) != self.radix:
            raise ConfigurationError(
                "Wordlist should contain %d words, but it contains %d words."
                % (self.radix, len(self.wordlist))
            )

    def normalize_string(txt: AnyStr) -> str:
        if isinstance(txt, bytes):
            utxt = txt.decode("utf8")
        elif isinstance(txt, str):
            utxt = txt
        else:
            raise TypeError("String value expected")
        return unicodedata.normalize("NFKD", utxt)

    def generate(self, strength: int = 128) -> str:
        if strength not in [128, 160, 192, 224, 256]:
            raise ValueError(
                "Strength should be one of the following [128, 160, 192, 224, 256], but it is not (%d)."
                % strength
            )
        return self.to_mnemonic(os.urandom(strength // 8))

    def to_entropy(self, words: Union[List[str], str]) -> bytearray:
        if not isinstance(words, list):
            words = words.split(" ")
        if len(words) not in [12, 15, 18, 21, 24]:
            raise ValueError(
                "Number of words must be one of the following: [12, 15, 18, 21, 24], but it is not (%d)."
                % len(words)
            )
        concatLenBits = len(words) * 11
        concatBits = [False] * concatLenBits
        wordindex = 0
        if self.language == "english":
            use_binary_search = True
        else:
            use_binary_search = False
        for word in words:
            # Find the words index in the wordlist
            ndx = (
                binary_search(self.wordlist, word)
                if use_binary_search
                else self.wordlist.index(word)
            )
            if ndx < 0:
                raise LookupError('Unable to find "%s" in word list.' % word)
            # Set the next 11 bits to the value of the index
            for ii in range(11):
                concatBits[(wordindex * 11) + ii] = (ndx & (1 << (10 - ii))) != 0
            wordindex += 1
        checksumLengthBits = concatLenBits // 33
        entropyLengthBits = concatLenBits - checksumLengthBits
        # Extract original entropy as bytes
        entropy = bytearray(entropyLengthBits // 8)
        for ii in range(len(entropy)):
            for jj in range(8):
                if concatBits[(ii * 8) + jj]:
                    entropy[ii] |= 1 << (7 - jj)
        # Take the digest of the entropy
        hashBytes = hashlib.sha256(entropy).digest()
        hashBits = list(
            itertools.chain.from_iterable(
                [c & (1 << (7 - i)) != 0 for i in range(8)] for c in hashBytes
            )
        )
        # Check all the checksum bits
        for i in range(checksumLengthBits):
            if concatBits[entropyLengthBits + i] != hashBits[i]:
                raise ValueError("Failed checksum.")
        return entropy

    def to_mnemonic(self, data: bytes) -> str:
        if len(data) not in [16, 20, 24, 28, 32]:
            raise ValueError(
                "Data length should be one of the following: [16, 20, 24, 28, 32], but it is not (%d)."
                % len(data)
            )
        h = hashlib.sha256(data).hexdigest()
        b = (
            bin(int.from_bytes(data, byteorder="big"))[2:].zfill(len(data) * 8)
            + bin(int(h, 16))[2:].zfill(256)[: len(data) * 8 // 32]
        )
        result = []
        for i in range(len(b) // 11):
            idx = int(b[i * 11 : (i + 1) * 11], 2)
            result.append(self.wordlist[idx])
            result_phrase = " ".join(result)
        return result_phrase

    def check(self, mnemonic: str) -> bool:
        mnemonic_list = self.normalize_string(mnemonic).split(" ")
        # list of valid mnemonic lengths
        if len(mnemonic_list) not in [12, 15, 18, 21, 24]:
            return False
        try:
            idx = map(
                lambda x: bin(self.wordlist.index(x))[2:].zfill(11), mnemonic_list
            )
            b = "".join(idx)
        except ValueError:
            return False
        l = len(b)
        d = b[: l // 33 * 32]
        h = b[-l // 33 :]
        nd = int(d, 2).to_bytes(l // 33 * 4, byteorder="big")
        nh = bin(int(hashlib.sha256(nd).hexdigest(), 16))[2:].zfill(256)[: l // 33]
        return h == nh

    def expand_word(self, prefix: str) -> str:
        if prefix in self.wordlist:
            return prefix
        else:
            matches = [word for word in self.wordlist if word.startswith(prefix)]
            if len(matches) == 1:  # matched exactly one word in the wordlist
                return matches[0]
            else:
                # exact match not found
                return prefix

    def expand(self, mnemonic: str) -> str:
        return " ".join(map(self.expand_word, mnemonic.split(" ")))

    def to_seed(cls, mnemonic: str, passphrase: str = "") -> bytes:
        mnemonic = cls.normalize_string(mnemonic)
        passphrase = cls.normalize_string(passphrase)
        passphrase = "mnemonic" + passphrase
        mnemonic_bytes = mnemonic.encode("utf-8")
        passphrase_bytes = passphrase.encode("utf-8")
        stretched = hashlib.pbkdf2_hmac(
            "sha512", mnemonic_bytes, passphrase_bytes, PBKDF2_ROUNDS
        )
        return stretched[:64]

while True:
    # Input a number of words
    numbers = input("How many words in your mnemonic? (12, 15, 18, 21, 24): ")
    if numbers=="12":byte=16
    elif numbers=="15":byte=20
    elif numbers=="18":byte=24
    elif numbers=="21":byte=28
    elif numbers=="24":byte=32
    else : 
        print("Not a valid input!")
        break
    # Generate a random seed of 16 bytes, 20 bytes, 24 bytes, 28 bytes or 32 bytes
    seed = secrets.token_bytes(byte)
    # Define BIP39 wordlist language and import generated seed from secrets method
    mnemonic_words = Mnemonic("english").to_mnemonic(seed)
    # Split the mnemonic into individual words
    mnemonic_word_list = mnemonic_words.split()
    # Print the generated mnemonic
    print("Generated Mnemonic:")
    print(" ".join(mnemonic_word_list))
print("Bye!")
