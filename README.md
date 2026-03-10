# HashMapper

A highly concurrent, multi-layered hash identification and brute-force tool written in Go with support for 70+ algorithms, salt formatting, and deep nested template decryption.

Go ile geliştirilmiş, 70'ten fazla algoritmayı destekleyen; iç içe geçmiş (nested) ve parolalar ile birlikte kullanılan ek veri (salt) eklenmiş karmaşık hash yapılarını tespit etme ve kırma aracı.

---

## Features

- **87 algorithms** across families: MD, SHA-1, SHA-2, SHA-3, Keccak, SHAKE, BLAKE2, RIPEMD, CRC, FNV, Adler, HMAC, chained/double hashes, slow hashes (bcrypt, scrypt, Argon2, PBKDF2), Unix crypt formats, CMS formats (WordPress, Joomla, Django, Drupal), and more.
- **Hash identification** — ranks candidate algorithms by length, character set, and format patterns.
- **Concurrent cracking** — worker pool with configurable concurrency (wordlist + brute-force).
- **Salt formatting** — 13 combination modes: `append`, `prepend`, `colon_append`, `colon_prepend`, `dollar_append`, `dollar_prepend`, `dot_append`, `dot_prepend`, `underscore_append`, `underscore_prepend`, `pipe_append`, `pipe_prepend`, and `none`.
- **Nested template expressions** — express multi-layer hash operations in a simple DSL.

---

## Installation

```bash
go install github.com/02gur/HashMapper@latest
```

Or build from source:

```bash
git clone https://github.com/02gur/HashMapper
cd HashMapper
go build -o hashmapper .
```

---

## Usage

### Identify a hash

```bash
hashmapper identify 5f4dcc3b5aa765d61d8327deb882cf99
hashmapper identify --all 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8
```

### Crack with a wordlist

```bash
hashmapper crack --hash 5f4dcc3b5aa765d61d8327deb882cf99 \
                 --wordlist /usr/share/wordlists/rockyou.txt
```

### Crack with a salt

```bash
hashmapper crack --hash b305cadbb3bce54f3aa59c64fec00dea \
                 --wordlist wordlist.txt \
                 --algorithm md5 \
                 --salt mysalt \
                 --salt-mode append
```

### Brute-force attack

```bash
hashmapper crack --hash 187ef4436122d1cc2f40dc2b92f0eba0 \
                 --algorithm md5 \
                 --brute \
                 --charset "abcdefghijklmnopqrstuvwxyz0123456789" \
                 --minlen 1 --maxlen 6
```

### Nested template cracking

```bash
# Crack sha1(md5(password))
hashmapper crack --hash 55c3b5386c486feb662a0785f340938f518d547f \
                 --wordlist wordlist.txt \
                 --template "sha1(md5(password))"

# Crack sha256(password + salt) with a known salt
hashmapper crack --hash <hash> \
                 --wordlist wordlist.txt \
                 --template "sha256(password+salt)" \
                 --salt mysalt
```

### Template DSL

Templates support:

- Any registered algorithm as a function: `md5(...)`, `sha256(...)`, `blake2b_512(...)`, etc.
- String concatenation with `+`: `md5(password + salt)`
- Variables: `password` (the candidate) and `salt` (the `--salt` value)
- String literals: `md5("prefix" + password)`
- Encoding helpers: `base64(...)`, `hex(...)`, `upper(...)`, `lower(...)`, `unhex(...)`
- Arbitrary nesting: `sha256(sha1(md5(password + salt)))`

---

## Supported Algorithms

| Family       | Algorithms |
|--------------|------------|
| MD           | MD2, MD4, MD5, MD5(Base64) |
| SHA-1        | SHA-1, SHA-1(Base64) |
| SHA-2        | SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256, SHA-256(Base64), SHA-512(Base64) |
| SHA-3        | SHA3-224, SHA3-256, SHA3-384, SHA3-512 |
| Keccak       | Keccak-224, Keccak-256, Keccak-384, Keccak-512 |
| SHAKE        | SHAKE-128/256-bit, SHAKE-256/512-bit |
| BLAKE2       | BLAKE2s-256, BLAKE2b-256, BLAKE2b-384, BLAKE2b-512 |
| RIPEMD       | RIPEMD-160 |
| CRC          | CRC-16, CRC-32 (IEEE/Castagnoli/Koopman), CRC-64 (ECMA/ISO) |
| FNV          | FNV-1/1a 32/64/128-bit |
| Adler        | Adler-32 |
| HMAC         | HMAC-MD5/SHA1/SHA256/SHA512/SHA3-256/SHA3-512/RIPEMD160 |
| Chained      | Double-MD5/SHA1/SHA256, MD5(SHA1), SHA1(MD5), SHA256(MD5), MD5(SHA256), MD5(NTLM) |
| NTLM/Windows | NTLM (NT Hash) |
| MySQL        | MySQL 3.2.3, MySQL 4.1+ |
| Slow / KDF   | bcrypt, scrypt, Argon2i, Argon2id, PBKDF2-SHA1/SHA256/SHA512 |
| Unix crypt   | MD5-Crypt ($1$), SHA-256-Crypt ($5$), SHA-512-Crypt ($6$) |
| CMS          | WordPress/phpBB3 ($P$/$H$), Joomla, Django MD5/SHA1/PBKDF2, Drupal 7 ($S$) |
| Legacy       | Tiger-128/160/192, Whirlpool, HAVAL-128/160/192/224/256 (3-pass), Snefru-128/256 |

---

## Options

```
crack:
  --hash          Target hash to crack (required)
  --algorithm     Algorithm ID(s) to try (auto-detected when omitted)
  --wordlist      Path to wordlist for dictionary attack
  --brute         Enable brute-force attack
  --charset       Character set for brute-force (default: a-z A-Z 0-9)
  --minlen        Minimum candidate length for brute-force (default: 1)
  --maxlen        Maximum candidate length for brute-force (default: 8)
  --salt          Salt value
  --salt-mode     Salt combination mode (default: all modes tried)
  --template      Nested hash template expression
  --workers       Number of concurrent goroutines (default: NumCPU)
  --verbose       Print progress every second

identify:
  --all           Show all candidates, not just the top-scoring ones
```

---

## License

Apache License 2.0 — see [LICENSE](LICENSE).
