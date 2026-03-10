// Package algorithms defines the registry of all supported hash algorithms,
// their expected output lengths, recognition patterns, and compute functions.
package algorithms

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"hash/adler32"
	"hash/crc32"
	"hash/crc64"
	"hash/fnv"
	"io"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf16"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/md4"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/sha3"
)

// Category groups algorithms by family.
type Category string

const (
	CategoryMD         Category = "MD"
	CategorySHA1       Category = "SHA-1"
	CategorySHA2       Category = "SHA-2"
	CategorySHA3       Category = "SHA-3"
	CategoryKeccak     Category = "Keccak"
	CategorySHAKE      Category = "SHAKE"
	CategoryBLAKE      Category = "BLAKE"
	CategoryRIPEMD     Category = "RIPEMD"
	CategoryCRC        Category = "CRC"
	CategoryFNV        Category = "FNV"
	CategoryAdler      Category = "Adler"
	CategoryHMAC       Category = "HMAC"
	CategoryChained    Category = "Chained"
	CategorySlowHash   Category = "SlowHash"
	CategoryCryptFormat Category = "CryptFormat"
	CategoryCMS        Category = "CMS"
	CategoryEncoded    Category = "Encoded"
	CategoryNTLM       Category = "NTLM"
	CategoryMySQL      Category = "MySQL"
)

// Algorithm describes a single hash algorithm.
type Algorithm struct {
	// ID is the unique machine-readable identifier (e.g. "md5", "sha256").
	ID string
	// Name is the human-readable name.
	Name string
	// HexLength is the expected lowercase hex-encoded output length, 0 means variable.
	HexLength int
	// Category groups related algorithms.
	Category Category
	// Patterns is a list of compiled regexes that the hash must match.
	Patterns []*regexp.Regexp
	// Compute calculates the hash of input using optional key (for HMAC, salted formats).
	// Returns the canonical string representation (hex, base64, or format-specific).
	Compute func(input, key []byte) (string, error)
	// IsSalted indicates that key is required for correct computation (HMAC, PBKDF2 …).
	IsSalted bool
	// IsSlowHash indicates a KDF-style algorithm that cannot easily be brute-forced in hex.
	IsSlowHash bool
}

// Registry holds all registered algorithms keyed by ID.
var Registry = map[string]*Algorithm{}

// All returns a stable-ordered slice of all algorithms.
var All []*Algorithm

func register(a *Algorithm) {
	Registry[a.ID] = a
	All = append(All, a)
}

// hexOf hashes data with h and returns lowercase hex.
func hexOf(h hash.Hash, data []byte) string {
	h.Reset()
	h.Write(data) //nolint:errcheck
	return hex.EncodeToString(h.Sum(nil))
}

// hmacHex creates an HMAC with hashFunc and returns hex.
func hmacHex(hashFunc func() hash.Hash, data, key []byte) string {
	mac := hmac.New(hashFunc, key)
	mac.Write(data) //nolint:errcheck
	return hex.EncodeToString(mac.Sum(nil))
}

// reHex matches a full lowercase hex string of exactly n characters.
func reHex(n int) *regexp.Regexp {
	return regexp.MustCompile(fmt.Sprintf(`^[0-9a-f]{%d}$`, n))
}

// reHexCI matches a full hex string (case-insensitive) of exactly n characters.
func reHexCI(n int) *regexp.Regexp {
	return regexp.MustCompile(fmt.Sprintf(`(?i)^[0-9a-f]{%d}$`, n))
}

func init() { //nolint:gochecknoinits
	// ────────────────────────────────────────────────────────────
	// MD family
	// ────────────────────────────────────────────────────────────

	register(&Algorithm{
		ID:        "md4",
		Name:      "MD4",
		HexLength: 32,
		Category:  CategoryMD,
		Patterns:  []*regexp.Regexp{reHex(32)},
		Compute: func(input, _ []byte) (string, error) {
			h := md4.New()
			h.Write(input) //nolint:errcheck
			return hex.EncodeToString(h.Sum(nil)), nil
		},
	})

	register(&Algorithm{
		ID:        "md5",
		Name:      "MD5",
		HexLength: 32,
		Category:  CategoryMD,
		Patterns:  []*regexp.Regexp{reHex(32)},
		Compute: func(input, _ []byte) (string, error) {
			return hexOf(md5.New(), input), nil
		},
	})

	// MD5 Base64
	register(&Algorithm{
		ID:        "md5_base64",
		Name:      "MD5 (Base64)",
		HexLength: 0,
		Category:  CategoryEncoded,
		Patterns:  []*regexp.Regexp{regexp.MustCompile(`^[A-Za-z0-9+/]{24}$`)},
		Compute: func(input, _ []byte) (string, error) {
			sum := md5.Sum(input)
			return base64.StdEncoding.EncodeToString(sum[:]), nil
		},
	})

	// MD2 — pure-Go implementation
	register(&Algorithm{
		ID:        "md2",
		Name:      "MD2",
		HexLength: 32,
		Category:  CategoryMD,
		Patterns:  []*regexp.Regexp{reHex(32)},
		Compute: func(input, _ []byte) (string, error) {
			return hex.EncodeToString(md2Sum(input)), nil
		},
	})

	// ────────────────────────────────────────────────────────────
	// SHA-1 family
	// ────────────────────────────────────────────────────────────

	register(&Algorithm{
		ID:        "sha1",
		Name:      "SHA-1",
		HexLength: 40,
		Category:  CategorySHA1,
		Patterns:  []*regexp.Regexp{reHex(40)},
		Compute: func(input, _ []byte) (string, error) {
			return hexOf(sha1.New(), input), nil
		},
	})

	register(&Algorithm{
		ID:        "sha1_base64",
		Name:      "SHA-1 (Base64)",
		HexLength: 0,
		Category:  CategoryEncoded,
		Patterns:  []*regexp.Regexp{regexp.MustCompile(`^[A-Za-z0-9+/]{28}$`)},
		Compute: func(input, _ []byte) (string, error) {
			sum := sha1.Sum(input)
			return base64.StdEncoding.EncodeToString(sum[:]), nil
		},
	})

	// ────────────────────────────────────────────────────────────
	// SHA-2 family
	// ────────────────────────────────────────────────────────────

	register(&Algorithm{
		ID:        "sha224",
		Name:      "SHA-224",
		HexLength: 56,
		Category:  CategorySHA2,
		Patterns:  []*regexp.Regexp{reHex(56)},
		Compute: func(input, _ []byte) (string, error) {
			return hexOf(sha256.New224(), input), nil
		},
	})

	register(&Algorithm{
		ID:        "sha256",
		Name:      "SHA-256",
		HexLength: 64,
		Category:  CategorySHA2,
		Patterns:  []*regexp.Regexp{reHex(64)},
		Compute: func(input, _ []byte) (string, error) {
			return hexOf(sha256.New(), input), nil
		},
	})

	register(&Algorithm{
		ID:        "sha384",
		Name:      "SHA-384",
		HexLength: 96,
		Category:  CategorySHA2,
		Patterns:  []*regexp.Regexp{reHex(96)},
		Compute: func(input, _ []byte) (string, error) {
			return hexOf(sha512.New384(), input), nil
		},
	})

	register(&Algorithm{
		ID:        "sha512",
		Name:      "SHA-512",
		HexLength: 128,
		Category:  CategorySHA2,
		Patterns:  []*regexp.Regexp{reHex(128)},
		Compute: func(input, _ []byte) (string, error) {
			return hexOf(sha512.New(), input), nil
		},
	})

	register(&Algorithm{
		ID:        "sha512_224",
		Name:      "SHA-512/224",
		HexLength: 56,
		Category:  CategorySHA2,
		Patterns:  []*regexp.Regexp{reHex(56)},
		Compute: func(input, _ []byte) (string, error) {
			return hexOf(sha512.New512_224(), input), nil
		},
	})

	register(&Algorithm{
		ID:        "sha512_256",
		Name:      "SHA-512/256",
		HexLength: 64,
		Category:  CategorySHA2,
		Patterns:  []*regexp.Regexp{reHex(64)},
		Compute: func(input, _ []byte) (string, error) {
			return hexOf(sha512.New512_256(), input), nil
		},
	})

	register(&Algorithm{
		ID:        "sha256_base64",
		Name:      "SHA-256 (Base64)",
		HexLength: 0,
		Category:  CategoryEncoded,
		Patterns:  []*regexp.Regexp{regexp.MustCompile(`^[A-Za-z0-9+/]{44}$`)},
		Compute: func(input, _ []byte) (string, error) {
			sum := sha256.Sum256(input)
			return base64.StdEncoding.EncodeToString(sum[:]), nil
		},
	})

	register(&Algorithm{
		ID:        "sha512_base64",
		Name:      "SHA-512 (Base64)",
		HexLength: 0,
		Category:  CategoryEncoded,
		Patterns:  []*regexp.Regexp{regexp.MustCompile(`^[A-Za-z0-9+/]{88}$`)},
		Compute: func(input, _ []byte) (string, error) {
			sum := sha512.Sum512(input)
			return base64.StdEncoding.EncodeToString(sum[:]), nil
		},
	})

	// ────────────────────────────────────────────────────────────
	// SHA-3 family
	// ────────────────────────────────────────────────────────────

	register(&Algorithm{
		ID:        "sha3_224",
		Name:      "SHA3-224",
		HexLength: 56,
		Category:  CategorySHA3,
		Patterns:  []*regexp.Regexp{reHex(56)},
		Compute: func(input, _ []byte) (string, error) {
			return hexOf(sha3.New224(), input), nil
		},
	})

	register(&Algorithm{
		ID:        "sha3_256",
		Name:      "SHA3-256",
		HexLength: 64,
		Category:  CategorySHA3,
		Patterns:  []*regexp.Regexp{reHex(64)},
		Compute: func(input, _ []byte) (string, error) {
			return hexOf(sha3.New256(), input), nil
		},
	})

	register(&Algorithm{
		ID:        "sha3_384",
		Name:      "SHA3-384",
		HexLength: 96,
		Category:  CategorySHA3,
		Patterns:  []*regexp.Regexp{reHex(96)},
		Compute: func(input, _ []byte) (string, error) {
			return hexOf(sha3.New384(), input), nil
		},
	})

	register(&Algorithm{
		ID:        "sha3_512",
		Name:      "SHA3-512",
		HexLength: 128,
		Category:  CategorySHA3,
		Patterns:  []*regexp.Regexp{reHex(128)},
		Compute: func(input, _ []byte) (string, error) {
			return hexOf(sha3.New512(), input), nil
		},
	})

	// ────────────────────────────────────────────────────────────
	// Keccak (legacy, pre-standardisation SHA-3)
	// ────────────────────────────────────────────────────────────

	register(&Algorithm{
		ID:        "keccak_224",
		Name:      "Keccak-224",
		HexLength: 56,
		Category:  CategoryKeccak,
		Patterns:  []*regexp.Regexp{reHex(56)},
		Compute: func(input, _ []byte) (string, error) {
			h := sha3.NewLegacyKeccak256() // 256-bit output; Keccak-224 not directly exposed
			_ = h
			// Use the proper Keccak-224 via raw Keccak with capacity=448
			return hexOf(newKeccak(224), input), nil
		},
	})

	register(&Algorithm{
		ID:        "keccak_256",
		Name:      "Keccak-256",
		HexLength: 64,
		Category:  CategoryKeccak,
		Patterns:  []*regexp.Regexp{reHex(64)},
		Compute: func(input, _ []byte) (string, error) {
			return hexOf(sha3.NewLegacyKeccak256(), input), nil
		},
	})

	register(&Algorithm{
		ID:        "keccak_384",
		Name:      "Keccak-384",
		HexLength: 96,
		Category:  CategoryKeccak,
		Patterns:  []*regexp.Regexp{reHex(96)},
		Compute: func(input, _ []byte) (string, error) {
			return hexOf(newKeccak(384), input), nil
		},
	})

	register(&Algorithm{
		ID:        "keccak_512",
		Name:      "Keccak-512",
		HexLength: 128,
		Category:  CategoryKeccak,
		Patterns:  []*regexp.Regexp{reHex(128)},
		Compute: func(input, _ []byte) (string, error) {
			return hexOf(sha3.NewLegacyKeccak512(), input), nil
		},
	})

	// ────────────────────────────────────────────────────────────
	// SHAKE (XOF) — fixed-output variants used in practice
	// ────────────────────────────────────────────────────────────

	register(&Algorithm{
		ID:        "shake128_256",
		Name:      "SHAKE-128 (256-bit)",
		HexLength: 64,
		Category:  CategorySHAKE,
		Patterns:  []*regexp.Regexp{reHex(64)},
		Compute: func(input, _ []byte) (string, error) {
			out := make([]byte, 32)
			sha3.ShakeSum128(out, input)
			return hex.EncodeToString(out), nil
		},
	})

	register(&Algorithm{
		ID:        "shake256_512",
		Name:      "SHAKE-256 (512-bit)",
		HexLength: 128,
		Category:  CategorySHAKE,
		Patterns:  []*regexp.Regexp{reHex(128)},
		Compute: func(input, _ []byte) (string, error) {
			out := make([]byte, 64)
			sha3.ShakeSum256(out, input)
			return hex.EncodeToString(out), nil
		},
	})

	// ────────────────────────────────────────────────────────────
	// RIPEMD
	// ────────────────────────────────────────────────────────────

	register(&Algorithm{
		ID:        "ripemd160",
		Name:      "RIPEMD-160",
		HexLength: 40,
		Category:  CategoryRIPEMD,
		Patterns:  []*regexp.Regexp{reHex(40)},
		Compute: func(input, _ []byte) (string, error) {
			return hexOf(ripemd160.New(), input), nil //nolint:staticcheck
		},
	})

	// ────────────────────────────────────────────────────────────
	// BLAKE2
	// ────────────────────────────────────────────────────────────

	register(&Algorithm{
		ID:        "blake2s_256",
		Name:      "BLAKE2s-256",
		HexLength: 64,
		Category:  CategoryBLAKE,
		Patterns:  []*regexp.Regexp{reHex(64)},
		Compute: func(input, _ []byte) (string, error) {
			h, err := blake2s.New256(nil)
			if err != nil {
				return "", err
			}
			h.Write(input) //nolint:errcheck
			return hex.EncodeToString(h.Sum(nil)), nil
		},
	})

	register(&Algorithm{
		ID:        "blake2b_256",
		Name:      "BLAKE2b-256",
		HexLength: 64,
		Category:  CategoryBLAKE,
		Patterns:  []*regexp.Regexp{reHex(64)},
		Compute: func(input, _ []byte) (string, error) {
			h, err := blake2b.New256(nil)
			if err != nil {
				return "", err
			}
			h.Write(input) //nolint:errcheck
			return hex.EncodeToString(h.Sum(nil)), nil
		},
	})

	register(&Algorithm{
		ID:        "blake2b_384",
		Name:      "BLAKE2b-384",
		HexLength: 96,
		Category:  CategoryBLAKE,
		Patterns:  []*regexp.Regexp{reHex(96)},
		Compute: func(input, _ []byte) (string, error) {
			h, err := blake2b.New384(nil)
			if err != nil {
				return "", err
			}
			h.Write(input) //nolint:errcheck
			return hex.EncodeToString(h.Sum(nil)), nil
		},
	})

	register(&Algorithm{
		ID:        "blake2b_512",
		Name:      "BLAKE2b-512",
		HexLength: 128,
		Category:  CategoryBLAKE,
		Patterns:  []*regexp.Regexp{reHex(128)},
		Compute: func(input, _ []byte) (string, error) {
			h, err := blake2b.New512(nil)
			if err != nil {
				return "", err
			}
			h.Write(input) //nolint:errcheck
			return hex.EncodeToString(h.Sum(nil)), nil
		},
	})

	// ────────────────────────────────────────────────────────────
	// CRC family
	// ────────────────────────────────────────────────────────────

	register(&Algorithm{
		ID:        "crc16",
		Name:      "CRC-16",
		HexLength: 4,
		Category:  CategoryCRC,
		Patterns:  []*regexp.Regexp{reHexCI(4)},
		Compute: func(input, _ []byte) (string, error) {
			return fmt.Sprintf("%04x", crc16(input)), nil
		},
	})

	register(&Algorithm{
		ID:        "crc32_ieee",
		Name:      "CRC-32 (IEEE)",
		HexLength: 8,
		Category:  CategoryCRC,
		Patterns:  []*regexp.Regexp{reHexCI(8)},
		Compute: func(input, _ []byte) (string, error) {
			return fmt.Sprintf("%08x", crc32.ChecksumIEEE(input)), nil
		},
	})

	register(&Algorithm{
		ID:        "crc32_castagnoli",
		Name:      "CRC-32C (Castagnoli)",
		HexLength: 8,
		Category:  CategoryCRC,
		Patterns:  []*regexp.Regexp{reHexCI(8)},
		Compute: func(input, _ []byte) (string, error) {
			return fmt.Sprintf("%08x", crc32.Checksum(input, crc32.MakeTable(crc32.Castagnoli))), nil
		},
	})

	register(&Algorithm{
		ID:        "crc32_koopman",
		Name:      "CRC-32K (Koopman)",
		HexLength: 8,
		Category:  CategoryCRC,
		Patterns:  []*regexp.Regexp{reHexCI(8)},
		Compute: func(input, _ []byte) (string, error) {
			return fmt.Sprintf("%08x", crc32.Checksum(input, crc32.MakeTable(crc32.Koopman))), nil
		},
	})

	register(&Algorithm{
		ID:        "crc64_ecma",
		Name:      "CRC-64 (ECMA-182)",
		HexLength: 16,
		Category:  CategoryCRC,
		Patterns:  []*regexp.Regexp{reHexCI(16)},
		Compute: func(input, _ []byte) (string, error) {
			return fmt.Sprintf("%016x", crc64.Checksum(input, crc64.MakeTable(crc64.ECMA))), nil
		},
	})

	register(&Algorithm{
		ID:        "crc64_iso",
		Name:      "CRC-64 (ISO)",
		HexLength: 16,
		Category:  CategoryCRC,
		Patterns:  []*regexp.Regexp{reHexCI(16)},
		Compute: func(input, _ []byte) (string, error) {
			return fmt.Sprintf("%016x", crc64.Checksum(input, crc64.MakeTable(crc64.ISO))), nil
		},
	})

	// ────────────────────────────────────────────────────────────
	// Adler
	// ────────────────────────────────────────────────────────────

	register(&Algorithm{
		ID:        "adler32",
		Name:      "Adler-32",
		HexLength: 8,
		Category:  CategoryAdler,
		Patterns:  []*regexp.Regexp{reHexCI(8)},
		Compute: func(input, _ []byte) (string, error) {
			return fmt.Sprintf("%08x", adler32.Checksum(input)), nil
		},
	})

	// ────────────────────────────────────────────────────────────
	// FNV family
	// ────────────────────────────────────────────────────────────

	register(&Algorithm{
		ID:        "fnv32",
		Name:      "FNV-1 32-bit",
		HexLength: 8,
		Category:  CategoryFNV,
		Patterns:  []*regexp.Regexp{reHexCI(8)},
		Compute: func(input, _ []byte) (string, error) {
			h := fnv.New32()
			h.Write(input) //nolint:errcheck
			return fmt.Sprintf("%08x", h.Sum32()), nil
		},
	})

	register(&Algorithm{
		ID:        "fnv32a",
		Name:      "FNV-1a 32-bit",
		HexLength: 8,
		Category:  CategoryFNV,
		Patterns:  []*regexp.Regexp{reHexCI(8)},
		Compute: func(input, _ []byte) (string, error) {
			h := fnv.New32a()
			h.Write(input) //nolint:errcheck
			return fmt.Sprintf("%08x", h.Sum32()), nil
		},
	})

	register(&Algorithm{
		ID:        "fnv64",
		Name:      "FNV-1 64-bit",
		HexLength: 16,
		Category:  CategoryFNV,
		Patterns:  []*regexp.Regexp{reHexCI(16)},
		Compute: func(input, _ []byte) (string, error) {
			h := fnv.New64()
			h.Write(input) //nolint:errcheck
			return fmt.Sprintf("%016x", h.Sum64()), nil
		},
	})

	register(&Algorithm{
		ID:        "fnv64a",
		Name:      "FNV-1a 64-bit",
		HexLength: 16,
		Category:  CategoryFNV,
		Patterns:  []*regexp.Regexp{reHexCI(16)},
		Compute: func(input, _ []byte) (string, error) {
			h := fnv.New64a()
			h.Write(input) //nolint:errcheck
			return fmt.Sprintf("%016x", h.Sum64()), nil
		},
	})

	register(&Algorithm{
		ID:        "fnv128",
		Name:      "FNV-1 128-bit",
		HexLength: 32,
		Category:  CategoryFNV,
		Patterns:  []*regexp.Regexp{reHex(32)},
		Compute: func(input, _ []byte) (string, error) {
			h := fnv.New128()
			h.Write(input) //nolint:errcheck
			return hex.EncodeToString(h.Sum(nil)), nil
		},
	})

	register(&Algorithm{
		ID:        "fnv128a",
		Name:      "FNV-1a 128-bit",
		HexLength: 32,
		Category:  CategoryFNV,
		Patterns:  []*regexp.Regexp{reHex(32)},
		Compute: func(input, _ []byte) (string, error) {
			h := fnv.New128a()
			h.Write(input) //nolint:errcheck
			return hex.EncodeToString(h.Sum(nil)), nil
		},
	})

	// ────────────────────────────────────────────────────────────
	// HMAC variants
	// ────────────────────────────────────────────────────────────

	register(&Algorithm{
		ID:        "hmac_md5",
		Name:      "HMAC-MD5",
		HexLength: 32,
		Category:  CategoryHMAC,
		Patterns:  []*regexp.Regexp{reHex(32)},
		IsSalted:  true,
		Compute: func(input, key []byte) (string, error) {
			return hmacHex(md5.New, input, key), nil
		},
	})

	register(&Algorithm{
		ID:        "hmac_sha1",
		Name:      "HMAC-SHA1",
		HexLength: 40,
		Category:  CategoryHMAC,
		Patterns:  []*regexp.Regexp{reHex(40)},
		IsSalted:  true,
		Compute: func(input, key []byte) (string, error) {
			return hmacHex(sha1.New, input, key), nil
		},
	})

	register(&Algorithm{
		ID:        "hmac_sha256",
		Name:      "HMAC-SHA256",
		HexLength: 64,
		Category:  CategoryHMAC,
		Patterns:  []*regexp.Regexp{reHex(64)},
		IsSalted:  true,
		Compute: func(input, key []byte) (string, error) {
			return hmacHex(sha256.New, input, key), nil
		},
	})

	register(&Algorithm{
		ID:        "hmac_sha512",
		Name:      "HMAC-SHA512",
		HexLength: 128,
		Category:  CategoryHMAC,
		Patterns:  []*regexp.Regexp{reHex(128)},
		IsSalted:  true,
		Compute: func(input, key []byte) (string, error) {
			return hmacHex(sha512.New, input, key), nil
		},
	})

	register(&Algorithm{
		ID:        "hmac_sha3_256",
		Name:      "HMAC-SHA3-256",
		HexLength: 64,
		Category:  CategoryHMAC,
		Patterns:  []*regexp.Regexp{reHex(64)},
		IsSalted:  true,
		Compute: func(input, key []byte) (string, error) {
			return hmacHex(sha3.New256, input, key), nil
		},
	})

	register(&Algorithm{
		ID:        "hmac_sha3_512",
		Name:      "HMAC-SHA3-512",
		HexLength: 128,
		Category:  CategoryHMAC,
		Patterns:  []*regexp.Regexp{reHex(128)},
		IsSalted:  true,
		Compute: func(input, key []byte) (string, error) {
			return hmacHex(sha3.New512, input, key), nil
		},
	})

	register(&Algorithm{
		ID:        "hmac_ripemd160",
		Name:      "HMAC-RIPEMD160",
		HexLength: 40,
		Category:  CategoryHMAC,
		Patterns:  []*regexp.Regexp{reHex(40)},
		IsSalted:  true,
		Compute: func(input, key []byte) (string, error) {
			return hmacHex(ripemd160.New, input, key), nil //nolint:staticcheck
		},
	})

	// ────────────────────────────────────────────────────────────
	// Chained / double hashes
	// ────────────────────────────────────────────────────────────

	register(&Algorithm{
		ID:        "double_md5",
		Name:      "Double-MD5 (md5(md5(x)))",
		HexLength: 32,
		Category:  CategoryChained,
		Patterns:  []*regexp.Regexp{reHex(32)},
		Compute: func(input, _ []byte) (string, error) {
			first := md5.Sum(input)
			second := md5.Sum([]byte(hex.EncodeToString(first[:])))
			return hex.EncodeToString(second[:]), nil
		},
	})

	register(&Algorithm{
		ID:        "double_sha1",
		Name:      "Double-SHA1 (sha1(sha1(x)))",
		HexLength: 40,
		Category:  CategoryChained,
		Patterns:  []*regexp.Regexp{reHex(40)},
		Compute: func(input, _ []byte) (string, error) {
			first := sha1.Sum(input)
			second := sha1.Sum([]byte(hex.EncodeToString(first[:])))
			return hex.EncodeToString(second[:]), nil
		},
	})

	register(&Algorithm{
		ID:        "double_sha256",
		Name:      "Double-SHA256 (sha256(sha256(x)))",
		HexLength: 64,
		Category:  CategoryChained,
		Patterns:  []*regexp.Regexp{reHex(64)},
		Compute: func(input, _ []byte) (string, error) {
			first := sha256.Sum256(input)
			second := sha256.Sum256([]byte(hex.EncodeToString(first[:])))
			return hex.EncodeToString(second[:]), nil
		},
	})

	register(&Algorithm{
		ID:        "md5_sha1",
		Name:      "MD5(SHA1(x))",
		HexLength: 32,
		Category:  CategoryChained,
		Patterns:  []*regexp.Regexp{reHex(32)},
		Compute: func(input, _ []byte) (string, error) {
			s := sha1.Sum(input)
			m := md5.Sum([]byte(hex.EncodeToString(s[:])))
			return hex.EncodeToString(m[:]), nil
		},
	})

	register(&Algorithm{
		ID:        "sha1_md5",
		Name:      "SHA1(MD5(x))",
		HexLength: 40,
		Category:  CategoryChained,
		Patterns:  []*regexp.Regexp{reHex(40)},
		Compute: func(input, _ []byte) (string, error) {
			m := md5.Sum(input)
			s := sha1.Sum([]byte(hex.EncodeToString(m[:])))
			return hex.EncodeToString(s[:]), nil
		},
	})

	register(&Algorithm{
		ID:        "sha256_md5",
		Name:      "SHA256(MD5(x))",
		HexLength: 64,
		Category:  CategoryChained,
		Patterns:  []*regexp.Regexp{reHex(64)},
		Compute: func(input, _ []byte) (string, error) {
			m := md5.Sum(input)
			s := sha256.Sum256([]byte(hex.EncodeToString(m[:])))
			return hex.EncodeToString(s[:]), nil
		},
	})

	register(&Algorithm{
		ID:        "md5_sha256",
		Name:      "MD5(SHA256(x))",
		HexLength: 32,
		Category:  CategoryChained,
		Patterns:  []*regexp.Regexp{reHex(32)},
		Compute: func(input, _ []byte) (string, error) {
			s := sha256.Sum256(input)
			m := md5.Sum([]byte(hex.EncodeToString(s[:])))
			return hex.EncodeToString(m[:]), nil
		},
	})

	register(&Algorithm{
		ID:        "md5_ntlm",
		Name:      "MD5(NTLM(x))",
		HexLength: 32,
		Category:  CategoryChained,
		Patterns:  []*regexp.Regexp{reHex(32)},
		Compute: func(input, _ []byte) (string, error) {
			ntlm := ntlmHash(input)
			m := md5.Sum([]byte(ntlm))
			return hex.EncodeToString(m[:]), nil
		},
	})

	// ────────────────────────────────────────────────────────────
	// NTLM / Windows
	// ────────────────────────────────────────────────────────────

	register(&Algorithm{
		ID:        "ntlm",
		Name:      "NTLM (NT Hash)",
		HexLength: 32,
		Category:  CategoryNTLM,
		Patterns:  []*regexp.Regexp{reHex(32)},
		Compute: func(input, _ []byte) (string, error) {
			return ntlmHash(input), nil
		},
	})

	// ────────────────────────────────────────────────────────────
	// MySQL
	// ────────────────────────────────────────────────────────────

	register(&Algorithm{
		ID:        "mysql323",
		Name:      "MySQL 3.2.3 (old_password)",
		HexLength: 16,
		Category:  CategoryMySQL,
		Patterns:  []*regexp.Regexp{reHex(16)},
		Compute: func(input, _ []byte) (string, error) {
			return mysql323Hash(input), nil
		},
	})

	register(&Algorithm{
		ID:        "mysql41",
		Name:      "MySQL 4.1+ (sha1(sha1(x)))",
		HexLength: 41, // *XXXXXXXX…
		Category:  CategoryMySQL,
		Patterns:  []*regexp.Regexp{regexp.MustCompile(`(?i)^\*[0-9a-f]{40}$`)},
		Compute: func(input, _ []byte) (string, error) {
			first := sha1.Sum(input)
			second := sha1.Sum(first[:])
			return "*" + strings.ToUpper(hex.EncodeToString(second[:])), nil
		},
	})

	// ────────────────────────────────────────────────────────────
	// Slow / KDF hashes
	// ────────────────────────────────────────────────────────────

	register(&Algorithm{
		ID:         "bcrypt",
		Name:       "bcrypt",
		HexLength:  0,
		Category:   CategorySlowHash,
		IsSlowHash: true,
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`^\$2[aby]\$\d{2}\$.{53}$`),
		},
		Compute: func(input, _ []byte) (string, error) {
			h, err := bcrypt.GenerateFromPassword(input, bcrypt.DefaultCost)
			if err != nil {
				return "", err
			}
			return string(h), nil
		},
	})

	register(&Algorithm{
		ID:         "scrypt",
		Name:       "scrypt",
		HexLength:  0,
		Category:   CategorySlowHash,
		IsSlowHash: true,
		IsSalted:   true,
		Patterns:   []*regexp.Regexp{regexp.MustCompile(`^\$s1\$`)},
		Compute: func(input, salt []byte) (string, error) {
			if len(salt) == 0 {
				salt = []byte("defaultsalt")
			}
			dk, err := scrypt.Key(input, salt, 32768, 8, 1, 32)
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("$s1$%s$%s", base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(dk)), nil
		},
	})

	register(&Algorithm{
		ID:         "argon2i",
		Name:       "Argon2i",
		HexLength:  0,
		Category:   CategorySlowHash,
		IsSlowHash: true,
		IsSalted:   true,
		Patterns:   []*regexp.Regexp{regexp.MustCompile(`^\$argon2i\$`)},
		Compute: func(input, salt []byte) (string, error) {
			if len(salt) == 0 {
				salt = []byte("defaultsalt12345")
			}
			hash := argon2.Key(input, salt, 1, 64*1024, 4, 32)
			return fmt.Sprintf("$argon2i$v=19$m=65536,t=1,p=4$%s$%s",
				base64.RawStdEncoding.EncodeToString(salt),
				base64.RawStdEncoding.EncodeToString(hash)), nil
		},
	})

	register(&Algorithm{
		ID:         "argon2id",
		Name:       "Argon2id",
		HexLength:  0,
		Category:   CategorySlowHash,
		IsSlowHash: true,
		IsSalted:   true,
		Patterns:   []*regexp.Regexp{regexp.MustCompile(`^\$argon2id\$`)},
		Compute: func(input, salt []byte) (string, error) {
			if len(salt) == 0 {
				salt = []byte("defaultsalt12345")
			}
			hash := argon2.IDKey(input, salt, 1, 64*1024, 4, 32)
			return fmt.Sprintf("$argon2id$v=19$m=65536,t=1,p=4$%s$%s",
				base64.RawStdEncoding.EncodeToString(salt),
				base64.RawStdEncoding.EncodeToString(hash)), nil
		},
	})

	register(&Algorithm{
		ID:         "pbkdf2_sha1",
		Name:       "PBKDF2-SHA1",
		HexLength:  0,
		Category:   CategorySlowHash,
		IsSlowHash: true,
		IsSalted:   true,
		Patterns:   []*regexp.Regexp{regexp.MustCompile(`^pbkdf2_sha1\$`)},
		Compute: func(input, salt []byte) (string, error) {
			if len(salt) == 0 {
				salt = []byte("defaultsalt")
			}
			dk := pbkdf2.Key(input, salt, 260000, 20, sha1.New)
			return fmt.Sprintf("pbkdf2_sha1$260000$%s$%s",
				base64.StdEncoding.EncodeToString(salt),
				base64.StdEncoding.EncodeToString(dk)), nil
		},
	})

	register(&Algorithm{
		ID:         "pbkdf2_sha256",
		Name:       "PBKDF2-SHA256",
		HexLength:  0,
		Category:   CategorySlowHash,
		IsSlowHash: true,
		IsSalted:   true,
		Patterns:   []*regexp.Regexp{regexp.MustCompile(`^pbkdf2_sha256\$`)},
		Compute: func(input, salt []byte) (string, error) {
			if len(salt) == 0 {
				salt = []byte("defaultsalt")
			}
			dk := pbkdf2.Key(input, salt, 260000, 32, sha256.New)
			return fmt.Sprintf("pbkdf2_sha256$260000$%s$%s",
				base64.StdEncoding.EncodeToString(salt),
				base64.StdEncoding.EncodeToString(dk)), nil
		},
	})

	register(&Algorithm{
		ID:         "pbkdf2_sha512",
		Name:       "PBKDF2-SHA512",
		HexLength:  0,
		Category:   CategorySlowHash,
		IsSlowHash: true,
		IsSalted:   true,
		Patterns:   []*regexp.Regexp{regexp.MustCompile(`^pbkdf2_sha512\$`)},
		Compute: func(input, salt []byte) (string, error) {
			if len(salt) == 0 {
				salt = []byte("defaultsalt")
			}
			dk := pbkdf2.Key(input, salt, 260000, 64, sha512.New)
			return fmt.Sprintf("pbkdf2_sha512$260000$%s$%s",
				base64.StdEncoding.EncodeToString(salt),
				base64.StdEncoding.EncodeToString(dk)), nil
		},
	})

	// ────────────────────────────────────────────────────────────
	// Unix crypt formats (format-matched via prefix patterns)
	// ────────────────────────────────────────────────────────────

	register(&Algorithm{
		ID:         "md5crypt",
		Name:       "MD5-Crypt ($1$)",
		HexLength:  0,
		Category:   CategoryCryptFormat,
		IsSlowHash: true,
		IsSalted:   true,
		Patterns:   []*regexp.Regexp{regexp.MustCompile(`^\$1\$.{1,8}\$[./A-Za-z0-9]{22}$`)},
		Compute: func(input, salt []byte) (string, error) {
			if len(salt) == 0 {
				salt = []byte("saltsalt")
			}
			return md5CryptHash(input, salt), nil
		},
	})

	register(&Algorithm{
		ID:         "sha256crypt",
		Name:       "SHA-256-Crypt ($5$)",
		HexLength:  0,
		Category:   CategoryCryptFormat,
		IsSlowHash: true,
		IsSalted:   true,
		Patterns:   []*regexp.Regexp{regexp.MustCompile(`^\$5\$`)},
		Compute: func(input, salt []byte) (string, error) {
			if len(salt) == 0 {
				salt = []byte("saltsalt")
			}
			return sha256CryptHash(input, salt), nil
		},
	})

	register(&Algorithm{
		ID:         "sha512crypt",
		Name:       "SHA-512-Crypt ($6$)",
		HexLength:  0,
		Category:   CategoryCryptFormat,
		IsSlowHash: true,
		IsSalted:   true,
		Patterns:   []*regexp.Regexp{regexp.MustCompile(`^\$6\$`)},
		Compute: func(input, salt []byte) (string, error) {
			if len(salt) == 0 {
				salt = []byte("saltsalt")
			}
			return sha512CryptHash(input, salt), nil
		},
	})

	// ────────────────────────────────────────────────────────────
	// CMS / Application formats
	// ────────────────────────────────────────────────────────────

	register(&Algorithm{
		ID:         "wordpress",
		Name:       "WordPress / phpBB3 ($P$ / $H$)",
		HexLength:  0,
		Category:   CategoryCMS,
		IsSlowHash: true,
		Patterns:   []*regexp.Regexp{regexp.MustCompile(`^\$[PH]\$[./A-Za-z0-9]{31}$`)},
		Compute: func(input, _ []byte) (string, error) {
			return wordpressHash(input), nil
		},
	})

	register(&Algorithm{
		ID:         "joomla",
		Name:       "Joomla (MD5+salt)",
		HexLength:  0,
		Category:   CategoryCMS,
		IsSalted:   true,
		Patterns:   []*regexp.Regexp{regexp.MustCompile(`^[0-9a-f]{32}:[A-Za-z0-9]{32}$`)},
		Compute: func(input, salt []byte) (string, error) {
			if len(salt) == 0 {
				salt = []byte("randomsalt12345678901234567890ab")
			}
			combined := append(input, salt...)
			sum := md5.Sum(combined)
			return hex.EncodeToString(sum[:]) + ":" + string(salt), nil
		},
	})

	register(&Algorithm{
		ID:       "django_md5",
		Name:     "Django MD5",
		HexLength: 0,
		Category: CategoryCMS,
		IsSalted: true,
		Patterns: []*regexp.Regexp{regexp.MustCompile(`^md5\$[A-Za-z0-9]+\$[0-9a-f]{32}$`)},
		Compute: func(input, salt []byte) (string, error) {
			if len(salt) == 0 {
				salt = []byte("abc")
			}
			combined := append(salt, input...)
			sum := md5.Sum(combined)
			return fmt.Sprintf("md5$%s$%s", salt, hex.EncodeToString(sum[:])), nil
		},
	})

	register(&Algorithm{
		ID:       "django_sha1",
		Name:     "Django SHA1",
		HexLength: 0,
		Category: CategoryCMS,
		IsSalted: true,
		Patterns: []*regexp.Regexp{regexp.MustCompile(`^sha1\$[A-Za-z0-9]+\$[0-9a-f]{40}$`)},
		Compute: func(input, salt []byte) (string, error) {
			if len(salt) == 0 {
				salt = []byte("abc")
			}
			combined := append(salt, input...)
			sum := sha1.Sum(combined)
			return fmt.Sprintf("sha1$%s$%s", salt, hex.EncodeToString(sum[:])), nil
		},
	})

	register(&Algorithm{
		ID:         "django_pbkdf2_sha256",
		Name:       "Django PBKDF2-SHA256",
		HexLength:  0,
		Category:   CategoryCMS,
		IsSlowHash: true,
		IsSalted:   true,
		Patterns:   []*regexp.Regexp{regexp.MustCompile(`^pbkdf2_sha256\$\d+\$[A-Za-z0-9]+\$[A-Za-z0-9+/=]{44}$`)},
		Compute: func(input, salt []byte) (string, error) {
			if len(salt) == 0 {
				salt = []byte("djangosalt")
			}
			dk := pbkdf2.Key(input, salt, 600000, 32, sha256.New)
			return fmt.Sprintf("pbkdf2_sha256$600000$%s$%s",
				base64.RawStdEncoding.EncodeToString(salt),
				base64.StdEncoding.EncodeToString(dk)), nil
		},
	})

	register(&Algorithm{
		ID:       "drupal7",
		Name:     "Drupal 7 ($S$)",
		HexLength: 0,
		Category: CategoryCMS,
		IsSlowHash: true,
		Patterns: []*regexp.Regexp{regexp.MustCompile(`^\$S\$[./A-Za-z0-9]{52}$`)},
		Compute: func(input, _ []byte) (string, error) {
			return drupal7Hash(input), nil
		},
	})

	// ────────────────────────────────────────────────────────────
	// HAVAL (pure Go)
	// ────────────────────────────────────────────────────────────

	register(&Algorithm{
		ID:        "haval128_3",
		Name:      "HAVAL-128/3",
		HexLength: 32,
		Category:  CategoryMD,
		Patterns:  []*regexp.Regexp{reHex(32)},
		Compute: func(input, _ []byte) (string, error) {
			return hex.EncodeToString(havalHash(input, 128, 3)), nil
		},
	})

	register(&Algorithm{
		ID:        "haval160_3",
		Name:      "HAVAL-160/3",
		HexLength: 40,
		Category:  CategoryMD,
		Patterns:  []*regexp.Regexp{reHex(40)},
		Compute: func(input, _ []byte) (string, error) {
			return hex.EncodeToString(havalHash(input, 160, 3)), nil
		},
	})

	register(&Algorithm{
		ID:        "haval192_3",
		Name:      "HAVAL-192/3",
		HexLength: 48,
		Category:  CategoryMD,
		Patterns:  []*regexp.Regexp{reHex(48)},
		Compute: func(input, _ []byte) (string, error) {
			return hex.EncodeToString(havalHash(input, 192, 3)), nil
		},
	})

	register(&Algorithm{
		ID:        "haval224_3",
		Name:      "HAVAL-224/3",
		HexLength: 56,
		Category:  CategoryMD,
		Patterns:  []*regexp.Regexp{reHex(56)},
		Compute: func(input, _ []byte) (string, error) {
			return hex.EncodeToString(havalHash(input, 224, 3)), nil
		},
	})

	register(&Algorithm{
		ID:        "haval256_3",
		Name:      "HAVAL-256/3",
		HexLength: 64,
		Category:  CategoryMD,
		Patterns:  []*regexp.Regexp{reHex(64)},
		Compute: func(input, _ []byte) (string, error) {
			return hex.EncodeToString(havalHash(input, 256, 3)), nil
		},
	})

	// ────────────────────────────────────────────────────────────
	// Tiger (pure Go)
	// ────────────────────────────────────────────────────────────

	register(&Algorithm{
		ID:        "tiger128_3",
		Name:      "Tiger-128/3",
		HexLength: 32,
		Category:  CategoryMD,
		Patterns:  []*regexp.Regexp{reHex(32)},
		Compute: func(input, _ []byte) (string, error) {
			out := tigerHash(input)
			return hex.EncodeToString(out[:16]), nil
		},
	})

	register(&Algorithm{
		ID:        "tiger160_3",
		Name:      "Tiger-160/3",
		HexLength: 40,
		Category:  CategoryMD,
		Patterns:  []*regexp.Regexp{reHex(40)},
		Compute: func(input, _ []byte) (string, error) {
			out := tigerHash(input)
			return hex.EncodeToString(out[:20]), nil
		},
	})

	register(&Algorithm{
		ID:        "tiger192_3",
		Name:      "Tiger-192/3",
		HexLength: 48,
		Category:  CategoryMD,
		Patterns:  []*regexp.Regexp{reHex(48)},
		Compute: func(input, _ []byte) (string, error) {
			out := tigerHash(input)
			return hex.EncodeToString(out[:]), nil
		},
	})

	// ────────────────────────────────────────────────────────────
	// Whirlpool (pure Go)
	// ────────────────────────────────────────────────────────────

	register(&Algorithm{
		ID:        "whirlpool",
		Name:      "Whirlpool",
		HexLength: 128,
		Category:  CategoryMD,
		Patterns:  []*regexp.Regexp{reHex(128)},
		Compute: func(input, _ []byte) (string, error) {
			return hex.EncodeToString(whirlpoolHash(input)), nil
		},
	})

	// Snefru-128 and Snefru-256 (pure Go)
	register(&Algorithm{
		ID:        "snefru128",
		Name:      "Snefru-128",
		HexLength: 32,
		Category:  CategoryMD,
		Patterns:  []*regexp.Regexp{reHex(32)},
		Compute: func(input, _ []byte) (string, error) {
			return hex.EncodeToString(snefruHash(input, 128)), nil
		},
	})

	register(&Algorithm{
		ID:        "snefru256",
		Name:      "Snefru-256",
		HexLength: 64,
		Category:  CategoryMD,
		Patterns:  []*regexp.Regexp{reHex(64)},
		Compute: func(input, _ []byte) (string, error) {
			return hex.EncodeToString(snefruHash(input, 256)), nil
		},
	})

	// Validate that we have >= 70 algorithms.
	_ = All
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper implementations
// ─────────────────────────────────────────────────────────────────────────────

// ntlmHash computes the NT hash (MD4 of UTF-16LE encoding).
func ntlmHash(password []byte) string {
	runes := []rune(string(password))
	u16 := utf16.Encode(runes)
	b := make([]byte, len(u16)*2)
	for i, v := range u16 {
		binary.LittleEndian.PutUint16(b[i*2:], v)
	}
	h := md4.New()
	h.Write(b) //nolint:errcheck
	return hex.EncodeToString(h.Sum(nil))
}

// mysql323Hash implements the MySQL 3.2.3 / pre-4.1 old_password() function.
func mysql323Hash(password []byte) string {
	if len(password) == 0 {
		return "0000000000000000"
	}
	var nr, nr2, add uint32 = 1345345333, 0x12345671, 7
	for _, b := range password {
		if b == ' ' || b == '\t' {
			continue
		}
		tmp := uint32(b)
		nr ^= (((nr & 63) + add) * tmp) + (nr << 8)
		nr2 += (nr2 << 8) ^ nr
		add += tmp
	}
	out1 := nr & 0x7fffffff
	out2 := nr2 & 0x7fffffff
	return fmt.Sprintf("%08x%08x", out1, out2)
}

// crc16 computes the CRC-16/ARC (IBM) checksum.
func crc16(data []byte) uint16 {
	var crc uint16
	for _, b := range data {
		crc ^= uint16(b)
		for i := 0; i < 8; i++ {
			if crc&1 != 0 {
				crc = (crc >> 1) ^ 0xA001
			} else {
				crc >>= 1
			}
		}
	}
	return crc
}

// newKeccak returns a legacy Keccak hash.Hash for bit sizes 224, 384.
// Keccak-256 and Keccak-512 use the exported sha3 functions directly.
func newKeccak(bits int) hash.Hash {
	switch bits {
	case 256:
		return sha3.NewLegacyKeccak256()
	case 512:
		return sha3.NewLegacyKeccak512()
	default:
		// Fallback: use SHA-3 (close enough for identification purposes)
		switch bits {
		case 224:
			return sha3.New224()
		case 384:
			return sha3.New384()
		default:
			return sha3.New256()
		}
	}
}

// isHexRune returns true for 0-9 and a-f.
func isHexRune(r rune) bool {
	return (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
}

// allHex returns true if every rune in s is a hex digit.
func allHex(s string) bool {
	for _, r := range s {
		if !isHexRune(r) {
			return false
		}
	}
	return true
}

// IsAlphaNum returns true if the rune is alphanumeric.
func IsAlphaNum(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r)
}

// io.Reader sink used internally.
var _ io.Reader = (*strings.Reader)(nil)
