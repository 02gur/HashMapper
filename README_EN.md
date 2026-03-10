# HashMapper

HashMapper is a Go tool designed to detect and crack complex and nested hash algorithms. It is especially useful for determining the method used to create a target hash when multiple algorithms are used in succession or when a salt is added to the hash text.
A hash obtained from the system and a clear text password are required for the tool to work.

## Features

* **Nested Hash Detection:** Can resolve multi-layered algorithms like MD5(SHA1(PASSWORD)).
* **Automatic Depth Expansion (-multi):** Can test an ambiguous structure sequentially up to a depth of N (e.g., SHA1(SHA1(SHA1(PASSWORD)))).
* **Salt Support:** Supports scenarios where a salt (additional data used alongside the password) is added to the beginning or end of the password.
* **Hex and Raw Formats:** During nested hashing, it can determine whether the output of the previous step is a "hex string" or a "raw byte" (or try both). This is especially useful for simulating PHP's `hash('algo', $pass, true)` behavior.
* **Unknown Algorithm Discovery:** By using `?` in the template, you can brute-force to find which algorithm was used.
* **Fast and Concurrent:** Produces fast results thanks to Go's concurrency structure (especially in progress and scanning loops).

## Supported Algorithms

A total of 70 algorithms are supported. You can use the `-list` argument to see the list of algorithms:

```bash
./hashmapper -list
```

**Available algorithms:**
```bash
    1. adler32                      2. blake2b-256              
    3. blake2b-384                  4. blake2b-512              
    5. blake2s-128                  6. blake2s-256              
    7. blake3                       8. blake3-256               
    9. blake3-512                  10. crc32                    
   11. crc32b                      12. crc32c                   
   13. fnv1128                     14. fnv132                   
   15. fnv164                      16. fnv1a128                 
   17. fnv1a32                     18. fnv1a64                  
   19. gost                        20. gost-crypto              
   21. haval128,3                  22. haval128,4               
   23. haval128,5                  24. haval160,3               
   25. haval160,4                  26. haval160,5               
   27. haval192,3                  28. haval192,4               
   29. haval192,5                  30. haval224,3               
   31. haval224,4                  32. haval224,5               
   33. haval256,3                  34. haval256,4               
   35. haval256,5                  36. joaat                    
   37. md2                         38. md4                      
   39. md5                         40. murmur3a                 
   41. murmur3c                    42. murmur3f                 
   43. ripemd128                   44. ripemd160                
   45. ripemd256                   46. ripemd320                
   47. sha1                        48. sha224                   
   49. sha256                      50. sha3-224                 
   51. sha3-256                    52. sha3-384                 
   53. sha3-512                    54. sha384                   
   55. sha512                      56. sha512/224               
   57. sha512/256                  58. shake128                 
   59. shake256                    60. tiger128,3               
   61. tiger128,4                  62. tiger160,3               
   63. tiger160,4                  64. tiger192,3               
   65. tiger192,4                  66. whirlpool                
   67. xxh128                      68. xxh3                     
   69. xxh32                       70. xxh64  
```
## Usage Parameters

The mandatory parameters for usage are `-hash` (the hex value to crack) and `-password` (the experimental plaintext password).

```text
USAGE:
  hashmapper -hash <HASH> -password <PASSWORD>  [FLAGS]

REQUIRED FLAGS:
  -hash      <value>   Target hash value (in hex format)
  -password  <value>   Password to test (plaintext)

OPTIONAL FLAGS:
  -salt      <value>   Salt value (used as SALT in the template)
  -template  <template> Used to specify a nested hash template
  -multi     <N>       Expands the ? token in the template up to N depths and tries them all
  -list                Lists the supported algorithms
  -examples            Shows usage examples
  -v                   Prints every combination attempt to the screen (verbose)
  -hex-only            Tries only the string (hex) output in inner templates
  -raw-only            Tries only the byte (raw) output in inner templates
```

## Usage Examples

### 0. Multi Mode (Automatic Depth)

If you suspect an algorithm might have been applied N times in succession, you can automate the tool with the `-multi` flag. There must be a single `?` in the template.

For example, the following command tries the password with SHA1 consecutively from 1 to 5 times:
```bash
./hashmapper -template 'SHA1(?)' -multi 5 -hash <HASH> -password "password"

./hashmapper -template '?(?)' -multi 5 -hash <HASH> -password "password"
# It sequentially tests the following:
# Depth 1: SHA1(SHA1(PASSWORD))
# Depth 2: SHA1(SHA1(SHA1(PASSWORD)))
# ...
# Depth 5: SHA1(SHA1(SHA1(SHA1(SHA1(PASSWORD)))))
```

### 1. Plain Mode (Simple Algorithm Detection)

If you think a target is encrypted with only a single algorithm, run it without the `-template`. The tool will try all algorithms sequentially.

```bash
./hashmapper -hash 5f4dcc3b5aa765d61d8327deb882cf99 -password password
```

### 2. Fixed Template Usage (Nested)

If you know the hash was created in a specific format (e.g., MD5(SHA1(PASSWORD))):

```bash
./hashmapper -template 'MD5(SHA1(PASSWORD))' -hash <HASH_VALUE> -password "secretpassword"
```

### 3. Salt Usage

If you know a salt (additional data used alongside the password) value was used (as a prefix or suffix), you can specify this in the template.

* Password + Salt (Suffix):
```bash
./hashmapper -template 'MD5(?(PASSWORD.SALT))' -hash <HASH> -password "password" -salt "123"
```
* Salt + Password (Prefix):
```bash
./hashmapper -template 'MD5(SALT.?(PASSWORD))' -hash <HASH> -password "password" -salt "123"
```

### 4. Finding Unknown Layers (?)

If you know the outer layer is MD5 but don't know what was used in the inner layer, you can use the `?` operator.

```bash
./hashmapper -template 'MD5(?(PASSWORD))' -hash <HASH> -password "password"
```

For situations where both layers are unknown:

```bash
./hashmapper -template '?(?(PASSWORD))' -hash <HASH> -password "password"
```

### 6. Hex and Raw Output Differences

Especially in languages like PHP, the output of a hash function returns in text format (hex), whereas when used as `hash('md5', 'data', true)`, it returns binary (raw byte). HashMapper calculates and tries both situations by default.

* To try only hex: `-hex-only`
* To try only raw (binary): `-raw-only`
