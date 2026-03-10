# HashMapper

HashMapper, karmaşık ve iç içe geçmiş (nested) hash algoritmalarını tespit etmek ve kırmak için geliştirilmiş bir Go aracıdır. Özellikle birden fazla algoritmanın arka arkaya kullanıldığı veya hash metnine (salt) eklendiği durumlarda, hedef hash'in hangi yöntemle oluşturulduğunu bulmaya yardımcı olur.
Tool çalışabilmesi için sistemden alınmış bir hash ve clear text parolaya ihtiyaç vardır.

## Özellikler

* **İç İçe Hash Tespiti:** MD5(SHA1(PASSWORD)) gibi çok katmanlı algoritmaları çözebilir.
* **Otomatik Derinlik Genişletme (-multi):** Belirsiz bir yapıyı N derinliğine kadar arka arkaya test edebilir (Örn: SHA1(SHA1(SHA1(PASSWORD)))).
* **Salt Desteği:** Parola ile birlikte kullanılan salt (ek veri) değerinin, parolanın başına veya sonuna eklendiği senaryoları destekler.
* **Hex ve Raw Formatları:** İç içe hash'lemelerde bir önceki adımın çıktısının "hex string" mi yoksa "raw byte" mı olduğunu belirleyip (veya her ikisini de) deneyebilir (Özellikle PHP'deki `hash('algo', $pass, true)` davranışını simüle eder).
* **Bilinmeyen Algoritma Belirleme:** Şablonda `?` kullanarak hangi algoritmanın kullanıldığını brute-force ile arayabilirsiniz.
* **Hızlı ve Eşzamanlı:** Go'nun concurrency yapısı (özellikle progress ve tarama döngülerinde) sayesinde hızlı sonuç üretir.


## Desteklenen Algoritmalar

Toplam 70 adet algoritma desteklenmektedir. Algoritmaların listesini görmek için `-list` argümanını kullanabilirsiniz:

```bash
./hashmapper -list
```

**Mevcut algoritmalar:** 
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
## Kullanım Parametreleri

Kullanım zorunlu parametreler `-hash` (kırılacak hex değeri) ve `-password` (deneysel düz metin parolası).

```text
KULLANIM:
  hashmapper -hash <HASH> -password <PAROLA>  [BAYRAKLAR]

ZORUNLU BAYRAKLAR:
  -hash      <değer>   Hedef hash değeri (hex formatında)
  -password  <değer>   Test edilecek parola (düz metin)

OPSİYONEL BAYRAKLAR:
  -salt      <değer>   Salt değeri (şablonda SALT olarak kullanılır)
  -template  <şablon>  İç içe hash şablonu belirtmek için kullanılır
  -multi     <N>       Şablondaki ? token'ını 1'den N'e kadar derinliğe genişletip dener
  -list                Desteklenen algoritmaları listeler
  -examples            Kullanım örneklerini gösterir
  -v                   Her kombinasyon denemesini ekrana basar (verbose)
  -hex-only            İç şablonlarda sadece string (hex) çıktısını dener
  -raw-only            İç şablonlarda sadece byte (raw) çıktısını dener
```

## Örnek Kullanımlar

### 0. Multi Mod (Otomatik Derinlik)

Bir algoritmanın N defa üst üste uygulanmış olabileceğini düşünüyorsanız `-multi` bayrağı ile aracı otomatize edebilirsiniz. Şablonda tek bir `?` bulunmalıdır.

Örneğin, aşağıdaki komut parolayı 1'den 5'e kadar SHA1 ile arka arkaya dener:
```bash
./hashmapper -template 'SHA1(?)' -multi 5 -hash <HASH> -password "parola"

./hashmapper -template '?(?)' -multi 5 -hash <HASH> -password "parola"
# Sırayla şunları test eder:
# Derinlik 1: SHA1(SHA1(PASSWORD))
# Derinlik 2: SHA1(SHA1(SHA1(PASSWORD)))
# ...
# Derinlik 5: SHA1(SHA1(SHA1(SHA1(SHA1(PASSWORD)))))


### 1. Düz Mod (Basit Algoritma Tespiti)

Eğer bir hedefin sadece tek bir algoritma ile şifrelendiğini düşünüyorsanız `-template` vermeden çalıştırın. Araç tüm algoritmaları sırayla dener.

```bash
./hashmapper -hash 5f4dcc3b5aa765d61d8327deb882cf99 -password password
```

### 2. Sabit Şablon Kullanımı (İç İçe)

Hash'in belirli bir düzende (Örneğin MD5(SHA1(PAROLA))) oluşturulduğunu biliyorsanız:

```bash
./hashmapper -template 'MD5(SHA1(PASSWORD))' -hash <HASH_DEGERI> -password "gizliparola"
```

### 3. Salt Kullanımı

Parola ile birlikte kullanılan bir salt (ek veri) değeri olduğunu biliyorsanız (prefix veya suffix olarak) bunu şablonda belirtebilirsiniz.

* Parola + Salt (Suffix):
```bash
./hashmapper -template 'MD5(?(PASSWORD.SALT))' -hash <HASH> -password "parola" -salt "123"
```
* Salt + Parola (Prefix):
```bash
./hashmapper -template 'MD5(SALT.?(PASSWORD))' -hash <HASH> -password "parola" -salt "123"
```

### 4. Bilinmeyen Katmanları Bulma (?)

Dış katmanın MD5 olduğunu biliyor ancak iç katmanda ne kullanıldığını bilmiyorsanız `?` operatörünü kullanabilirsiniz.

```bash
./hashmapper -template 'MD5(?(PASSWORD))' -hash <HASH> -password "parola"
```

Her iki katmanın da bilinmediği durumlar için:

```bash
./hashmapper -template '?(?(PASSWORD))' -hash <HASH> -password "parola"
```
```
Templateler arttırılarak gidebilir. multi parametresi hepsini dener süre uzayabilir.

### 5. Hex ve Raw Çıktı Farkları

Özellikle PHP gibi dillerde bir hash fonksiyonunun çıktısı metin formatında (hex) dönerken `hash('md5', 'veri', true)` şeklinde kullanıldığında binary (raw byte) döner. HashMapper varsayılan olarak her iki durumu da hesaplayıp dener.

* Sadece hex denenmesi için: `-hex-only`
* Sadece raw (binary) denenmesi için: `-raw-only`
