# Laboratoire de cryptographie

🇫🇷 [Français](#français) · 🇬🇧 [English](#english)

**Essayer l'outil :** https://valentin-auger-laboratoire.github.io/portfolio/outils/laboratoire-crypto/

---

## Français

### Ce que fait l'outil
SHA-256, AES et RSA écrits à la main, en JavaScript pur et sans bibliothèque, pour voir ce qui se passe à l'intérieur. Chaque résultat est comparé en direct au module de chiffrement du navigateur (Web Crypto). Rien de ce qui est tapé ne quitte la page.

**Hachage SHA-256**
- Empreinte d'un texte, vérifiée contre Web Crypto.
- **Effet avalanche** : on change un seul bit du message, et environ la moitié des 256 bits de l'empreinte changent (carte des bits modifiés).
- Les 64 tours du premier bloc : registres a à h et mot W du message à chaque tour.

**Chiffrement AES-128**
- Modes **CBC** (rembourrage PKCS#7) et **CTR**, clé et vecteur au hasard, déchiffrement vérifié contre Web Crypto.
- Le premier bloc **étape par étape** (SubBytes, ShiftRows, MixColumns, AddRoundKey), avec les octets modifiés en rouge, et les 11 clés de tour.
- La boîte S est **calculée** (inverse dans GF(2⁸) puis transformation affine), pas recopiée.
- Modification d'un octet du message chiffré : message abîmé ou rembourrage refusé. C'est la démonstration qu'il faut aussi authentifier (AES-GCM, HMAC).

**RSA**
- Génération d'une clé de 32 à 1 024 bits :
  - nombres premiers testés par Miller-Rabin ;
  - n, φ, e = 65 537, d calculé par Euclide étendu.
- Chiffrement et déchiffrement d'un message court.
- **Signature** du haché SHA-256 et vérification : un message modifié est détecté.
- **Casser une clé trop courte** par la méthode rho de Pollard, qui retrouve p, q et la clé privée. S'y ajoute un tableau du temps estimé selon la taille de la clé, extrapolé depuis la vitesse mesurée dans le navigateur.

**Mots de passe**
- Entropie estimée :
  - taille de l'alphabet et longueur ;
  - pénalités pour les mots de passe courants, les prénoms, les suites de clavier, les répétitions et le motif « Mot + année + ! » ;
  - environ 11 bits par mot pour une phrase de passe.
- Temps moyen de cassage selon le stockage : attaque en ligne, bcrypt, PBKDF2, SHA-256 simple, MD5.
- **Sel et hachage lent** : PBKDF2-HMAC-SHA256 avec un nombre d'itérations réglable, temps mesuré et vérification contre Web Crypto.

### Fichiers
| Fichier | Rôle |
|---|---|
| `crypto.js` | SHA-256 (FIPS 180-4), HMAC, PBKDF2 (RFC 8018), AES-128 (FIPS 197) en CBC et CTR, RSA en BigInt (Miller-Rabin, Euclide étendu, signature), rho de Pollard, force des mots de passe |
| `index.html` | Interface, bilingue FR / EN |
| `tests/test.js` | Tests, comparés au module crypto de Node (OpenSSL) et aux vecteurs officiels |

### Lancer les tests
```bash
node tests/test.js
```
Environ 1 200 vérifications :
- SHA-256 : vecteurs officiels et **500 messages au hasard comparés à OpenSSL**, effet avalanche moyen d'environ 128 bits ;
- HMAC et PBKDF2 comparés à OpenSSL ;
- AES : boîte S, multiplication dans GF(2⁸), vecteur de la norme FIPS 197, expansion de clé, puis **200 messages au hasard en CBC et en CTR comparés à OpenSSL**, débordement du compteur ;
- RSA :
  - primalité (y compris des nombres de Carmichael, qui trompent les tests naïfs) ;
  - **p et q confirmés premiers par OpenSSL** jusqu'à 1 024 bits ;
  - e·d ≡ 1 mod φ, chiffrement aller-retour, signatures ;
  - factorisation d'une clé de 64 bits ;
- force des mots de passe sur des cas types.

### Limites
- **Outil pour comprendre, pas pour protéger.** Pas de protection contre les attaques par canaux auxiliaires (temps de calcul, cache).
- RSA « manuel », sans rembourrage OAEP ni PSS.
- AES sans authentification.
- L'estimation de la force d'un mot de passe est volontairement simple : de vrais outils (zxcvbn) utilisent de grands dictionnaires.
- Les vitesses d'attaque sont des ordres de grandeur.

### Utiliser en local
Ouvrir `index.html` dans un navigateur.

---

## English

### What the tool does
SHA-256, AES and RSA written by hand in plain JavaScript, with no library, to see what happens inside. Every result is compared live with the browser's Web Crypto module. Nothing typed leaves the page.

- **SHA-256**: digest, avalanche effect (one bit changed → about half the output bits change), the 64 rounds of the first block.
- **AES-128**:
  - CBC and CTR modes, the first block step by step (SubBytes, ShiftRows, MixColumns, AddRoundKey);
  - computed S-box, round keys;
  - tampering demo (why authentication is needed).
- **RSA**:
  - key generation from 32 to 1,024 bits (Miller-Rabin, extended Euclid);
  - encryption, signature and verification;
  - breaking a short key with Pollard's rho, with time estimates by key size.
- **Passwords**:
  - entropy estimate with penalties for common passwords, sequences and patterns;
  - crack time by storage method;
  - salted PBKDF2 with adjustable iterations.

### Tests
```bash
node tests/test.js
```
About 1,200 checks:
- SHA-256, HMAC, PBKDF2 and AES (CBC and CTR) compared with Node/OpenSSL on official vectors and random inputs;
- RSA primes confirmed by OpenSSL up to 1,024 bits, Carmichael numbers rejected;
- round trips, signatures, factoring a 64-bit key.

### Limits
- Teaching implementation: not side-channel safe.
- Textbook RSA (no OAEP/PSS).
- No AES authentication.
- Simple password estimator.

---

← [Portfolio](https://valentin-auger-laboratoire.github.io/portfolio/#projets)
