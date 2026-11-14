# Fable, specifica v0.12

Chain proof-of-work che sposta coin da una chiave a un'altra. SHA-256 è l'unica primitiva crittografica e le regole sono congelate al genesis.
L'implementazione di riferimento è `fable.py`. Se questo testo e il codice non coincidono, vale il codice e il testo va corretto.

## 1. Codifiche e crittografia

- Tutti gli interi sono little-endian. Gli hash si scrivono nell'ordine dei byte in cui escono da SHA-256.
- `H(tag, x) = SHA-256(byte(tag) ‖ x)`. Tag: TX = 1, SIG = 2, LEAF = 3, WIT = 4, ADDR = 5, UTXO = 6.
- `sha256d(x) = SHA-256(SHA-256(x))`, usato per header, coinbase e nodi Merkle, come in Bitcoin.
- Firma: SLH-DSA-SHA2-128s (FIPS 205), interfaccia "pure" con contesto vuoto. Chiave pubblica 32 byte, firma 7.856 byte.
  Il consenso definisce solo la verifica: firme con o senza casualità aggiunta sono entrambe valide.
- Indirizzo: `H(ADDR, chiave pubblica)`, 32 byte, riusabile.
- Unità: 1 coin = 10^8 unità. Ticker: FABLE.

## 2. Transazione

| Campo | Byte | Valori |
| --- | --- | --- |
| `n_in` | 1 | 1–32 |
| per input: `prev_txid`, `prev_index` | 32 + 1 | indice 0–15 |
| `n_out` | 1 | 1–16 |
| per output: `importo`, `indirizzo` | 8 + 32 | importo 1–2^62 |
| `n_wit` | 1 | 1–min(4, n_in) |
| per testimone: chiave pubblica, firma | 32 + 7.856 | |

- Il **corpo** è tutto fino agli output compresi. I **testimoni** sono `n_wit` seguito dalle coppie.
- `txid = H(TX, corpo)`. Messaggio firmato: `H(SIG, chain_id ‖ corpo)`, uguale per tutti i testimoni.
- Foglia Merkle: `H(LEAF, txid ‖ H(WIT, testimoni))`.
- Dimensioni: 1 input e 2 output, 8.004 byte. 32 input da un indirizzo e 1 output, 8.987 byte. Massimo 33.251 byte. Un pagamento a 15 destinatari più il resto, da un indirizzo, pesa 8.564 byte.

**Regole**

1. Contatori nei limiti, input tutti distinti, lunghezza esatta.
2. Ogni input punta a un output non speso, anche creato prima nello stesso blocco. Un output di coinbase creato all'altezza `c` è spendibile da `c + 100`.
3. I testimoni sono esattamente gli indirizzi distinti degli input, nell'ordine in cui compaiono per la prima volta, ciascuno come `H(ADDR, pk)`.
4. Ogni firma è valida sul messaggio.
5. Somma input ≥ somma output. La differenza è la fee.

## 3. Blocco

`blocco = header (80) ‖ coinbase ‖ n_tx (1 byte, 0–80) ‖ transazioni`, senza byte in coda.

**Header, layout di Bitcoin**: `version` (4, qualunque valore), `prev_hash` (32), `merkle_root` (32), `time` (4, i 32 bit bassi), `bits` (4), `nonce` (4).

**Coinbase**: `height` (4) ‖ `extra` (8) ‖ `utxo_root` (32) ‖ `n_out` (1–2) ‖ output da 40 byte. Il suo id è `sha256d` dei suoi byte.

**Merkle**: foglie = id della coinbase, poi le foglie delle transazioni in ordine. Nodo interno `sha256d(sinistro ‖ destro)`; un nodo spaiato sale invariato.

**Regole**

1. `prev_hash` è l'hash della punta; `bits` è il valore ASERT; `sha256d(header)`, letto come intero little-endian, è ≤ target.
2. `merkle_root` corrisponde; `height` della coinbase è l'altezza del blocco.
3. `utxo_root` è quello della sezione 6 nei blocchi di snapshot, 32 zeri negli altri.
4. Al massimo 80 testimoni nel blocco, coinbase esclusa (circa 0,64 MB con transazioni tipiche, 0,77 MB al massimo).
5. Output della coinbase ≤ sussidio + fee. Incassare meno è ammesso: la differenza è bruciata.
6. Nessun output nuovo può avere un `(txid, indice)` già presente.

## 4. Consenso

- Tempo di blocco 60 s. Vince la catena con più lavoro cumulato, lavoro di un blocco = `2^256 / (target + 1)`. A parità vale la prima vista. Nessun checkpoint.
- **Tempo**: il valore pieno a 64 bit è il più piccolo maggiore del tempo del blocco precedente con quei 32 bit bassi. Deve essere ≤ orologio locale + 600 s.
- **Difficoltà (aserti3-2d di Bitcoin Cash, ancorato al genesis)**, per il blocco dopo un genitore di altezza `h` e tempo `t`:
  ```
  time_delta = t − (t_genesis − 60)
  num = (time_delta − 60 × (h + 1)) × 65536
  exponent = num / 3600            divisione troncata verso zero
  shifts = exponent >> 16          shift aritmetico
  exponent −= shifts × 65536
  factor = ((195766423245049·e + 971821376·e² + 5127·e³ + 2^47) >> 48) + 65536
  target = (target_genesis × factor) << shifts (o >> −shifts), poi >> 16
  ```
  Se `shifts > 300` o il risultato supera `0x1d00ffff` si usa `0x1d00ffff`; se `shifts < −300` o il risultato è 0 si usa 1. `bits` in forma compatta canonica.
- **Genesis**: header con `version` 1, `prev_hash` = hash di un blocco Bitcoin scelto il giorno del lancio, `merkle_root` zero, `bits` `0x1b040000`, `nonce` 0. È una costante del codice, non viene validato e non crea coin. `chain_id = sha256d(header di genesis)`.
- Rete di prova `test`: stesse regole, `bits` del genesis e massimo `0x207fffff`.

## 5. Emissione

- `r = 50 coin`; ogni 131.400 blocchi `r = r − (r >> 4)`; mai sotto 1 coin.
- Avvio lento: per `h < 43.200`, sussidio = `r × h / 43.200` (divisione intera).
- Coda di 1 coin per blocco dal 61° trimestre. Circa 102 milioni di coin all'inizio della coda. Nessun premine.

## 6. Stato e snapshot

- Voce UTXO (78 byte): `txid (32) ‖ indice (1) ‖ importo (8) ‖ indirizzo (32) ‖ altezza (4) ‖ coinbase (1)`.
- Nei blocchi con altezza multipla di 1.440, `utxo_root` è la radice Merkle delle foglie `H(UTXO, voce)` dell'insieme dopo il blocco precedente, ordinate per `(txid, indice)` in byte.
- Snapshot scaricato a pezzi di 4.096 voci consecutive, ciascuno con la sua prova Merkle verso `utxo_root`.
- Pruning: header, UTXO e ultimi 2.880 blocchi completi; sotto si possono scartare le firme.

## 7. Wallet (fuori consenso)

- Frase di 24 parole con lista e checksum BIP39.
- `seed = PBKDF2-HMAC-SHA256(frase NFKD, "fable" ‖ passphrase NFKD, 2048 giri, 32 byte)`.
- Per `(conto, indice)`: `HMAC-SHA256(seed, "fable/0" ‖ u32 conto ‖ u32 indice)` ‖ i primi 16 byte di `HMAC-SHA256(seed, "fable/1" ‖ u32 conto ‖ u32 indice)`: 48 byte usati come SK.seed, SK.prf e PK.seed della generazione delle chiavi FIPS 205.
- Indirizzo: Bech32m con prefisso `fb`, 61 caratteri.

## 8. Politica del nodo (fuori consenso, default modificabili)

- Fee minima di inoltro 0,001 coin per firma; output minimo inoltrato 0,001 coin.
- Mempool: tetto di 5.000 firme, ordine per fee per firma, sostituzione con fee più alta, al massimo 64 transazioni non confermate collegate tra loro.
- Header accettati solo se la catena supera una soglia di lavoro; limiti di dimensione dei messaggi; peer in uscita da reti /16 diverse.

## 9. Rete e mining

- P2P su TCP, frame `lunghezza (4) ‖ tipo (1) ‖ contenuto`. Messaggi: `hello`, `peers`, `inv`, `get`, `tx`, `block`, `headers`, `snap`. Seed statici nel binario. Nessuna cifratura.
- Stratum v1: `coinb1` = `height`, `extranonce1` + `extranonce2` = 4 + 4 byte = `extra`, `coinb2` = `utxo_root` ‖ output. Version rolling con maschera `0x1fffe000`.

## 10. Limiti noti

- Nessuna difesa di protocollo contro il 51%.
- Circa 1,3 transazioni al secondo con transazioni tipiche da 8 KB; fino a 20 pagamenti al secondo se raggruppati, 15 destinatari per firma.
- L'insieme UTXO può crescere fino a 1.280 output al minuto.
- La storia prima di uno snapshot è garantita dal solo PoW.
- Le regole sono congelate: un bug di consenso si corregge solo con un hard fork concordato.
