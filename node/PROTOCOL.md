# Messaggi P2P del nodo Rust

La specifica (sezione 9) fissa il frame e i nomi degli otto messaggi, non il loro contenuto.
Questo è il formato che usa `node/src/p2p.rs`. È una proposta: se va bene, il testo può entrare nella specifica.

Tutti gli interi sono little-endian, gli hash nell'ordine dei byte di SHA-256, come nel resto della specifica.

## Frame

```
lunghezza (4) ‖ tipo (1) ‖ contenuto
```

`lunghezza` conta i byte del solo contenuto. Contenuto massimo 2 MiB: un blocco arriva a circa 0,65 MB.
Un messaggio che non si decodifica, o con un contenuto avanzato, chiude la connessione.

| Tipo | Nome | Contenuto |
| --- | --- | --- |
| 0 | `hello` | `versione (4) ‖ chain_id (32) ‖ altezza (4) ‖ punta (32) ‖ porta (2) ‖ nonce (8)` |
| 1 | `peers` | `n (2, ≤ 100) ‖ n × (IPv6 (16) ‖ porta (2))`; IPv4 come `::ffff:a.b.c.d`. `n = 0` chiede indirizzi |
| 2 | `inv` | `tipo (1) ‖ n (2, ≤ 1.000) ‖ n × hash (32)`; tipo 1 = transazione (txid), 2 = blocco |
| 3 | `get` | come `inv`; tipo 1 e 2 chiedono quegli oggetti, tipo 3 chiede gli header dopo un locator |
| 4 | `tx` | la transazione serializzata |
| 5 | `block` | il blocco serializzato |
| 6 | `headers` | `n (2, ≤ 2.000) ‖ n × header (80)` |
| 7 | `snap` | sottotipo (1) e campi, sotto |

`versione` è 1. `porta` è quella su cui il nodo ascolta, 0 se non ascolta. `nonce` è casuale per processo e serve a riconoscere una connessione verso se stessi.

## Scambio

1. Chi apre la connessione manda `hello`; l'altro risponde con il suo. Un `chain_id` diverso chiude la connessione, e prima di `hello` non vale nessun altro messaggio.
2. Ciascuno chiede gli header (`get` tipo 3) con un locator: gli hash della propria catena attiva dalla punta all'indietro, i primi 10 uno per uno, poi con passo che raddoppia, e per ultimo il genesis.
   La risposta contiene fino a 2.000 header della catena attiva dopo il primo hash del locator che chi risponde riconosce. Con 2.000 header se ne chiedono altri.
3. Ogni header viene controllato rispetto al genitore (tempo, `bits` ASERT, proof of work) prima di entrare nell'indice. Un header che sbaglia `bits` o il proof of work chiude la connessione.
4. Quando la catena di header migliore ha più lavoro della punta, il nodo chiede i blocchi mancanti (`get` tipo 2), al massimo 16 per peer e solo ai peer che li hanno annunciati. Una richiesta senza risposta in 30 secondi torna disponibile.
5. Un blocco nuovo sulla catena attiva si annuncia con `inv` tipo 2 dell'hash della punta. Chi non lo conosce chiede gli header; poi il blocco.
6. Una transazione accettata in mempool si annuncia con `inv` tipo 1. Dopo `hello` ciascuno annuncia la propria mempool.

## Snapshot (`snap`)

| Sottotipo | Campi |
| --- | --- |
| 0 richiesta | `altezza (4) ‖ pezzo (4)` |
| 1 pezzo | `altezza (4) ‖ pezzo (4) ‖ totale voci (4) ‖ n (2) ‖ n × voce UTXO (78) ‖ m (1) ‖ m × hash (32)` |
| 2 non disponibile | `altezza (4) ‖ pezzo (4)` |

`altezza` è un'altezza multipla di 1.440: lo snapshot è l'insieme che il blocco a quell'altezza impegna nel suo `utxo_root`, cioè quello dopo il blocco precedente.
Il pezzo `k` contiene le voci da `4.096·k` a `4.096·k + 4.095`, nell'ordine `(txid, indice)`.

La prova sfrutta il fatto che 4.096 = 2^12: il pezzo `k` è il nodo all'indice `k` del livello 12 dell'albero di Merkle della sezione 6, e la sua radice è `merkle_root` delle sue foglie `H(UTXO, voce)`.
La prova elenca i fratelli dal livello 12 alla radice, saltando i livelli in cui il nodo è spaiato e sale invariato.
Per verificarla servono solo `k` e il totale delle voci: da questi si sa a ogni livello quanti nodi ci sono e quindi se il fratello esiste.
Le funzioni sono `chunk_proof` e `chunk_root` in `node/src/consensus.rs`.
