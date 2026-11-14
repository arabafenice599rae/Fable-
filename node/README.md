# Nodo di riferimento in Rust

Nodo completo per Fable, specifica v0.11. Il consenso (`src/consensus.rs`) è un port riga per riga di `fable.py`: stessi controlli, nello stesso ordine, con gli stessi codici d'errore.
La firma usa una terza libreria SLH-DSA, `slh-dsa` di RustCrypto (versione fissata a `=0.2.0-rc.5`), diversa da quelle di Python e di JavaScript.

```
cd node
cargo build --release
cargo test --release
```

## Verifiche

| Comando | Cosa controlla |
| --- | --- |
| `cargo test --release` | Tutti i vettori di `../vectors.json`, la stessa catena fatta passare dall'albero dei blocchi, reorg, mempool, file dei blocchi, prove dei pezzi di snapshot, codifica dei messaggi |
| `./target/release/fable vectors ../vectors.json` | I vettori, con lo stesso resoconto di `check_vectors.mjs` |
| `python3 crosscheck.py 1 && node/target/release/fable crosscheck` | Il differenziale di `crosscheck.py` (dalla radice del repository) |
| `python3 node/tests/e2e.py` | Tre nodi su socket veri, Bitaxe simulato, pagamento, reorg, riavvio, replay su `fable.py` e `fable.mjs` |
| `python3 node/tests/e2e_snapshot.py` | Avvio da snapshot UTXO tra nodi |
| `cargo run --release --example bench` | Velocità di verifica delle firme |

Stato attuale: 1.732 controlli sui vettori e 37.660 casi del differenziale per seme (semi 1, 2 e 3), tutti uguali al riferimento.
Una firma si verifica in circa 0,15 ms; le firme di un blocco si verificano in parallelo, un blocco pieno da 80 firme in circa 4 ms su 4 core.

## Uso

```
fable node --net test -v                                  # rete di prova, dati in ~/.fable/test
fable node --net test --connect 10.0.0.2:17171            # con un peer fisso
fable node --net lab --stratum 0.0.0.0:3333 --payout fb1...   # per un Bitaxe vero, come stratum.py
fable node --net test --snapshot-sync --connect ...       # parte dall'ultimo snapshot UTXO
fable rpc getinfo
fable rpc generate 10 fb1...                              # mining su CPU, per la rete di prova
fable wallet new
fable wallet address --words "<24 parole>" --count 3
fable wallet balance --words "<24 parole>"
fable wallet send --words "<24 parole>" --to fb1... --amount 1.5
```

Porte predefinite: P2P 17171 e controllo 17172 (7171 e 7172 per `main`). La frase si può passare anche in `FABLE_WORDS`.
L'interfaccia di controllo è JSON su righe, senza autenticazione: resta su `127.0.0.1`.
Metodi: `getinfo`, `getpeers`, `getblockhash`, `getblock`, `submitblock`, `sendtx`, `getmempool`, `getutxos`, `gettemplate`, `generate`, `addpeer`, `getsnapshot`, `stop`.

## Com'è fatto

| File | Cosa fa |
| --- | --- |
| `src/consensus.rs` | Regole di consenso, port di `fable.py`; prove Merkle dei pezzi di snapshot |
| `src/wallet.rs` | Frase BIP39, derivazione delle chiavi, Bech32m, firma delle transazioni (sezione 7) |
| `src/chainstate.rs` | Indice di header e blocchi, scelta della catena, reorg, file dei blocchi, snapshot |
| `src/mempool.rs` | Politica della sezione 8 e scelta delle transazioni per il blocco |
| `src/miner.rs` | Template di blocco e miner su CPU |
| `src/p2p.rs`, `src/node.rs` | Messaggi P2P e nodo in esecuzione; il formato dei messaggi è in [`PROTOCOL.md`](PROTOCOL.md) |
| `src/snapsync.rs` | Raccolta e verifica dei pezzi di uno snapshot |
| `src/stratum.rs` | Server Stratum v1, port di `stratum.py` |
| `src/rpc.rs`, `src/main.rs` | Interfaccia di controllo e riga di comando |

- **Scelta della catena.** Ogni header che supera i controlli rispetto al genitore (tempo, `bits` ASERT, proof of work) entra nell'indice anche prima del suo blocco.
  Vince la catena con più lavoro tra quelle che si possono collegare; a parità resta quella vista per prima.
  Un blocco che fallisce durante un reorg viene segnato invalido con i discendenti e il nodo torna alla migliore catena valida.
  Un blocco con la radice Merkle sbagliata non rende invalido il suo header, perché il corpo può essere stato alterato per strada.
- **Codici d'errore.** Le firme di un blocco si raccolgono e si verificano insieme alla fine. Un errore trovato più avanti viene riportato solo se tutte le firme che il riferimento avrebbe verificato prima sono valide, così il codice resta quello di `fable.py`.
- **Mempool.** Fee minima 0,001 coin per firma e output minimo 0,001 coin; tetto di 5.000 firme, esce prima chi paga meno per firma; una sostituzione deve pagare più del totale che sostituisce (discendenti compresi) e più per firma di ogni transazione in conflitto; al massimo 64 transazioni non confermate collegate. Dopo un reorg le transazioni dei blocchi scollegati tornano in mempool. Le firme già verificate non si verificano di nuovo.
- **Stratum.** Come `stratum.py`, ma i job includono le transazioni della mempool, quindi il ramo Merkle non è vuoto. Job nuovo a ogni nuova punta e ogni 30 secondi.
- **Snapshot.** Il nodo tiene gli ultimi due insiemi UTXO impegnati da un blocco di snapshot e li serve a pezzi da 4.096 voci con la prova verso `utxo_root`.
  Con `--snapshot-sync` un nodo nuovo scarica gli header, il blocco dello snapshot, i pezzi (ciascuno verificato) e poi solo i blocchi successivi. Non può riorganizzare sotto lo snapshot.
- **Peer.** In uscita al massimo 8, uno per rete /16; i peer dati con `--connect` sono sempre tenuti. I blocchi si chiedono solo ai peer che li hanno annunciati.

## Limiti noti

- L'insieme UTXO sta in memoria. All'avvio il nodo rilegge `blocks.dat` e rivalida tutto, firme comprese: va bene per la rete di prova e per catene giovani, non per anni di mainnet.
- Nessun pruning: il nodo tiene tutti i blocchi che ha ricevuto. La specifica lo permette ma non lo richiede.
- Il formato dei messaggi P2P non è nella specifica: `PROTOCOL.md` è una proposta.
- `MAIN` ha ancora il segnaposto per `prev_hash` del genesis e nessun seed nel binario.
- Difese di rete minime: disconnessione per messaggi o header invalidi, pool di orfani limitato a 256, soglia di lavoro per scaricare blocchi (`--min-chain-work`, 0 di default). Niente punteggi di comportamento.
- Lo snapshot è provato in rete con un solo pezzo (1.439 voci); più pezzi sono provati nei test unitari.
