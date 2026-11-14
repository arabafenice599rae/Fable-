# Fable

Chain proof-of-work su SHA-256 con firme SLH-DSA. La specifica è in [`SPEC.md`](SPEC.md) (v0.12).

Questo repository contiene le regole di consenso in due implementazioni, i vettori di test e un server Stratum. Il nodo completo in Rust non c'è ancora.

| File | Cosa fa |
| --- | --- |
| `fable.py` | Implementazione di riferimento delle regole di consenso |
| `fable.mjs` | Seconda implementazione, in JavaScript e su un'altra libreria SLH-DSA |
| `vectors.json` | Vettori di test e una catena simulata di 1.445 blocchi con 29 blocchi invalidi |
| `gen_vectors.py` | Rigenera `vectors.json` dal riferimento |
| `check_vectors.mjs` | Fa girare tutti i vettori sulla seconda implementazione |
| `crosscheck.py` / `.mjs` | Confronto differenziale su casi casuali e blocchi alterati |
| `stratum.py` | Server Stratum v1 per minare con un Bitaxe |
| `bitaxe_sim.py` | Bitaxe simulato, portato dal firmware ESP-Miner |
| `test_stratum.py` | Prova completa miner simulato ↔ server ↔ due implementazioni |
| `cli.mjs` | Chiavi, indirizzi e firme da riga di comando |

## Installazione

```
pip install slh-dsa==0.2.5
npm install
```

## Verifiche

```
python3 gen_vectors.py        # circa 20 secondi
node check_vectors.mjs
python3 crosscheck.py 1       # il numero è il seme casuale
python3 test_stratum.py 40
```

## Prova con un Bitaxe vero

```
node cli.mjs wallet "<le tue 24 parole>" 0 0     # stampa l'indirizzo fb1...
python3 stratum.py --net lab --address fb1...
```

Nel Bitaxe: pool = indirizzo IP di questo computer, porta 3333, utente a piacere.
La rete `lab` ha la difficoltà della mainnet e un genesis usa e getta: con 1,2 TH/s esce circa un blocco al minuto.
I blocchi finiscono in `chain.txt`; per ripartire da zero cancella `chain.txt` e `chain.txt.genesis`.
