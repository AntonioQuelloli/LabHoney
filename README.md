# LabHoney

Progetto didattico per creare in pochi comandi un honeypot locale che emula servizi comuni e registra le interazioni.

## Features
- Emulazione semplice di HTTP (risposta statica), banner (es. SSH), e TCP generico.
- Logging strutturato in JSONL (logs/interactions.jsonl), con raw bytes in hex e testo decodificato se possibile.
- Configurazione tramite file JSON (o uso della configurazione di default).
- Facile da estendere: aggiungi nuovi handler in handlers.py o come moduli esterni.

## Avvertenze Legali ed Etiche
Usare solo su host/reti dove si ha autorizzazione. Non usare per intercettare o disturbare terzi.

## Requisiti
- Python 3.8+
- (opzionale) uvloop per migliori performance
- Installa i requisiti: `pip install -r requirements.txt`

## Esempi
Generare config di esempio:
