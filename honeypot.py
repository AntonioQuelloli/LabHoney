#!/usr/bin/env python3
# honeypot.py
# Semplice CLI per creare e avviare un honeypot modulare.
# Uso didattico: emula HTTP, banner (SSH/Telnet) e TCP generico; registra tutte le interazioni.

import argparse
import asyncio
import os
import json
from datetime import datetime
from importlib import import_module
import handlers
import signal

DEFAULT_CONFIG = {
    "listeners": [
        {"port": 80,  "proto": "tcp", "handler": "http"},
        {"port": 2222,"proto": "tcp", "handler": "banner", "banner": "SSH-2.0-OpenSSH_7.4\\r\\n"},
        {"port": 502, "proto": "tcp", "handler": "generic", "echo": False}
    ],
    "log_dir": "logs",
    "jsonl": True
}

SERVERS = []

def ensure_logdir(path):
    if not os.path.exists(path):
        os.makedirs(path, exist_ok=True)

def jsonl_logger_factory(path):
    ensure_logdir(path)
    filename = os.path.join(path, "interactions.jsonl")
    # ensure file exists
    open(filename, "a").close()
    def logger(record):
        with open(filename, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    return logger

async def start_listener(bind_host, listener, logger):
    port = listener.get("port")
    handler_name = listener.get("handler")
    proto = listener.get("proto", "tcp")
    ctx_base = {"logger": logger}
    # select handler
    if handler_name == "http":
        handler = handlers.http_handler
    elif handler_name == "banner":
        # wrapper to pass banner
        async def h(r, w, ctx):
            banner = listener.get("banner", "SSH-2.0-OpenSSH_7.4\r\n").encode().decode('unicode_escape').encode()
            await handlers.banner_handler(r, w, ctx, banner=banner)
        handler = h
    else:
        # generic
        echo = bool(listener.get("echo", False))
        async def h(r, w, ctx):
            ctx["service"] = listener.get("service", f"tcp_{port}")
            await handlers.generic_tcp_handler(r, w, ctx, echo=echo)
        handler = h

    async def client_connected(reader, writer):
        ctx = dict(ctx_base)  # copy
        # set peer info in handler
        peer = writer.get_extra_info("peername")
        if peer:
            ctx["peer"], ctx["peer_port"] = peer[0], peer[1]
        else:
            ctx["peer"], ctx["peer_port"] = None, None
        try:
            await handler(reader, writer, ctx)
        except Exception as e:
            # log handler exception
            record = {
                "ts": datetime.utcnow().isoformat(),
                "event": "handler_exception",
                "port": port,
                "handler": handler_name,
                "error": str(e)
            }
            logger(record)

    # start server
    server = await asyncio.start_server(client_connected, bind_host, port)
    addrs = ", ".join(str(sock.getsockname()) for sock in server.sockets)
    print(f"[+] Listening on {addrs} (handler={handler_name})")
    return server

async def run_from_config(cfg, bind_host="0.0.0.0"):
    logdir = cfg.get("log_dir", "logs")
    ensure_logdir(logdir)
    logger = jsonl_logger_factory(logdir)
    listeners = cfg.get("listeners", [])
    servers = []
    for l in listeners:
        try:
            srv = await start_listener(bind_host, l, logger)
            servers.append(srv)
        except PermissionError:
            print(f"Errore: permessi insufficienti per aprire porta {l.get('port')}. Usa porta >1024 o sudo.")
        except Exception as e:
            print("Errore creazione listener:", e)
    return servers

def load_config(path):
    if not path:
        return DEFAULT_CONFIG
    with open(path, "r", encoding="utf-8") as f:
        if path.endswith(".json"):
            return json.load(f)
        else:
            # try yaml-lite (user may supply json style)
            return json.load(f)

def sigint_handler(loop):
    print("\n[!] Arresto richiesto, chiudo server...")
    for s in SERVERS:
        s.close()
    # stop loop later

def main():
    parser = argparse.ArgumentParser(description="Honeypot-lite: crea un honeypot in pochi comandi (uso didattico)")
    parser.add_argument("-c", "--config", help="File di configurazione JSON (opzionale)")
    parser.add_argument("-b", "--bind", default="0.0.0.0", help="Indirizzo su cui bindare (default 0.0.0.0)")
    parser.add_argument("--list", action="store_true", help="Stampa configurazione di default e esce")
    parser.add_argument("--gen-config", help="Genera un template config JSON nel path indicato e esci")
    args = parser.parse_args()

    if args.list:
        print(json.dumps(DEFAULT_CONFIG, indent=2))
        return

    if args.gen_config:
        with open(args.gen_config, "w", encoding="utf-8") as f:
            json.dump(DEFAULT_CONFIG, f, indent=2)
        print(f"Template di configurazione creato in {args.gen_config}")
        return

    cfg = DEFAULT_CONFIG if not args.config else load_config(args.config)
    loop = asyncio.get_event_loop()
    # opzione per uvloop se installato
    try:
        import uvloop
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
    except Exception:
        pass

    try:
        servers = loop.run_until_complete(run_from_config(cfg, bind_host=args.bind))
        global SERVERS
        SERVERS = servers
        # keep running until Ctrl+C
        print("[*] Honeypot avviato. Premi Ctrl+C per terminare.")
        for s in servers:
            # keep servers referenced
            pass
        # wait forever
        loop.run_forever()
    except KeyboardInterrupt:
        print("\n[!] Interruzione ricevuta.")
    finally:
        for s in SERVERS:
            s.close()
        loop.stop()
        loop.run_until_complete(loop.shutdown_asyncgens())
        loop.close()
        print("[*] Honeypot arrestato.")

if __name__ == "__main__":
    main()
