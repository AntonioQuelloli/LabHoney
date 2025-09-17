# handlers.py
# Moduli di handler per i vari "servizi" dell'honeypot.
# Ogni handler è una coroutine che riceve (reader, writer, ctx) come asyncio streams.

import asyncio
from datetime import datetime
import json
import binascii

async def log_interaction(ctx, role, data_bytes):
    # ctx contiene: logger (callable or object), peer, port, service
    ts = datetime.utcnow().isoformat()
    record = {
        "ts": ts,
        "role": role,            # "client" o "server"
        "peer": ctx.get("peer"),
        "peer_port": ctx.get("peer_port"),
        "service": ctx.get("service"),
        "raw_hex": binascii.hexlify(data_bytes).decode(),
        "raw_text": None
    }
    # prova a decodificare in utf-8 (non obbligatorio)
    try:
        record["raw_text"] = data_bytes.decode("utf-8", errors="replace")
    except Exception:
        pass
    # scrivi con il logger (funzione o oggetto)
    logger = ctx.get("logger")
    if callable(logger):
        logger(record)
    else:
        # fallback: append su file jsonl
        with open("logs/interactions.jsonl", "a") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

# HTTP handler: semplice server che risponde con pagina statica
HTTP_RESPONSE = b"""HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: {length}

{body}
"""

async def http_handler(reader, writer, ctx):
    peer = writer.get_extra_info("peername")
    ctx["peer"], ctx["peer_port"] = peer[0], peer[1] if peer else (None, None)
    ctx["service"] = "http"
    # ricevi prima porzione (non reassembly)
    try:
        data = await asyncio.wait_for(reader.read(4096), timeout=3.0)
    except asyncio.TimeoutError:
        data = b""
    if data:
        await log_interaction(ctx, "client", data)
    body = "<html><body><h1>Welcome</h1><p>This is a honeypot HTTP page.</p></body></html>"
    resp = HTTP_RESPONSE.format(length=len(body), body=body).encode()
    await log_interaction(ctx, "server", resp)
    writer.write(resp)
    try:
        await writer.drain()
    except:
        pass
    writer.close()
    try:
        await writer.wait_closed()
    except:
        pass

# Banner handler: simula servizi come SSH/Telnet inviando un banner e registrando input
async def banner_handler(reader, writer, ctx, banner=b"SSH-2.0-OpenSSH_7.4\r\n"):
    peer = writer.get_extra_info("peername")
    ctx["peer"], ctx["peer_port"] = peer[0], peer[1] if peer else (None, None)
    ctx["service"] = "banner"
    # invia banner
    try:
        writer.write(banner)
        await writer.drain()
        await log_interaction(ctx, "server", banner)
    except:
        pass
    # legge i primi N byte (timeout)
    try:
        data = await asyncio.wait_for(reader.read(2048), timeout=10.0)
    except asyncio.TimeoutError:
        data = b""
    if data:
        await log_interaction(ctx, "client", data)
    # optionally respond with nothing and close connection
    writer.close()
    try:
        await writer.wait_closed()
    except:
        pass

# Generic TCP handler: echo-like but with logging (non echoing by default)
async def generic_tcp_handler(reader, writer, ctx, echo=False):
    peer = writer.get_extra_info("peername")
    ctx["peer"], ctx["peer_port"] = peer[0], peer[1] if peer else (None, None)
    ctx["service"] = ctx.get("service", "tcp")
    try:
        while True:
            data = await reader.read(4096)
            if not data:
                break
            await log_interaction(ctx, "client", data)
            if echo:
                writer.write(data)
                await writer.drain()
    except Exception:
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except:
            pass
