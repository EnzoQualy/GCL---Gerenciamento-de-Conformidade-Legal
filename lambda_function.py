import os
import json
import time
import hashlib
import logging
import urllib3
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple

import boto3
import requests
from botocore.exceptions import ClientError
from requests.exceptions import RequestException, Timeout, SSLError
from bs4 import BeautifulSoup
from PyPDF2 import PdfReader

VERSION = "2025-08-27-R1"

# ==============================
# CONFIG
# ==============================
REGION = os.getenv("AWS_REGION", "us-east-2")
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
TABLE_NAME = os.getenv("TABELA", "Monitoramento_Conformidade_Legal")
MAX_WORKERS = int(os.getenv("MAX_WORKERS", "8"))
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "25"))
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
ENABLE_HEAD_CHECK = os.getenv("ENABLE_HEAD_CHECK", "false").lower() == "true"
VERBOSE = os.getenv("VERBOSE", "false").lower() == "true"
DISABLE_SSL_VERIFY = os.getenv("DISABLE_SSL_VERIFY", "false").lower() == "true"
MAX_CONTENT_BYTES = int(os.getenv("MAX_CONTENT_BYTES", str(5 * 1024 * 1024)))
USER_AGENT = os.getenv("USER_AGENT", "LegalMonitorBot/1.1")

_raw_arn = os.getenv("SNS_TOPIC_ARN")
SNS_TOPIC_ARN = _raw_arn if (_raw_arn and _raw_arn.strip()) else "arn:aws:sns:us-east-2:637423340060:MonitoramentoLegal"

MIN_NOTIFY_DELTA = int(os.getenv("MIN_NOTIFY_DELTA", "50"))   # ainda usado p/ destacar mudanças grandes
NOTIFY_ERRORS = os.getenv("NOTIFY_ERRORS", "false").lower() == "true"  # se True lista erros em detalhe
INCLUDE_OK_CHANGES = True  # sempre listar mudanças (mesmo que pequenas)
MAX_LIST_CHANGES = int(os.getenv("MAX_LIST_CHANGES", "30"))
MAX_LIST_ERRORS = int(os.getenv("MAX_LIST_ERRORS", "30"))

# Sempre enviar notificação, conforme exigido
ALWAYS_NOTIFY = True

logger = logging.getLogger()
logger.setLevel(LOG_LEVEL)
if not logger.handlers:
    logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s | %(levelname)s | %(message)s")
if DISABLE_SSL_VERIFY:
    logger.warning("SSL certificate verification DISABLED (DISABLE_SSL_VERIFY=true) - use only for debugging!")

dynamodb = boto3.client("dynamodb", region_name=REGION)

sns_client = None
if SNS_TOPIC_ARN:
    try:
        sns_client = boto3.client("sns", region_name=REGION)
    except Exception as e:
        logger.error(f"Falha ao criar cliente SNS: {e}")
else:
    logger.info("SNS_TOPIC_ARN não definido (ou vazio) – notificações SNS desativadas.")

DEFAULT_HEADERS = {"User-Agent": USER_AGENT}

# ==============================
# UTIL
# ==============================
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

def normalize_text(txt: str) -> str:
    return " ".join(txt.split())

def attr_str(item, key):
    return item.get(key, {}).get("S")

def attr_num(item, key):
    v = item.get(key, {}).get("N")
    return int(v) if v is not None else None

def is_probably_pdf_url(url: str) -> bool:
    return url.lower().split("?")[0].endswith(".pdf")

def fetch_head(url: str) -> Tuple[Optional[str], Optional[str]]:
    try:
        r = requests.head(
            url,
            timeout=REQUEST_TIMEOUT,
            headers=DEFAULT_HEADERS,
            allow_redirects=True,
            verify=not DISABLE_SSL_VERIFY
        )
        if r.status_code == 200:
            return r.headers.get("ETag"), r.headers.get("Last-Modified")
    except Exception:
        pass
    return None, None

def fetch_content(url: str) -> Tuple[Optional[bytes], Dict[str, str], str]:
    raw_url = url
    url = url.strip().replace(" ", "%20")
    if not (url.lower().startswith("http://") or url.lower().startswith("https://")):
        return None, {}, "invalid_url"
    adaptive_timeout = REQUEST_TIMEOUT * (2 if "sistemas.vitoria.es.gov.br" in url else 1)
    max_retries = 3
    backoff_base = 0.8
    last_exc: Optional[Exception] = None
    verify = not DISABLE_SSL_VERIFY
    for attempt in range(1, max_retries + 1):
        try:
            r = requests.get(url, timeout=adaptive_timeout, headers=DEFAULT_HEADERS, stream=True, verify=verify)
            r.raise_for_status()
            content = b''
            max_bytes = MAX_CONTENT_BYTES
            for chunk in r.iter_content(chunk_size=65536):
                if chunk:
                    content += chunk
                    if len(content) > max_bytes:
                        if VERBOSE:
                            logger.warning(f"{url} excedeu limite {max_bytes} bytes")
                        return None, r.headers, "too_large"
            if url != raw_url and VERBOSE:
                logger.info(f"URL normalizada: '{raw_url}' -> '{url}'")
            return content, r.headers, "ok"
        except SSLError as e:
            last_exc = e
            if verify and not DISABLE_SSL_VERIFY:
                verify = False
                continue
        except (Timeout, RequestException) as e:
            last_exc = e
            if attempt == max_retries:
                break
            sleep_time = backoff_base * (2 ** (attempt - 1))
            if VERBOSE:
                logger.warning(f"retry {attempt}/{max_retries} {url}: {e} em {sleep_time:.1f}s")
            time.sleep(sleep_time)
        except Exception as e:
            last_exc = e
            break
    if last_exc and VERBOSE:
        logger.warning(f"Falha ao obter {url}: {last_exc}")
    return None, {}, "fetch_error"

def extract_text_html(raw: bytes) -> str:
    soup = BeautifulSoup(raw, "html.parser")
    for tag in soup(["script", "style", "noscript"]):
        tag.extract()
    txt = soup.get_text(separator=" ", strip=True)
    return normalize_text(txt)

def extract_text_pdf(raw: bytes) -> str:
    import tempfile, os
    fd, path = tempfile.mkstemp(suffix=".pdf")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(raw)
        with open(path, "rb") as f:
            reader = PdfReader(f)
            parts = []
            for page in reader.pages:
                try:
                    parts.append(page.extract_text() or "")
                except Exception:
                    continue
        return normalize_text(" ".join(parts))
    finally:
        try:
            os.remove(path)
        except OSError:
            pass

def classify_and_extract(url: str, force_pdf_hint: bool):
    raw, headers, status = fetch_content(url)
    if raw is None:
        return "", headers.get("Content-Type", ""), status if status != "ok" else "fetch_error"
    content_type = (headers.get("Content-Type") or "").lower()
    is_pdf = "application/pdf" in content_type or (force_pdf_hint and "text/html" not in content_type)
    if is_pdf:
        try:
            text = extract_text_pdf(raw)
            return text, content_type or "application/pdf", status
        except Exception as e:
            logger.error(f"Erro extraindo PDF {url}: {e}")
            return "", content_type, "parse_error"
    else:
        try:
            text = extract_text_html(raw)
            return text, content_type or "text/html", status
        except Exception as e:
            logger.error(f"Erro extraindo HTML {url}: {e}")
            return "", content_type, "parse_error"

def scan_all_items() -> list:
    res = []
    start_key = None
    while True:
        params = {"TableName": TABLE_NAME}
        if start_key:
            params["ExclusiveStartKey"] = start_key
        resp = dynamodb.scan(**params)
        res.extend(resp.get("Items", []))
        start_key = resp.get("LastEvaluatedKey")
        if not start_key:
            break
    return res

def update_item_monitoramento(
    codigo: str,
    last_hash: str,
    char_count: int,
    changed: bool,
    delta: int,
    direction: str,
    process_status: str,
    content_type: str,
    last_change_at: Optional[str],
    store_change_time: bool,
    etag: Optional[str] = None,
    last_modified: Optional[str] = None
):
    names = {
        "#LH": "LastHash",
        "#LC": "LastCharCount",
        "#LCA": "LastCheckedAt",
        "#CHG": "Changed",
        "#DC": "DeltaChars",
        "#DIR": "ChangeDirection",
        "#PSTS": "ProcessStatus",
        "#CT": "ContentType"
    }
    values = {
        ":lh": {"S": last_hash},
        ":lc": {"N": str(char_count)},
        ":lca": {"S": now_iso()},
        ":chg": {"BOOL": changed},
        ":dc": {"N": str(delta)},
        ":dir": {"S": direction},
        ":psts": {"S": process_status},
        ":ct": {"S": content_type or "unknown"}
    }
    set_expr = [
        "#LH = :lh",
        "#LC = :lc",
        "#LCA = :lca",
        "#CHG = :chg",
        "#DC = :dc",
        "#DIR = :dir",
        "#PSTS = :psts",
        "#CT = :ct"
    ]
    if etag is not None:
        names["#ETG"] = "ETag"
        values[":etag"] = {"S": etag}
        set_expr.append("#ETG = :etag")
    if last_modified is not None:
        names["#LM"] = "LastModified"
        values[":lm"] = {"S": last_modified}
        set_expr.append("#LM = :lm")

    if changed:
        names["#VER"] = "Version"
        set_expr.append("#VER = if_not_exists(#VER, :one) + :one")
        values[":one"] = {"N": "1"}
        names["#LCH"] = "LastChangeAt"
        values[":lch"] = {"S": last_change_at or now_iso()}
        set_expr.append("#LCH = :lch")
    elif store_change_time and last_change_at:
        names["#LCH"] = "LastChangeAt"
        values[":lch"] = {"S": last_change_at}
        set_expr.append("#LCH = :lch")
    if not any(":one" in expr for expr in set_expr):
        values.pop(":one", None)

    update_expression = "SET " + ", ".join(set_expr)
    try:
        dynamodb.update_item(
            TableName=TABLE_NAME,
            Key={"Codigo": {"S": codigo}},
            UpdateExpression=update_expression,
            ExpressionAttributeNames=names,
            ExpressionAttributeValues=values
        )
    except ClientError as e:
        logger.error(f"Erro DynamoDB update {codigo}: {e}")

def process_item(item: dict) -> dict:
    codigo = attr_str(item, "Codigo") or "SEM_CODIGO"
    nome = attr_str(item, "Nome") or codigo
    fonte = attr_str(item, "Fonte")
    situacao_legal = attr_str(item, "Status")

    prev_hash = attr_str(item, "LastHash") or ""
    prev_count = attr_num(item, "LastCharCount")
    last_change_at = attr_str(item, "LastChangeAt")
    prev_etag = attr_str(item, "ETag")
    prev_last_modified = attr_str(item, "LastModified")

    if not fonte:
        update_item_monitoramento(
            codigo=codigo,
            last_hash=prev_hash,
            char_count=prev_count or 0,
            changed=False,
            delta=0,
            direction="same",
            process_status="missing_source",
            content_type="unknown",
            last_change_at=last_change_at,
            store_change_time=True
        )
        return {
            "codigo": codigo,
            "nome": nome,
            "fonte": fonte,
            "process_status": "missing_source",
            "changed": False,
            "char_count": prev_count,
            "delta": 0
        }

    force_pdf_hint = is_probably_pdf_url(fonte)
    t0 = time.time()
    try:
        current_etag = None
        current_last_modified = None
        if ENABLE_HEAD_CHECK and prev_hash and prev_count is not None:
            try:
                he, lm = fetch_head(fonte)
                current_etag, current_last_modified = he, lm
                if (he and he == prev_etag) or (lm and lm == prev_last_modified):
                    update_item_monitoramento(
                        codigo=codigo,
                        last_hash=prev_hash,
                        char_count=prev_count,
                        changed=False,
                        delta=0,
                        direction="same",
                        process_status="not_modified",
                        content_type=attr_str(item, "ContentType") or "unknown",
                        last_change_at=last_change_at,
                        store_change_time=True,
                        etag=he,
                        last_modified=lm
                    )
                    return {
                        "codigo": codigo,
                        "nome": nome,
                        "fonte": fonte,
                        "process_status": "not_modified",
                        "situacao_legal": situacao_legal,
                        "changed": False,
                        "char_count": prev_count,
                        "delta": 0,
                        "direction": "same",
                        "skipped_download": True,
                        "duration_ms": int((time.time() - t0) * 1000)
                    }
            except Exception as e:
                if VERBOSE:
                    logger.warning(f"[{codigo}] HEAD falhou: {e}")

        text, content_type, status = classify_and_extract(fonte, force_pdf_hint)
        if status != "ok":
            update_item_monitoramento(
                codigo=codigo,
                last_hash=prev_hash,
                char_count=prev_count or 0,
                changed=False,
                delta=0,
                direction="same",
                process_status=status,
                content_type=content_type,
                last_change_at=last_change_at,
                store_change_time=True,
                etag=current_etag,
                last_modified=current_last_modified
            )
            return {
                "codigo": codigo,
                "nome": nome,
                "fonte": fonte,
                "process_status": status,
                "changed": False,
                "char_count": prev_count,
                "delta": 0,
                "duration_ms": int((time.time() - t0) * 1000)
            }

        char_count = len(text)
        new_hash = sha256(text)
        changed = (new_hash != prev_hash) if prev_hash else True
        delta = (char_count - prev_count) if prev_count is not None else char_count
        if not changed:
            direction = "same"
        else:
            direction = "up" if delta > 0 else ("down" if delta < 0 else "same")

        update_item_monitoramento(
            codigo=codigo,
            last_hash=new_hash,
            char_count=char_count,
            changed=changed,
            delta=delta,
            direction=direction,
            process_status="ok",
            content_type=content_type,
            last_change_at=now_iso() if changed else last_change_at,
            store_change_time=not changed,
            etag=current_etag,
            last_modified=current_last_modified
        )
        return {
            "codigo": codigo,
            "nome": nome,
            "fonte": fonte,
            "process_status": "ok",
            "situacao_legal": situacao_legal,
            "changed": changed,
            "char_count": char_count,
            "delta": delta,
            "direction": direction,
            "duration_ms": int((time.time() - t0) * 1000)
        }

    except Timeout:
        err_status = "timeout"
    except RequestException as e:
        logger.warning(f"Request error {fonte}: {e}")
        err_status = "fetch_error"
    except Exception as e:
        logger.exception(f"Erro inesperado {fonte}: {e}")
        err_status = "unexpected_error"

    update_item_monitoramento(
        codigo=codigo,
        last_hash=prev_hash,
        char_count=prev_count or 0,
        changed=False,
        delta=0,
        direction="same",
        process_status=err_status,
        content_type="unknown",
        last_change_at=last_change_at,
        store_change_time=True,
        etag=None,
        last_modified=None
    )
    return {
        "codigo": codigo,
        "nome": nome,
        "fonte": fonte,
        "process_status": err_status,
        "changed": False,
        "char_count": prev_count,
        "delta": 0,
        "direction": "same",
        "duration_ms": int((time.time() - t0) * 1000)
    }

def main_run(paralelo=True):
    import concurrent.futures
    inicio = time.time()
    items = scan_all_items()
    logger.info(f"Itens lidos: {len(items)}")
    resultados = []
    if paralelo and len(items) > 1:
        from concurrent.futures import ThreadPoolExecutor, as_completed
        real_workers = min(len(items), MAX_WORKERS)
        with ThreadPoolExecutor(max_workers=real_workers) as pool:
            futures = [pool.submit(process_item, it) for it in items]
            for f in as_completed(futures):
                resultados.append(f.result())
    else:
        for it in items:
            resultados.append(process_item(it))
    alterados = sum(1 for r in resultados if r["changed"])
    erros = sum(1 for r in resultados if r["process_status"] not in ("ok", "not_modified"))
    error_counts = {}
    for r in resultados:
        st = r.get("process_status")
        if st and st not in ("ok", "not_modified"):
            error_counts[st] = error_counts.get(st, 0) + 1
    resumo = {
        "total": len(resultados),
        "alterados": alterados,
        "erros": erros,
        "duracao_s": round(time.time() - inicio, 3),
        "error_counts": error_counts,
        "itens": resultados
    }
    logger.info(f"Resumo execução: total={resumo['total']} alterados={resumo['alterados']} erros={resumo['erros']} duração_s={resumo['duracao_s']}")
    return resumo

# ==============================
# NOTIFICAÇÕES (sempre envia)
# ==============================
# ...existing code...
def build_notifications(resultados: list) -> Dict[str, str]:
    """
    Gera subject e body organizados:
    Seções:
      - Cabeçalho / resumo
      - Estatísticas por status
      - Mudanças críticas (Δ >= MIN_NOTIFY_DELTA)
      - Todas as mudanças (limitadas)
      - Erros (limitados, se NOTIFY_ERRORS)
    """
    ts = now_iso()
    total = len(resultados)
    alterados = sum(1 for r in resultados if r.get("changed"))
    erros = [r for r in resultados if r.get("process_status") not in ("ok", "not_modified")]
    erros_count = len(erros)

    # Indexar por status
    status_counts: Dict[str, int] = {}
    for r in resultados:
        st = r.get("process_status") or "desconhecido"
        status_counts[st] = status_counts.get(st, 0) + 1

    changed_ok = [r for r in resultados if r.get("changed") and r.get("process_status") == "ok"]
    changed_ok_sorted = sorted(changed_ok, key=lambda x: abs(x.get("delta") or 0), reverse=True)
    critical = [c for c in changed_ok_sorted if abs(c.get("delta") or 0) >= MIN_NOTIFY_DELTA]

    # Subject
    if alterados > 0:
        subject = f"Monitoramento Legal: {alterados} mudanças (erros={erros_count})"
    else:
        subject = f"Monitoramento Legal: 0 mudanças (erros={erros_count})"

    line = lambda s="": s  # atalho
    body_lines: List[str] = []

    # Cabeçalho
    body_lines += [
        "MONITORAMENTO DE CONFORMIDADE LEGAL",
        f"Data/Horário UTC: {ts}",
        "-" * 68,
        f"Resumo Geral:",
        f"  Total itens analisados : {total}",
        f"  Itens alterados        : {alterados}",
        f"  Itens com erro         : {erros_count}",
        f"  Mudanças críticas (Δ≥{MIN_NOTIFY_DELTA}) : {len(critical)}",
        "-" * 68
    ]

    # Estatísticas por status
    body_lines.append("Status (distribuição):")
    for st, cnt in sorted(status_counts.items(), key=lambda kv: (-kv[1], kv[0])):
        body_lines.append(f"  - {st}: {cnt}")
    body_lines.append("-" * 68)

    # Mudanças críticas
    if critical:
        body_lines.append("Mudanças CRÍTICAS (Δ ≥ limite):")
        body_lines.append("  Codigo | Δ | Dir | Chars | URL")
        for r in critical[:MAX_LIST_CHANGES]:
            codigo = r.get("codigo")
            delta = r.get("delta")
            direction = r.get("direction")
            char_count = r.get("char_count")
            fonte = (r.get("fonte") or "")[:140]
            body_lines.append(f"  {codigo} | {delta} | {direction} | {char_count} | {fonte}")
        if len(critical) > MAX_LIST_CHANGES:
            body_lines.append(f"  ... (+{len(critical) - MAX_LIST_CHANGES} não listados)")
        body_lines.append("-" * 68)
    else:
        body_lines.append("Nenhuma mudança crítica.")
        body_lines.append("-" * 68)

    # Todas as mudanças (se habilitado)
    if INCLUDE_OK_CHANGES and changed_ok_sorted:
        body_lines.append("Todas as mudanças (ordenadas por |Δ|):")
        body_lines.append("  Codigo | Δ | Dir | Chars | URL")
        for r in changed_ok_sorted[:MAX_LIST_CHANGES]:
            codigo = r.get("codigo")
            delta = r.get("delta")
            direction = r.get("direction")
            char_count = r.get("char_count")
            fonte = (r.get("fonte") or "")[:140]
            body_lines.append(f"  {codigo} | {delta} | {direction} | {char_count} | {fonte}")
        if len(changed_ok_sorted) > MAX_LIST_CHANGES:
            body_lines.append(f"  ... (+{len(changed_ok_sorted) - MAX_LIST_CHANGES} não listados)")
        body_lines.append("-" * 68)
    elif not changed_ok_sorted:
        body_lines.append("Sem mudanças em conteúdo (ok).")
        body_lines.append("-" * 68)

    # Erros
    if NOTIFY_ERRORS and erros:
        body_lines.append("Erros:")
        body_lines.append("  Codigo | Status | Detalhe | URL")
        for r in erros[:MAX_LIST_ERRORS]:
            codigo = r.get("codigo")
            st = r.get("process_status")
            det = (r.get("error_detail") or "-")[:120]
            fonte = (r.get("fonte") or "")[:140]
            body_lines.append(f"  {codigo} | {st} | {det} | {fonte}")
        if len(erros) > MAX_LIST_ERRORS:
            body_lines.append(f"  ... (+{len(erros) - MAX_LIST_ERRORS} não listados)")
        body_lines.append("-" * 68)
    elif NOTIFY_ERRORS:
        body_lines.append("Erros: nenhum.")
        body_lines.append("-" * 68)

    # Rodapé
    body_lines += [
        "Legenda:",
        "  Δ = variação de caracteres (positiva: aumento, negativa: redução)",
        f"  Limite crítico atual: {MIN_NOTIFY_DELTA}",
        "",
        "Fim."
    ]

    body = "\n".join(body_lines)
    return {"subject": subject, "body": body}
# ...existing code...

def send_notifications(resultados: list) -> Dict[str, int]:
    notif_counts = {"sns": 0}
    if not SNS_TOPIC_ARN or not sns_client:
        logger.warning("SNS não configurado corretamente. Não será possível enviar o e-mail.")
        return notif_counts

    data = build_notifications(resultados)
    subject = data["subject"]
    body = data["body"]

    try:
        logger.info(f"Publicando SNS: subject='{subject}' tamanho_body={len(body)} chars")
        resp = sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=subject[:100],  # limite do SNS Subject ~100 chars
            Message=body
        )
        logger.info(f"SNS publicado: MessageId={resp.get('MessageId')}")
        notif_counts["sns"] = 1
    except ClientError as ce:
        logger.error(f"Falha ao publicar SNS (ClientError): {ce}")
    except Exception as e:
        logger.error(f"Falha ao publicar SNS (geral): {e}")

    return notif_counts

# ==============================
# HANDLER
# ==============================
def debug_env():
    logger.info(json.dumps({
        "metric": "debug_env",
        "version": VERSION,
        "SNS_TOPIC_ARN": SNS_TOPIC_ARN,
        "HAS_SNS_CLIENT": bool(sns_client),
        "REGION": REGION,
        "MIN_NOTIFY_DELTA": MIN_NOTIFY_DELTA,
        "NOTIFY_ERRORS": NOTIFY_ERRORS
    }, ensure_ascii=False))

def lambda_handler(event, context):
    req_id = getattr(context, 'aws_request_id', None) if context else None
    debug_env()
    logger.info(json.dumps({
        "metric": "startup",
        "request_id": req_id,
        "table": TABLE_NAME,
        "region": REGION,
        "workers": MAX_WORKERS,
        "timeout": REQUEST_TIMEOUT,
        "head_check": ENABLE_HEAD_CHECK,
        "ssl_disabled": DISABLE_SSL_VERIFY,
        "max_content_bytes": MAX_CONTENT_BYTES,
        "version": VERSION
    }, ensure_ascii=False))
    rel = main_run(paralelo=True)
    notif = send_notifications(rel.get("itens", []))
    logger.info(json.dumps({
        "metric": "resumo",
        "request_id": req_id,
        "total": rel["total"],
        "alterados": rel["alterados"],
        "erros": rel["erros"],
        "duracao_s": rel["duracao_s"],
        "notificacoes_sns": notif.get("sns"),
        "version": VERSION
    }, ensure_ascii=False))
    return {"statusCode": 200, "body": json.dumps(rel, ensure_ascii=False)}

def novo_handler(event, context):
    return lambda_handler(event, context)

if __name__ == "__main__":
    r = main_run(paralelo=False)
    n = send_notifications(r.get("itens", []))
    print("Resumo local:", json.dumps(r, ensure_ascii=False, indent=2))
    print("Notificações:", n)