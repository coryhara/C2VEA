#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
train_cve_poc_retriever.py
- CVE ⇄ PoC 듀얼인코더 학습
- PoC 인덱스(FAISS) 구축
- 사용자 입력으로 검색

Usage examples:
  # 1) 학습
  python train_cve_poc_retriever.py train --epochs 3 --batch-size 16 --out-dir ./ckpt

  # 2) 인덱스만 재구축
  python train_cve_poc_retriever.py build-index --ckpt-dir ./ckpt

  # 3) 검색 (직접 텍스트)
  python train_cve_poc_retriever.py search --text "CVE: CVE-2024-XXXX\nDescription: ..." --topk 5 --ckpt-dir ./ckpt

  # 3-1) 검색 (파일에서)
  python train_cve_poc_retriever.py search --text-file ./query.txt --topk 5 --ckpt-dir ./ckpt

  # 3-2) 검색 (표준입력)
  echo "CVE: CVE-2024-XXXX..." | python train_cve_poc_retriever.py search --topk 5 --ckpt-dir ./ckpt
"""

import os, io, sys, zipfile, json, random, time, logging, argparse
from typing import List, Tuple, Dict, Optional
from dataclasses import dataclass

import numpy as np
import pymysql
import chardet
try:
    import magic  # optional (file type), not strictly required
except Exception:
    magic = None

from tqdm import tqdm

import torch
import torch.nn as nn
from torch.utils.data import Dataset

from transformers import AutoTokenizer, AutoModel

# =========================
# 0) 상수 & 로깅
# =========================

ALLOWED_CODE_EXT = {
    ".py", ".c", ".cpp", ".cc", ".h", ".hpp", ".java", ".js", ".ts", ".go", ".rb",
    ".php", ".cs", ".rs", ".sh", ".ps1", ".yml", ".yaml", ".toml", ".ini", ".md", ".txt"
}
MAX_BYTES_PER_FILE = 20000      # 파일당 최대 읽기 (20KB)
MAX_FILES_PER_ZIP  = 12         # ZIP에서 추출 파일 최대 개수
MAX_TOTAL_TEXT     = 40000      # ZIP 전체에서 추출 총 바이트 상한
READ_ME_FIRST      = ("readme", "read_me", "README", "Readme")

logger = logging.getLogger("cve-poc-retriever")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s.%(msecs)03d [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)

# =========================
# 1) DB 로딩 & 전처리 유틸
# =========================

@dataclass
class DBConfig:
    host: str
    user: str
    password: str
    database: str
    port: int = 3306
    charset: str = "utf8mb4"

def env_or_default(name: str, default: Optional[str]) -> Optional[str]:
    v = os.getenv(name)
    return v if v not in (None, "") else default

def get_db_conn(cfg: Optional[DBConfig] = None):
    if cfg is None:
        cfg = DBConfig(
            host=env_or_default("DB_HOST", "127.0.0.1"),
            user=env_or_default("DB_USER", "root"),
            password=env_or_default("DB_PASS", ""),
            database=env_or_default("DB_NAME", "cvedb"),
            port=int(env_or_default("DB_PORT", "3306")),
            charset=env_or_default("DB_CHARSET", "utf8mb4"),
        )
    return pymysql.connect(
        host=cfg.host,
        user=cfg.user,
        password=cfg.password,
        database=cfg.database,
        port=cfg.port,
        charset=cfg.charset,
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=True
    )

def load_pairs_from_db(min_year: int = 1999, db_cfg: Optional[DBConfig] = None) -> List[Dict]:
    """
    cve_poc_sources 를 기준으로 양성 쌍을 구성.
    CVE 메타는 cve_vulnerabilities, cve_descriptions, cve_tags, cvss_metrics에서 모아 합칩니다.
    """
    conn = get_db_conn(db_cfg)
    with conn.cursor() as cur:
        # CVE 본문(영문 설명 우선) + 태그/메트릭 집계
        cur.execute("""
        SELECT v.cve_id, v.source_identifier, v.published, v.last_modified, v.vuln_status
        FROM cve_vulnerabilities v
        WHERE YEAR(v.published) >= %s
        """, (min_year,))
        cves = {row["cve_id"]: row for row in cur.fetchall()}

        # descriptions
        cur.execute("""
        SELECT cve_id, description_lang, description_value
        FROM cve_descriptions
        """)
        desc_map = {}
        for r in cur.fetchall():
            d = desc_map.setdefault(r["cve_id"], [])
            d.append(r)

        # tags
        cur.execute("""
        SELECT cve_id, source_identifier, tag
        FROM cve_tags
        """)
        tag_map = {}
        for r in cur.fetchall():
            d = tag_map.setdefault(r["cve_id"], [])
            d.append(r["tag"])

        # cvss
        cur.execute("""
        SELECT cve_id, version, vector_string, base_score, base_severity,
               attack_vector, attack_complexity, privileges_required, user_interaction, scope,
               confidentiality_impact, integrity_impact, availability_impact
        FROM cvss_metrics
        """)
        cvss_map = {}
        for r in cur.fetchall():
            d = cvss_map.setdefault(r["cve_id"], [])
            d.append(r)

        # 양성쌍: cve_poc_sources
        cur.execute("""
        SELECT id, cve_id, source_identifier, url, downloaded_files, commit_sha, created_at
        FROM cve_poc_sources
        """)
        pairs = []
        for r in cur.fetchall():
            cve_id = r["cve_id"]
            if cve_id not in cves:
                continue
            pairs.append({
                "cve_meta": cves[cve_id],
                "cve_desc": desc_map.get(cve_id, []),
                "cve_tags": tag_map.get(cve_id, []),
                "cve_cvss": cvss_map.get(cve_id, []),
                "poc_row": r
            })
    conn.close()
    return pairs

def best_english_text(desc_list: List[Dict]) -> str:
    # 영문 우선, 없으면 가장 긴 설명
    if not desc_list:
        return ""
    en = [d["description_value"] for d in desc_list if (d.get("description_lang") or "").lower().startswith("en")]
    if en:
        return max(en, key=len)
    return max([d["description_value"] for d in desc_list], key=len)

def pack_cve_text(cve_meta, cve_desc, cve_tags, cve_cvss) -> str:
    parts = []
    parts.append(f"CVE: {cve_meta['cve_id']}")
    if cve_meta.get("vuln_status"): parts.append(f"Status: {cve_meta['vuln_status']}")
    # 설명
    desc = best_english_text(cve_desc)
    if desc: parts.append(f"Description: {desc}")
    # 태그
    if cve_tags:
        parts.append("Tags: " + ", ".join(sorted(set(cve_tags))[:30]))
    # CVSS(가장 최신 버전 우선)
    if cve_cvss:
        cvss_sorted = sorted(cve_cvss, key=lambda x: (str(x.get("version")), x.get("base_score") or 0), reverse=True)
        top = cvss_sorted[0]
        vec = top.get("vector_string") or ""
        sev = top.get("base_severity") or ""
        bs  = top.get("base_score") or ""
        parts.append(f"CVSS: v{top.get('version')} {vec} severity={sev} score={bs}")
        axes = ["attack_vector","attack_complexity","privileges_required","user_interaction","scope",
                "confidentiality_impact","integrity_impact","availability_impact"]
        axes_txt = [f"{k}={top.get(k)}" for k in axes if top.get(k)]
        if axes_txt:
            parts.append("Factors: " + ", ".join(axes_txt))
    return "\n".join(parts)

def safe_decode(b: bytes) -> str:
    if not b:
        return ""
    res = chardet.detect(b)
    enc = (res.get("encoding") or "utf-8").strip() or "utf-8"
    try:
        return b.decode(enc, errors="ignore")
    except Exception:
        return b.decode("utf-8", errors="ignore")

def text_from_zip_bytes(zbytes: bytes) -> str:
    """
    README/설명 우선 + 코드 몇 개만 샘플링해서 추출.
    """
    total = []
    with zipfile.ZipFile(io.BytesIO(zbytes)) as zf:
        infos = zf.infolist()
        files = [i for i in infos if not i.is_dir()]
        readmes = sorted(
            [f for f in files if any(os.path.basename(f.filename).lower().startswith(x.lower()) for x in READ_ME_FIRST)],
            key=lambda x: len(x.filename)
        )
        codefiles = [f for f in files if os.path.splitext(f.filename)[1].lower() in ALLOWED_CODE_EXT]

        picked = []
        picked.extend(readmes[:3])
        rest = [f for f in codefiles if f not in picked]
        random.shuffle(rest)
        picked.extend(rest[:MAX_FILES_PER_ZIP])

        consumed = 0
        for f in picked:
            if consumed >= MAX_TOTAL_TEXT:
                break
            with zf.open(f, "r") as fh:
                raw = fh.read(min(MAX_BYTES_PER_FILE, max(0, MAX_TOTAL_TEXT - consumed)))
                txt = safe_decode(raw)
                total.append(f"\n---FILE:{f.filename}---\n")
                total.append(txt)
                consumed += len(raw)
    return "\n".join(total[:])[:MAX_TOTAL_TEXT]

def load_zip_from_db_pointer(downloaded_files_json: str) -> Optional[bytes]:
    """
    downloaded_files JSON에 ZIP 파일의 경로가 저장되었다고 가정.
    예: [{"path": "/data/pocs/CVE-2024-XXXX_abc.zip"}]
    """
    try:
        meta = json.loads(downloaded_files_json or "[]")
        if isinstance(meta, list) and meta:
            path = meta[0].get("path")
            if path and os.path.exists(path):
                with open(path, "rb") as f:
                    return f.read()
        return None
    except Exception:
        return None

# =========================
# 2) 모델: Dual Encoder
# =========================

class EncoderWrapper(nn.Module):
    def __init__(self, model_name: str, out_dim: int = 384):
        super().__init__()
        self.backbone = AutoModel.from_pretrained(model_name)
        hid = self.backbone.config.hidden_size
        self.proj = nn.Linear(hid, out_dim) if hid != out_dim else nn.Identity()
        self.norm = nn.LayerNorm(out_dim)
        self.out_dim = out_dim

    def forward(self, input_ids, attention_mask):
        out = self.backbone(input_ids=input_ids, attention_mask=attention_mask)
        last = out.last_hidden_state  # (B, L, H)
        mask = attention_mask.unsqueeze(-1)  # (B, L, 1)
        mean = (last * mask).sum(1) / mask.sum(1).clamp(min=1e-6)
        z = self.proj(mean)
        z = self.norm(z)
        z = nn.functional.normalize(z, p=2, dim=-1)
        return z

class DualEncoder(nn.Module):
    def __init__(self, cve_model="sentence-transformers/all-MiniLM-L6-v2",
                 poc_model="microsoft/codebert-base",
                 out_dim=384):
        super().__init__()
        self.cve_tok = AutoTokenizer.from_pretrained(cve_model, use_fast=True)
        self.poc_tok = AutoTokenizer.from_pretrained(poc_model, use_fast=True)
        self.cve_enc = EncoderWrapper(cve_model, out_dim=out_dim)
        self.poc_enc = EncoderWrapper(poc_model, out_dim=out_dim)

    @torch.inference_mode()
    def encode_cve(self, texts: List[str], max_len=512, device="cpu"):
        batch = self.cve_tok(texts, padding=True, truncation=True, max_length=max_len, return_tensors="pt")
        batch = {k: v.to(device) for k, v in batch.items()}
        z = self.cve_enc(**batch)
        return z

    @torch.inference_mode()
    def encode_poc(self, texts: List[str], max_len=512, device="cpu"):
        batch = self.poc_tok(texts, padding=True, truncation=True, max_length=max_len, return_tensors="pt")
        batch = {k: v.to(device) for k, v in batch.items()}
        z = self.poc_enc(**batch)
        return z

    def forward(self, cve_inputs, poc_inputs):
        zc = self.cve_enc(**cve_inputs)
        zp = self.poc_enc(**poc_inputs)
        return zc, zp

# =========================
# 3) 데이터셋
# =========================

class PairDataset(Dataset):
    def __init__(self, pairs: List[Dict], max_cve_len=512, max_poc_len=512,
                 cache_zip_text: bool = True):
        self.items = pairs
        self.max_cve_len = max_cve_len
        self.max_poc_len = max_poc_len
        self.cache_zip_text = cache_zip_text
        self._poc_cache = {}

    def __len__(self): return len(self.items)

    def get_cve_text(self, obj):
        return pack_cve_text(obj["cve_meta"], obj["cve_desc"], obj["cve_tags"], obj["cve_cvss"])

    def get_poc_text(self, obj):
        key = obj["poc_row"]["id"]
        if self.cache_zip_text and key in self._poc_cache:
            return self._poc_cache[key]
        zbytes = None
        if obj["poc_row"]["downloaded_files"]:
            zbytes = load_zip_from_db_pointer(obj["poc_row"]["downloaded_files"])
        if not zbytes:
            txt = f"POC Source: {obj['poc_row'].get('source_identifier','')}\nURL: {obj['poc_row'].get('url','')}"
        else:
            txt = text_from_zip_bytes(zbytes)
            if len(txt) < 200:
                txt = (txt + "\n" + f"POC Source: {obj['poc_row'].get('source_identifier','')}\nURL: {obj['poc_row'].get('url','')}")[:MAX_TOTAL_TEXT]
        if self.cache_zip_text:
            self._poc_cache[key] = txt
        return txt

# =========================
# 4) 학습 루프(대조학습)
# =========================

def collate(batch, cve_tok, poc_tok, max_cve_len=512, max_poc_len=512, device="cpu"):
    cve_texts = [b["cve_txt"] for b in batch]
    poc_texts = [b["poc_txt"] for b in batch]
    cve_inputs = cve_tok(cve_texts, padding=True, truncation=True, max_length=max_cve_len, return_tensors="pt")
    poc_inputs = poc_tok(poc_texts, padding=True, truncation=True, max_length=max_poc_len, return_tensors="pt")
    return {k: v.to(device) for k, v in cve_inputs.items()}, {k: v.to(device) for k, v in poc_inputs.items()}

class ContrastiveLoss(nn.Module):
    """
    InfoNCE: 유사도 = cos, 목표는 정답쌍 대각선이 가장 크도록
    """
    def __init__(self, temperature: float = 0.05):
        super().__init__()
        self.t = nn.Parameter(torch.tensor(temperature))

    def forward(self, zc, zp):
        sim = (zc @ zp.t())  # (B,B) 이미 normalize됨
        sim = sim / self.t.clamp(min=1e-4)
        labels = torch.arange(sim.size(0), device=sim.device)
        loss_c2p = nn.functional.cross_entropy(sim, labels)
        loss_p2c = nn.functional.cross_entropy(sim.t(), labels)
        return (loss_c2p + loss_p2c) * 0.5

def set_seed(seed: int = 42):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)

def train_main(args, db_cfg: Optional[DBConfig] = None):
    set_seed(args.seed)
    device = "cuda" if torch.cuda.is_available() else "cpu"
    logger.info(f"Device: {device}")

    # 데이터 로딩
    all_pairs = load_pairs_from_db(min_year=args.min_year, db_cfg=db_cfg)
    if args.limit and args.limit > 0:
        all_pairs = all_pairs[:args.limit]
    random.shuffle(all_pairs)
    n = len(all_pairs)
    if n == 0:
        logger.error("No training pairs found. Check DB and min_year.")
        sys.exit(1)

    n_train = int(n * (1.0 - args.val_ratio))
    train_pairs = all_pairs[:n_train]
    val_pairs   = all_pairs[n_train:]

    dataset_train = PairDataset(train_pairs)
    dataset_val   = PairDataset(val_pairs)

    model = DualEncoder(
        cve_model=args.cve_model,
        poc_model=args.poc_model,
        out_dim=args.out_dim
    ).to(device)

    cve_tok = model.cve_tok
    poc_tok = model.poc_tok

    # 프리패킹(텍스트만 미리 생성)
    def pack_items(ds):
        packed = []
        for obj in tqdm(ds.items, desc="Packing texts"):
            packed.append({
                "cve_txt": ds.get_cve_text(obj),
                "poc_txt": ds.get_poc_text(obj)
            })
        return packed

    train_items = pack_items(dataset_train)
    val_items   = pack_items(dataset_val)

    def batch_iter(items, batch_size):
        for i in range(0, len(items), batch_size):
            yield items[i:i+batch_size]

    optimizer = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=args.weight_decay)
    loss_fn = ContrastiveLoss(temperature=args.temperature)
    best_val = float("inf")
    scaler = torch.cuda.amp.GradScaler(enabled=args.amp and (device == "cuda"))

    os.makedirs(args.out_dir, exist_ok=True)

    for epoch in range(args.epochs):
        model.train()
        tr_loss, steps = 0.0, 0
        for chunk in batch_iter(train_items, args.batch_size):
            cve_inputs, poc_inputs = collate(chunk, cve_tok, poc_tok,
                                             args.max_cve_len, args.max_poc_len, device)
            optimizer.zero_grad(set_to_none=True)

            if scaler.is_enabled():
                with torch.cuda.amp.autocast():
                    zc, zp = model(cve_inputs, poc_inputs)
                    loss = loss_fn(zc, zp)
                scaler.scale(loss).backward()
                torch.nn.utils.clip_grad_norm_(model.parameters(), args.max_grad_norm)
                scaler.step(optimizer)
                scaler.update()
            else:
                zc, zp = model(cve_inputs, poc_inputs)
                loss = loss_fn(zc, zp)
                loss.backward()
                torch.nn.utils.clip_grad_norm_(model.parameters(), args.max_grad_norm)
                optimizer.step()

            tr_loss += float(loss.item()); steps += 1

        avg_tr = tr_loss / max(1, steps)

        # 검증
        model.eval()
        with torch.no_grad():
            correct, total = 0, 0
            for chunk in batch_iter(val_items, args.batch_size):
                cve_inputs, poc_inputs = collate(chunk, cve_tok, poc_tok,
                                                 args.max_cve_len, args.max_poc_len, device)
                zc, zp = model(cve_inputs, poc_inputs)
                sim = zc @ zp.t()
                pred = sim.argmax(dim=1)
                labels = torch.arange(sim.size(0), device=sim.device)
                correct += (pred == labels).sum().item()
                total += sim.size(0)
            val_acc = correct / max(1, total)

        logger.info(f"[Epoch {epoch+1}/{args.epochs}] train_loss={avg_tr:.4f}  val_top1={val_acc:.4f}")

        # 체크포인트 (val_acc 최대화 ↔ val_metric 최소화)
        val_metric = -val_acc
        if val_metric < best_val:
            best_val = val_metric
            ckpt_path = os.path.join(args.out_dir, "dual_encoder.pt")
            torch.save({
                "model": model.state_dict(),
                "args": {
                    "cve_model": args.cve_model,
                    "poc_model": args.poc_model,
                    "out_dim": args.out_dim,
                    "max_cve_len": args.max_cve_len,
                    "max_poc_len": args.max_poc_len
                }
            }, ckpt_path)
            logger.info(f"Saved checkpoint to {ckpt_path}")

    # 최종 인덱스 구축
    build_faiss_index(model, train_items + val_items, args.out_dir, args.max_poc_len)

def build_faiss_index(model: DualEncoder, items: List[Dict], out_dir: str, max_poc_len: int):
    try:
        import faiss
    except Exception:
        logger.error("faiss 모듈을 불러올 수 없습니다. `pip install faiss-cpu` 후 재시도하세요.")
        return

    device = "cuda" if torch.cuda.is_available() else "cpu"
    model.eval()
    poc_texts = [it["poc_txt"] for it in items]
    if len(poc_texts) == 0:
        logger.error("PoC 텍스트가 없습니다. 인덱스를 만들 수 없습니다.")
        return

    pvecs = []
    with torch.no_grad():
        for i in tqdm(range(0, len(poc_texts), 64), desc="Indexing PoCs"):
            z = model.encode_poc(poc_texts[i:i+64], max_len=max_poc_len, device=device)
            pvecs.append(z.cpu().numpy())
    pvecs = np.vstack(pvecs).astype("float32")

    index = faiss.IndexFlatIP(pvecs.shape[1])  # 코사인 정규화 전제(내적)
    index.add(pvecs)
    os.makedirs(out_dir, exist_ok=True)
    faiss.write_index(index, os.path.join(out_dir, "poc.index"))
    with open(os.path.join(out_dir, "poc_corpus.jsonl"), "w", encoding="utf-8") as f:
        for it in items:
            f.write(json.dumps({"poc_txt": it["poc_txt"]}, ensure_ascii=False) + "\n")
    logger.info(f"Faiss index built at {out_dir}")

# =========================
# 5) 추론/검색
# =========================

def load_model_and_index(ckpt_dir="./ckpt"):
    try:
        import faiss
    except Exception:
        logger.error("faiss 모듈을 불러올 수 없습니다. `pip install faiss-cpu` 후 재시도하세요.")
        raise

    device = "cuda" if torch.cuda.is_available() else "cpu"
    ckpt_path = os.path.join(ckpt_dir, "dual_encoder.pt")
    index_path = os.path.join(ckpt_dir, "poc.index")
    corpus_path = os.path.join(ckpt_dir, "poc_corpus.jsonl")

    if not os.path.exists(ckpt_path) or not os.path.exists(index_path) or not os.path.exists(corpus_path):
        raise FileNotFoundError("체크포인트/인덱스/코퍼스 파일이 없습니다. 먼저 train 또는 build-index를 실행하세요.")

    ckpt = torch.load(ckpt_path, map_location=device)
    saved_args = ckpt["args"]
    model = DualEncoder(
        cve_model=saved_args.get("cve_model","sentence-transformers/all-MiniLM-L6-v2"),
        poc_model=saved_args.get("poc_model","microsoft/codebert-base"),
        out_dim=saved_args.get("out_dim",384)
    )
    model.load_state_dict(ckpt["model"])
    model.to(device).eval()

    import faiss  # re-import for type
    index = faiss.read_index(index_path)

    corpus = []
    with open(corpus_path, "r", encoding="utf-8") as f:
        for line in f:
            corpus.append(json.loads(line))

    return model, index, corpus, device, saved_args

@torch.inference_mode()
def search_poc_by_cve_text(cve_text: str, topk=5, ckpt_dir="./ckpt"):
    import faiss  # ensure present
    model, index, corpus, device, saved_args = load_model_and_index(ckpt_dir)
    z = model.encode_cve([cve_text], max_len=saved_args.get("max_cve_len", 512), device=device)
    z = z.cpu().numpy().astype("float32")
    D, I = index.search(z, topk)
    results = []
    for score, idx in zip(D[0], I[0]):
        results.append({"score": float(score), "poc_preview": corpus[idx]["poc_txt"][:800]})
    return results

# =========================
# 6) Exploit 가능성 분류기(옵션)
# =========================

class ExploitabilityClassifier(nn.Module):
    """
    CVE 텍스트 -> PoC 존재 여부(이진)
    """
    def __init__(self, base="sentence-transformers/all-MiniLM-L6-v2"):
        super().__init__()
        self.tok = AutoTokenizer.from_pretrained(base, use_fast=True)
        self.enc = AutoModel.from_pretrained(base)
        hid = self.enc.config.hidden_size
        self.clf = nn.Linear(hid, 2)

    def forward(self, input_ids, attention_mask):
        out = self.enc(input_ids=input_ids, attention_mask=attention_mask).last_hidden_state
        mask = attention_mask.unsqueeze(-1)
        mean = (out * mask).sum(1) / mask.sum(1).clamp(min=1e-6)
        logits = self.clf(mean)
        return logits

def build_exploit_labels(db_cfg: Optional[DBConfig] = None):
    """
    CVE에 연결된 PoC 존재하면 1, 없으면 0 라벨을 만들어 이진 분류 학습.
    """
    conn = get_db_conn(db_cfg)
    with conn.cursor() as cur:
        cur.execute("SELECT cve_id FROM cve_vulnerabilities")
        all_ids = {r["cve_id"] for r in cur.fetchall()}
        cur.execute("SELECT DISTINCT cve_id FROM cve_poc_sources")
        has_poc = {r["cve_id"] for r in cur.fetchall()}
    pos = has_poc
    neg = list(all_ids - has_poc)
    return list(pos), neg

# =========================
# 7) CLI
# =========================

def positive_int(v: str) -> int:
    iv = int(v)
    if iv <= 0:
        raise argparse.ArgumentTypeError("must be > 0")
    return iv

def nonneg_float(v: str) -> float:
    fv = float(v)
    if fv < 0:
        raise argparse.ArgumentTypeError("must be >= 0")
    return fv

def read_query_text(args) -> str:
    if args.text:
        return args.text
    if args.text_file:
        with open(args.text_file, "r", encoding="utf-8") as f:
            return f.read()
    # stdin
    if not sys.stdin.isatty():
        return sys.stdin.read()
    raise ValueError("검색 질의가 없습니다. --text 또는 --text-file 또는 표준입력을 사용하세요.")

def build_index_only(args, db_cfg: Optional[DBConfig]):
    # 기존 ckpt 로드 후, DB에서 다시 pairs를 뽑아 텍스트를 구성하여 인덱스만 재빌드
    device = "cuda" if torch.cuda.is_available() else "cpu"
    ckpt_dir = args.ckpt_dir
    ckpt_path = os.path.join(ckpt_dir, "dual_encoder.pt")
    if not os.path.exists(ckpt_path):
        logger.error("체크포인트가 없습니다. 먼저 train을 수행하거나 ckpt 디렉토리를 확인하세요.")
        sys.exit(1)

    # 모델 복원
    ckpt = torch.load(ckpt_path, map_location=device)
    saved = ckpt["args"]
    model = DualEncoder(
        cve_model=saved.get("cve_model","sentence-transformers/all-MiniLM-L6-v2"),
        poc_model=saved.get("poc_model","microsoft/codebert-base"),
        out_dim=saved.get("out_dim",384)
    ).to(device)
    model.load_state_dict(ckpt["model"])
    model.eval()

    # 새 pairs 로드 및 텍스트 구성
    all_pairs = load_pairs_from_db(min_year=args.min_year, db_cfg=db_cfg)
    if args.limit and args.limit > 0:
        all_pairs = all_pairs[:args.limit]
    dataset = PairDataset(all_pairs)

    items = []
    for obj in tqdm(dataset.items, desc="Packing texts"):
        items.append({
            "cve_txt": dataset.get_cve_text(obj),
            "poc_txt": dataset.get_poc_text(obj)
        })
    build_faiss_index(model, items, ckpt_dir, saved.get("max_poc_len", 512))

def main():
    parser = argparse.ArgumentParser(description="CVE↔PoC Dual Encoder Trainer / Indexer / Searcher")
    sub = parser.add_subparsers(dest="cmd", required=True)

    # 공통 DB 옵션
    def add_db_opts(p):
        p.add_argument("--db-host", default=env_or_default("DB_HOST", "127.0.0.1"))
        p.add_argument("--db-user", default=env_or_default("DB_USER", "root"))
        p.add_argument("--db-pass", default=env_or_default("DB_PASS", ""))
        p.add_argument("--db-name", default=env_or_default("DB_NAME", "cvedb"))
        p.add_argument("--db-port", type=int, default=int(env_or_default("DB_PORT", "3306")))
        p.add_argument("--db-charset", default=env_or_default("DB_CHARSET", "utf8mb4"))

    # train
    p_train = sub.add_parser("train", help="듀얼인코더 학습 및 인덱스 구축")
    add_db_opts(p_train)
    p_train.add_argument("--min-year", type=int, default=1999)
    p_train.add_argument("--limit", type=int, default=0, help="학습에 사용할 최대 pair 수(0이면 전체)")
    p_train.add_argument("--cve-model", default="sentence-transformers/all-MiniLM-L6-v2")
    p_train.add_argument("--poc-model", default="microsoft/codebert-base")
    p_train.add_argument("--out-dim", type=positive_int, default=384)
    p_train.add_argument("--epochs", type=positive_int, default=3)
    p_train.add_argument("--batch-size", type=positive_int, default=16)
    p_train.add_argument("--lr", type=float, default=2e-5)
    p_train.add_argument("--weight-decay", type=float, default=0.01)
    p_train.add_argument("--temperature", type=float, default=0.05)
    p_train.add_argument("--max-cve-len", type=positive_int, default=512)
    p_train.add_argument("--max-poc-len", type=positive_int, default=512)
    p_train.add_argument("--out-dir", default="./ckpt")
    p_train.add_argument("--val-ratio", type=float, default=0.1)
    p_train.add_argument("--seed", type=int, default=42)
    p_train.add_argument("--amp", action="store_true", help="자동혼합정밀(AMP) 사용")
    p_train.add_argument("--max-grad-norm", type=float, default=1.0)

    # build-index
    p_index = sub.add_parser("build-index", help="기존 체크포인트로 인덱스만 재구축")
    add_db_opts(p_index)
    p_index.add_argument("--min-year", type=int, default=1999)
    p_index.add_argument("--limit", type=int, default=0)
    p_index.add_argument("--ckpt-dir", default="./ckpt")

    # search
    p_search = sub.add_parser("search", help="사용자 입력으로 PoC 검색")
    p_search.add_argument("--ckpt-dir", default="./ckpt")
    p_search.add_argument("--topk", type=positive_int, default=5)
    g = p_search.add_mutually_exclusive_group()
    g.add_argument("--text", type=str, help="직접 질의 텍스트 입력")
    g.add_argument("--text-file", type=str, help="질의 텍스트가 담긴 파일 경로")

    args = parser.parse_args()

    db_cfg = None
    if args.cmd in ("train", "build-index"):
        db_cfg = DBConfig(
            host=args.db_host, user=args.db_user, password=args.db_pass,
            database=args.db_name, port=args.db_port, charset=args.db_charset
        )

    if args.cmd == "train":
        train_main(args, db_cfg=db_cfg)

    elif args.cmd == "build-index":
        build_index_only(args, db_cfg=db_cfg)

    elif args.cmd == "search":
        try:
            query = read_query_text(args)
        except Exception as e:
            logger.error(str(e))
            sys.exit(2)
        results = search_poc_by_cve_text(query, topk=args.topk, ckpt_dir=args.ckpt_dir)
        print(json.dumps(results, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()
