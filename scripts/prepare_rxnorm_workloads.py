#!/usr/bin/env python3
"""Derive reproducible MedProof workloads from the NLM RxNorm prescribable release.

Product names and active-ingredient identities come from RxNorm. Cohort/list
composition is seeded sampling for benchmark dimensions, not observed clinical data.
"""
import hashlib
import json
import random
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data" / "public_sources"
RXDIR = DATA / "rxnorm_prescribe_10052026"
OUTPUT = DATA / "rxnorm_prescribable_20261005_workloads.json"
SEEDS = [11, 23, 37, 53, 71]
E1 = [
    (16, 8, 8, 4, 2), (32, 8, 8, 4, 2), (64, 8, 8, 4, 2), (128, 8, 8, 4, 2),
    (16, 4, 8, 4, 2), (16, 8, 8, 4, 2), (16, 16, 8, 4, 2), (16, 32, 8, 4, 2),
    (16, 8, 4, 1, 4), (16, 8, 8, 4, 4), (16, 8, 16, 8, 4),
    (16, 8, 8, 8, 1), (16, 8, 8, 8, 2), (16, 8, 8, 8, 4),
    (16, 4, 4, 4, 1), (16, 8, 8, 4, 2), (32, 16, 16, 8, 2),
    # q=2 is the largest composition width with enough real RxNorm product
    # variants to sustain m=32; the q=4 synthetic boundary has too few classes.
    (64, 32, 16, 8, 2), (128, 32, 16, 8, 2),
]
E2 = [(16, 8, 8, 8, 1), (16, 8, 8, 4, 4), (16, 8, 8, 2, 4), (16, 8, 8, 4, 2)]


def sha256(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def load_rxnorm():
    tty, names, ingredient_names = {}, {}, {}
    with (RXDIR / "RXNCONSO.RRF").open(encoding="utf-8", errors="replace") as f:
        for line in f:
            c = line.rstrip("\n").split("|")
            if len(c) < 18 or c[11] != "RXNORM" or c[1] != "ENG" or c[16] != "N":
                continue
            cui, term_type, name = c[0], c[12], c[14]
            if term_type in {"SCD", "SCDC", "IN", "MIN", "PIN"}:
                tty[cui] = term_type
            if term_type == "SCD":
                names.setdefault(cui, name)
            if term_type == "IN":
                ingredient_names.setdefault(cui, name)

    scd_to_component, component_to_ingredient, direct = defaultdict(set), defaultdict(set), defaultdict(set)
    with (RXDIR / "RXNREL.RRF").open(encoding="utf-8", errors="replace") as f:
        for line in f:
            c = line.rstrip("\n").split("|")
            if len(c) < 11 or c[10] != "RXNORM":
                continue
            left, right, relation = c[0], c[4], c[7]
            if tty.get(left) == "SCD" and tty.get(right) == "SCDC" and relation == "constitutes":
                scd_to_component[left].add(right)
            elif tty.get(left) == "SCDC" and tty.get(right) == "IN" and relation == "ingredient_of":
                component_to_ingredient[left].add(right)
            elif tty.get(left) == "SCD" and tty.get(right) == "IN" and relation == "ingredients_of":
                direct[left].add(right)

    raw = []
    all_ingredients = set()
    for cui, name in names.items():
        ingredients = set(direct[cui])
        for component in scd_to_component[cui]:
            ingredients.update(component_to_ingredient[component])
        if ingredients:
            ordered = tuple(sorted(ingredients, key=int))
            raw.append((cui, name, ordered))
            all_ingredients.update(ordered)
    code = {cui: i + 1 for i, cui in enumerate(sorted(all_ingredients, key=int))}
    products = []
    for cui, name, ingredients in sorted(raw, key=lambda x: int(x[0])):
        products.append({
            "terminology_id": cui,
            "name": name,
            "ingredients": [code[x] for x in ingredients],
            "supported": True,
        })
    return products, code, ingredient_names


def balanced_counts(m, h):
    return [m // h + (i < m % h) for i in range(h)]


def select_batch(products, seed, m, u, h, q):
    groups = defaultdict(list)
    for p in products:
        key = tuple(p["ingredients"])
        if len(key) == q:
            groups[key].append(p)
    counts = balanced_counts(m, h)
    candidates = [key for key, rows in groups.items() if len(rows) >= max(counts)]
    rng = random.Random(seed * 7919 + m * 101 + u * 17 + h * 13 + q)
    buckets = defaultdict(list)
    for key in candidates:
        buckets[len(groups[key])].append(key)
    candidates = []
    for n in sorted(buckets, reverse=True):
        rng.shuffle(buckets[n])
        candidates.extend(buckets[n])

    selected, nodes = [], 0

    def dfs(start, union):
        nonlocal nodes
        nodes += 1
        if nodes > 500_000:
            return None
        if len(selected) == h:
            return list(selected) if len(union) == u else None
        if len(candidates) - start < h - len(selected) or len(union) > u:
            return None
        for i in range(start, len(candidates)):
            key = candidates[i]
            expanded = union.union(key)
            if len(expanded) > u:
                continue
            selected.append(key)
            found = dfs(i + 1, expanded)
            if found:
                return found
            selected.pop()
        return None

    sets = None
    if u == q * h:
        # Exact-union cases are disjoint set packing; random greedy matching is
        # much faster than enumerating dead-end partial matchings.
        for _ in range(5000):
            order = candidates[:]
            rng.shuffle(order)
            greedy, used = [], set()
            for key in order:
                if not used.intersection(key):
                    greedy.append(key)
                    used.update(key)
                    if len(greedy) == h:
                        break
            nodes += len(order)
            if len(greedy) == h:
                sets = greedy
                break
    else:
        sets = dfs(0, set())
    if not sets:
        raise ValueError(f"No RxNorm composition for seed={seed},m={m},u={u},h={h},q={q}; searched {nodes} nodes")
    product_rng = random.Random(seed * 131 + m * 31 + u * 17 + h * 13 + q)
    chosen = []
    classes = []
    for class_id, (key, take) in enumerate(zip(sets, counts)):
        options = groups[key][:]
        product_rng.shuffle(options)
        chosen.extend(dict(p, **{"class": class_id}) for p in options[:take])
        classes.append({"ingredient_codes": list(key), "product_count": take})
    product_rng.shuffle(chosen)
    all_codes = {x for p in chosen for x in p["ingredients"]}
    length = sum(len(p["ingredients"]) for p in chosen)
    return {
        "seed": seed, "source": "rxnorm-prescribable-20261005",
        "products": chosen, "u": len(all_codes), "L": length,
        "h": len(sets), "q": max(len(p["ingredients"]) for p in chosen),
        "alpha": 1 - len(all_codes) / length,
        "terminology_release": "RxNorm Current Prescribable Content 2026-10-05",
        "normalization": "RXNORM-SCD-to-SCDC-to-IN; direct SCD-to-IN ingredients_of; English preferred term per SCD RXCUI",
        "mapping_digest": "",
        "selection": {"m": m, "u": u, "h": h, "q": q, "classes": classes},
    }


def heterogeneous(products, seed):
    groups = defaultdict(list)
    for p in products:
        n = len(p["ingredients"])
        if 1 <= n <= 4:
            groups[tuple(p["ingredients"])].append(p)
    rng = random.Random(seed * 3571 + 8849)
    keys4 = [k for k, v in groups.items() if len(k) == 4 and len(v) >= 2]
    rng.shuffle(keys4)
    chosen = None
    for full_set in keys4:
        nested = []
        for n in (1, 2, 3, 4):
            options = [k for k, v in groups.items() if len(k) == n and set(k).issubset(full_set) and len(v) >= 2]
            rng.shuffle(options)
            if not options:
                break
            nested.append(options[0])
        if len(nested) == 4:
            chosen = []
            for class_id, key in enumerate(nested):
                rows = groups[key][:]
                rng.shuffle(rows)
                chosen.extend(dict(p, **{"class": class_id}) for p in rows[:2])
            break
    if chosen is None:
        raise ValueError("RxNorm has no nested width 1-4 composition classes within one four-ingredient union")
    # Sparse circuit rows are shape-specialized by position. Keep each seed's
    # variable-width rows in the same canonical width order so one compiled
    # circuit can process every seed in the batch.
    chosen.sort(key=lambda row: (len(row["ingredients"]), int(row["terminology_id"])))
    ingredients = {x for p in chosen for x in p["ingredients"]}
    length = sum(len(p["ingredients"]) for p in chosen)
    return {
        "seed": seed, "source": "rxnorm-prescribable-20261005-heterogeneous",
        "products": chosen, "u": len(ingredients), "L": length,
        "h": len({tuple(p["ingredients"]) for p in chosen}), "q": 4,
        "alpha": 1 - len(ingredients) / length,
        "terminology_release": "RxNorm Current Prescribable Content 2026-10-05",
        "normalization": "RXNORM-SCD-to-SCDC-to-IN; direct SCD-to-IN ingredients_of; English preferred term per SCD RXCUI",
        "mapping_digest": "",
        "selection": {"method": "two actual SCD products per width 1,2,3,4 class"},
    }


def main():
    products, ingredient_codes, ingredient_names = load_rxnorm()
    if len(products) < 1000 or not ingredient_codes:
        raise SystemExit("RxNorm source did not produce the expected mapped product set")
    rx_zip = DATA / "RxNorm_full_prescribe_10052026.zip"
    source_md5 = hashlib.md5(rx_zip.read_bytes()).hexdigest()
    expected_md5 = "a3bfab544c6a67c127ebcd10ab914aa9"
    if source_md5 != expected_md5:
        raise SystemExit(f"RxNorm source checksum mismatch: {source_md5}")
    mapping_rows = [{"rxcui": k, "ingredient_code": v, "english_name": ingredient_names.get(k, "")} for k, v in sorted(ingredient_codes.items(), key=lambda item: item[1])]
    mapping_digest = hashlib.sha256(json.dumps(mapping_rows, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
    batches = []
    dims = sorted(set((m, u, h, q) for _, m, u, h, q in E1 + E2))
    for seed in SEEDS:
        for m, u, h, q in dims:
            b = select_batch(products, seed, m, u, h, q)
            b["mapping_digest"] = mapping_digest
            batches.append(b)
        hb = heterogeneous(products, seed)
        hb["mapping_digest"] = mapping_digest
        batches.append(hb)
    payload = {"schema": "medproof-rxnorm-workloads-v1", "release": "RxNorm Current Prescribable Content 2026-10-05", "source_md5": source_md5, "rxconso_sha256": sha256(RXDIR / "RXNCONSO.RRF"), "rxnrel_sha256": sha256(RXDIR / "RXNREL.RRF"), "mapping_digest": mapping_digest, "products_catalogued": len(products), "ingredient_rxcuis": len(ingredient_codes), "batches": batches}
    payload["workload_payload_digest"] = hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    OUTPUT.write_text(json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(OUTPUT), "sha256": sha256(OUTPUT), "rxnorm_md5": source_md5, "mapping_digest": mapping_digest, "products_catalogued": len(products), "ingredient_rxcuis": len(ingredient_codes), "batch_count": len(batches), "dimensions": len(dims)}, indent=2))


if __name__ == "__main__":
    main()
