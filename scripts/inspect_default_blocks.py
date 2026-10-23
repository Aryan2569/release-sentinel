import glob
import json

caches = glob.glob("data/replay_cache_default_*.json")
for cpath in caches:
    data = json.loads(open(cpath, encoding="utf-8").read())
    for r in data.get("results", []):
        if r["decision"] == "BLOCK":
            print(f"BLOCK: {data['repo']} {r['pair_key']} ({r['subject'][:50]})")
            for b in r.get("blocks", []):
                print(f"   Package: {b['package']}@{b['version']}")
                print(f"   Evidence: {list(set(b['evidence']))}")
                for d in b.get("details", []):
                    sev = d.get("severity")
                    eid = d.get("id")
                    expl = d.get("explanation", "").replace("\n", " ")[:100]
                    print(f"      [{sev}] {eid}: {expl}")
