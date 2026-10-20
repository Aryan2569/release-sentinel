import json
from collections import defaultdict

eval_results = [json.loads(line) for line in open('data/eval_results_v5.jsonl', encoding='utf-8')]
clusters = json.load(open('data/eval_clusters_v5.json', encoding='utf-8'))
test_cids = sorted(
    {e['cluster_id'] for e in eval_results if e['split'] == 'TEST'},
    key=lambda cid: (clusters[cid]['earliest_discovery'], clusters[cid]['rank'], cid),
)
test_a_cids = set(test_cids[:98])
for e in eval_results:
    if e['split'] == 'TEST':
        e['split'] = 'TEST-A' if e['cluster_id'] in test_a_cids else 'TEST-B'

unlocked = [e for e in eval_results if e['split'] in ('DEV', 'VAL', 'TEST-A')]
c_pairs = defaultdict(list)
for p in unlocked:
    c_pairs[p['cluster_id']].append(p)

cats = defaultdict(list)

for cid, pairs in sorted(c_pairs.items()):
    decs = {p['decision'] for p in pairs}
    if 'BLOCK' in decs:
        continue
    evs = set()
    for p in pairs:
        evs.update(p['evidence_types'])
    rep = pairs[0]
    pkg_str = rep['package'] + '@' + rep['new']

    if 'WARN' in decs:
        if 'dynamic_code' in evs and 'long_encoded_blob' in evs:
            cats['W1: dynamic_code + long_encoded_blob'].append((cid, pkg_str))
        elif 'dynamic_code' in evs and 'large_size_jump' in evs:
            cats['W2: dynamic_code + large_size_jump'].append((cid, pkg_str))
        elif 'long_encoded_blob' in evs and 'large_size_jump' in evs:
            cats['W3: long_encoded_blob + large_size_jump'].append((cid, pkg_str))
        elif 'long_encoded_blob' in evs and 'notable_new_file' in evs:
            cats['W4: long_encoded_blob + notable_new_file'].append((cid, pkg_str))
        elif 'long_encoded_blob' in evs:
            cats['W5: standalone long_encoded_blob'].append((cid, pkg_str))
        elif 'inspection_incomplete' in evs:
            cats['W6: fail-closed only'].append((cid, pkg_str))
        else:
            cats['W7: other single heuristic'].append((cid, pkg_str, list(evs)))
    else:
        # undetected
        if 'unresolvable_dependency' in evs or 'dependency_added' in evs:
            cats['U1: unresolvable / delisted dependency'].append((cid, pkg_str))
        elif 'hardcoded_url' in evs:
            cats['U2: low-sev url only'].append((cid, pkg_str))
        else:
            cats['U3: other / binary diff'].append((cid, pkg_str, list(evs)))

for cat, items in sorted(cats.items()):
    print(f'=== {cat} ({len(items)} clusters) ===')
    for item in items[:10]:
        print(' ', item[0], item[1])
