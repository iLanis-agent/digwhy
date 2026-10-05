"""Independent dig-output parser for cross-checking engine.js."""
import json, sys, re, os

def parse(text):
    out = {"version": None, "opcode": None, "status": None, "id": None, "flags": [],
           "counts": {}, "opt": None, "question": [], "answer": [], "authority": [],
           "additional": [], "queryTime": None, "server": None, "when": None, "size": None}
    section = None
    for line in text.splitlines():
        m = re.match(r"; <<>> DiG (\S+)", line)
        if m:
            out["version"] = m.group(1); continue
        m = re.match(r";; ->>HEADER<<- opcode: (\S+), status: (\S+), id: (\d+)", line)
        if m:
            out["opcode"], out["status"], out["id"] = m.group(1), m.group(2), int(m.group(3)); continue
        m = re.match(r";; flags: ([^;]*); QUERY: (\d+), ANSWER: (\d+), AUTHORITY: (\d+), ADDITIONAL: (\d+)", line)
        if m:
            out["flags"] = [f for f in m.group(1).split() if f]
            out["counts"] = {"query": int(m.group(2)), "answer": int(m.group(3)),
                             "authority": int(m.group(4)), "additional": int(m.group(5))}
            continue
        if line.startswith(";; OPT PSEUDOSECTION:"):
            section = "opt"; continue
        m = re.match(r"; EDNS: version: (\d+), flags:([^;]*); udp: (\d+)", line)
        if m:
            out["opt"] = {"version": int(m.group(1)),
                          "flags": [f for f in m.group(2).split() if f], "udp": int(m.group(3))}
            continue
        if line.startswith(";; QUESTION SECTION:"):
            section = "question"; continue
        if line.startswith(";; ANSWER SECTION:"):
            section = "answer"; continue
        if line.startswith(";; AUTHORITY SECTION:"):
            section = "authority"; continue
        if line.startswith(";; ADDITIONAL SECTION:"):
            section = "additional"; continue
        m = re.match(r";; Query time: (\d+) msec", line)
        if m:
            out["queryTime"] = int(m.group(1)); section = None; continue
        m = re.match(r";; SERVER: (\S+)", line)
        if m:
            out["server"] = m.group(1); continue
        m = re.match(r";; WHEN: (.+)$", line)
        if m:
            out["when"] = m.group(1).strip(); continue
        m = re.match(r";; MSG SIZE\s+rcvd: (\d+)", line)
        if m:
            out["size"] = int(m.group(1)); continue
        if not section or section == "opt":
            continue
        flat = re.sub(r"\s+", " ", line.replace("\t", " ")).strip()
        if section == "question":
            m = re.match(r";(\S+)\s+(\w+)\s+(\w+)", flat)
            if m:
                out["question"].append({"name": m.group(1), "cls": m.group(2), "type": m.group(3)})
            continue
        m = re.match(r"(\S+)\s+(\d+)\s+(\w+)\s+(\w+)\s+(.*)$", flat)
        if m:
            out[section].append({"name": m.group(1), "ttl": int(m.group(2)),
                                 "cls": m.group(3), "type": m.group(4), "rdata": m.group(5).strip()})
    return out

corpus = sys.argv[1]
result = {}
for fn in sorted(os.listdir(corpus)):
    if fn.endswith(".txt"):
        result[fn] = parse(open(os.path.join(corpus, fn)).read())
print(json.dumps(result))
