import concurrent.futures, hashlib, json, urllib.request, urllib.error

BASE = "http://127.0.0.1:8080"

def do_req(body: bytes, mode: str, valid: bool):
    req = urllib.request.Request(
        BASE + "/?mode=" + mode,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    try:
        r = urllib.request.urlopen(req, timeout=60)
    except urllib.error.HTTPError as e:
        r = e
    with r:
        status = r.code
        data = r.read()
    expected = 200 if valid else 422
    if status != expected:
        raise RuntimeError(f"HTTP {status}, expected {expected}, body={data[:500]!r}")
    payload = json.loads(data.decode("utf-8"))
    if payload.get("hash") != hashlib.sha256(body).hexdigest():
        raise RuntimeError("Body hash mismatch")
    if valid and payload.get("ok") is not True:
        raise RuntimeError(f"Unexpected non-ok payload: {payload}")
    if (not valid) and payload.get("rejected") is not True:
        raise RuntimeError(f"Invalid JSON not rejected: {payload}")
    return payload.get("pid")

tests = []
small_valid = [
    b'{"a":1}',
    b'{"arr":[1,2,3],"nested":{"x":"y"}}',
    '{"unicode":"zlutoucky kun 🚀"}'.encode("utf-8"),
    b'true',
    b'42',
    b'null',
    b'[]',
    b'{}',
]
invalid = [b'', b'{', b'{"x":}', b'{"x":1} trailing']

for mode in ("direct", "pre-read"):
    for rep in range(10):
        for i, body in enumerate(small_valid):
            if body.startswith(b"{"):
                body = b'{"req":"%d-%s-%d","payload":%s}' % (rep, mode.encode(), i, body)
            tests.append((body, mode, True))
        for body in invalid:
            tests.append((body, mode, False))
        big = b'{"pad":"' + b'x' * (1024 * 1024) + b'"}'
        tests.append((big, mode, True))

pids = set()
for t in tests:
    pids.add(do_req(*t))

with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
    for pid in ex.map(lambda x: do_req(*x), tests):
        pids.add(pid)

print("OK, distinct pids:", sorted(p for p in pids if p is not None))
