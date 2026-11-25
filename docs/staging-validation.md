# v1.0.0 staging and rollback validation

Validated on 2026-11-25 using a disposable GitHub-hosted Docker runner, a synthetic
backend, and no customer credentials or live WAF endpoint.

- Tested code: `0dd18e914c6de3b419dee4b9409feba450037de8`
- Evidence run: https://github.com/secureline-tr/har2bw/actions/runs/45592324840
- Image: `bunkerity/bunkerweb-all-in-one:1.6.18`
- Image digest: `sha256:77cd4d2daa6ebc2f7457b40f973f75496cf514f5eb1c52508339ef192fe49e0c`
- Baseline and restored configuration SHA-256:
  `8d5c5c356dcf0c93a6ac4b001f2f574b49a08911a33fa10904892740526bee75`
- Result: baseline 16/16, candidate 16/16, rollback 16/16.

Each phase tests public access, the `/new` policy transition (403 → 200 → 403),
default deny, wrong methods, query constraints, encoded/dot/repeated-slash paths,
unauthenticated requests, authorized requests and cross-object denial. Backend
request auditing independently proves application authorization ran, even when
BunkerWeb replaces error response bodies. Tests also verify rejection of spoofed
client-IP headers from untrusted peers, correct handling from the one trusted
peer, and attack blocking on an otherwise permitted query endpoint without
reaching the backend. Effective NGINX configuration keeps ModSecurity enabled.

The saved baseline is restored through the same Docker environment-variable
control plane and persistent BunkerWeb data volume used to apply the candidate.
The harness waits for the scheduler's externally observable policy transition,
runs `nginx -t`, captures `nginx -T`, and reruns all request checks after restoration.
The artifact `bunkerweb-1.6.18-staging` contains synthetic configuration, checks,
image digests and logs. No external configuration is executed.

Initial harness failures exposed two fixture assumptions: BunkerWeb intercepts
backend error bodies, and accumulated negative requests can legitimately ban a
client across a configuration rollback. Verification now uses backend auditing
and independent clients per phase, with a separate attack client. Ban state is
preserved; no security feature, rule or threshold is disabled or relaxed.

Run `python staging/verify.py` through the repository's staging workflow. It
refuses non-GitHub-hosted execution and non-local Docker contexts, uses fixed
synthetic addresses, publishes no ports, and removes its named resources on exit.

This proves the supported release fixture, not a customer's deployment. Real
proxy topology, application authorization, configuration conflicts and production
rollback remain environment-specific operator checks. HAR2BW itself still has
no live deployment or write API.
