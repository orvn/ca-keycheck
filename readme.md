![Conventional Commits](https://img.shields.io/badge/Conventional_Commits-FE5196?style=flat&logo=conventionalcommits&logoColor=white)

# Certificate Authority Keycheck

Checks and experiments with the of the [eMudhra intermediate CA key compromise](https://emudhra.we-have-a-problem.com/), ([archived](https://web.archive.org/web/20261020211414/https://emudhra.we-have-a-problem.com/)) disclosed on 2026-10-20

The disclosure says the private keys of eight eMudhra P-384 intermediates were generated incorrectly and can be recovered from the certificates alone. `check.pl` confirms this from public data: it computes `k*G` on P-384 for every `k` from 1 to 255 and compares each result to a certificate's public key. A match means the private key is `k`

It only reads public keys, and it never signs anything or writes key material


### Reqs

- Perl 5 (core modules only: `Math::BigInt`, `IPC::Open2`)
- `openssl` on `PATH`


### Usage

```sh
perl check.pl samples/chains/*.pem
```

Every certificate in each file is checked, so full chains work. Certificates that aren't P-384 (the leaves are P-256) are skipped, and files that can't be read or contain no certificates print a warning and the run continues

On every run, a selftest first confirms that `G` and all of `1*G..255*G` lie on the curve.


### Results

From `samples/chains/`, the chains served by the disclosure's test hosts:

| Intermediate | Private scalar |
|---|---|
| EM DV TLS CA - G3B | 156 |
| EM DV TLS CA - G3C | 230 |
| EM EV TLS CA - G3B | 115 |
| EM EV TLS CA - G3C | 56 |
| EM OV TLS CA - G3B | 155 |
| EM OV TLS CA - G3C | 4 |

The Sectigo cross-signs (`*-aaa-*`) have the same keys and give the same results. The emSign Root TLS CA - G3 is not affected. The disclosure lists eight intermediates, and the other two aren't in these samples


### Samples

`samples/chains/` is the disclosure's `chains.zip`, extracted unmodified, downloaded on 2026-10-20. See `samples/chains/README.txt` for the file layout and for how to test a trust store with `openssl verify`


### Commit messages

Commits must use a conventional prefix, `.githooks/` rejects anything else.

Allowed types: `feat`, `fix`, `hotfix`, `refactor`, `style`, `chore`, `cleanup`, `perf`, `test`, `docs`, `content`

