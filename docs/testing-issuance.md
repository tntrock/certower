# Testing issuance

## Automated: Pebble

The ACME issuer is tested against [Pebble](https://github.com/letsencrypt/pebble),
Let's Encrypt's ACME test server, with its mock DNS server. The tests cover
DNS-01 (including wildcards), ACME profiles, ARI renewal windows, renewal with
`replaces`, revocation, External Account Binding, and account reuse.

```sh
go install github.com/letsencrypt/pebble/v2/cmd/pebble@latest
go install github.com/letsencrypt/pebble/v2/cmd/pebble-challtestsrv@latest
go test ./internal/plugins/acme -v
```

The tests start and stop Pebble themselves, and skip if it is not installed.

## Manual: Let's Encrypt staging + Cloudflare

`certower dev issue` issues one certificate without running the server. It
defaults to the **Let's Encrypt staging** environment, whose certificates are
not trusted by browsers and whose rate limits are generous.

1. In the Cloudflare dashboard, go to *My Profile → API Tokens → Create Token*
   and use the **Edit zone DNS** template. Limit it to the zone you will test
   with. The token needs `Zone:Read` and `DNS:Edit`.

2. Put the token in an environment variable. It is never passed as a flag,
   so it stays out of shell history.

   ```powershell
   # PowerShell
   $env:CLOUDFLARE_API_TOKEN = Read-Host -MaskInput "Cloudflare token"
   ```

   ```sh
   # bash
   read -rs CLOUDFLARE_API_TOKEN && export CLOUDFLARE_API_TOKEN
   ```

3. Issue a certificate:

   ```sh
   certower dev issue -domains certower-test.example.com -email you@example.com
   # Wildcards work too:
   certower dev issue -domains "example.com,*.example.com"
   ```

Output goes to `./certower-dev/<name>/` (`cert.pem`, `chain.pem`,
`fullchain.pem`, `key.pem`). The ACME account key is saved as
`./certower-dev/account.key` and reused on later runs.

Other options:

| Flag | Use |
|---|---|
| `-ca letsencrypt` | Production Let's Encrypt (trusted certificates, strict rate limits) |
| `-profile shortlived` | Let's Encrypt's short-lived profile (about 6 days) |
| `-key-type rsa-2048` | Key type: `ecdsa-p256`, `ecdsa-p384`, `rsa-2048`, `rsa-3072`, `rsa-4096` |
| `-ca zerossl -eab-kid <kid>` | A CA that needs EAB. Put the HMAC key in `ACME_EAB_HMAC` |
| `-directory <url>` | Any ACME directory, e.g. a TWCA endpoint |
