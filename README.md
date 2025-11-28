# PNG Stego (SPL v1) — CGI Utility

Email me clara@vejadu.xyz if you'e like a copy of the codebase.

`steg_tools.pl` is a Perl CGI web utility for hiding and retrieving encrypted payloads inside PNG files using a custom ancillary chunk named `stEg`.

- Encryption: Argon2id key derivation + AES‑256‑GCM (authenticated encryption)
- Container: PNG ancillary chunk `stEg` with a 1‑byte frame version and a self‑describing “SPL v1” payload
- Features:
  - Embed: upload a PNG, passphrase, optional Context (AAD), secret (text or Base64), download PNG with embedded payload
  - Extract: upload a PNG with `stEg`, passphrase; decrypt and either download plaintext or view UTF‑8 preview + Base64
  - Filenames: optional inclusion of Context in the downloaded plaintext filename
- Defaults:
  - Max upload: 10 MB
  - Argon2id parameters (default): t=3, m=64 MiB, p=2 (configurable)

Live example: https://vejadu.xyz/cgi-bin/steg_tools.pl

Note: The utility keeps all processing in memory (no server‑side storage of payloads or passphrases).

---

## Contents

- Requirements
- Installation
- Web server configuration (Apache/Nginx)
- Configuration knobs in the script
- Usage (browser UI and curl API)
- SPL v1 payload format and PNG chunk handling
- Security notes
- Troubleshooting
- Testing tips
- Future enhancements
- License

---

## Requirements

- Perl 5.26+ (tested on recent versions)
- CPAN modules:
  - `CryptX`
  - `Crypt::Argon2`
  - `Digest::CRC`
  - `CGI`
  - `MIME::Base64`
  - `Encode` (core)

Install modules (recommended: cpanm):
```bash
cpanm CryptX Crypt::Argon2 Digest::CRC CGI MIME::Base64
```

Installation

    Place the script
    Copy steg_tools.pl into your CGI directory, e.g. /var/www/cgi-bin/ or .../public_html/cgi-bin/.

    Make it executable:

chmod 755 /path/to/cgi-bin/steg_tools.pl

    Shebang
    The script uses #!/usr/bin/env perl. If your host requires a specific path, adjust it (e.g., #!/usr/bin/perl).

    Optional: landing page
    If you serve /cgi-bin/ as a browsable directory, add an index.html linking to steg_tools.pl and other tools.

Web server configuration
Apache (CGI)

Enable CGI for the directory and allow .pl scripts to execute:

# In a vhost or .htaccess (if allowed)
Options +ExecCGI
AddHandler cgi-script .pl
DirectoryIndex index.html

# Optional: limit request body size at the server (Apache 2.4+)
LimitRequestBody 10485760  # 10 MB, mirrors $MAX_UPLOAD

CGI directory example:

ScriptAlias /cgi-bin/ "/var/www/cgi-bin/"
<Directory "/var/www/cgi-bin/">
  Options +ExecCGI
  AllowOverride None
  Require all granted
</Directory>

Use HTTPS for production.
Nginx (via fcgiwrap or uWSGI for CGI)

Example (fcgiwrap):

location /cgi-bin/ {
    gzip off;
    root /var/www;                      # adjust
    fastcgi_pass unix:/run/fcgiwrap.socket;
    include /etc/nginx/fastcgi_params;
    fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    fastcgi_param QUERY_STRING $query_string;
    fastcgi_param REQUEST_METHOD $request_method;
    fastcgi_param CONTENT_TYPE $content_type;
    fastcgi_param CONTENT_LENGTH $content_length;
}

Also set:

client_max_body_size 10m;

Configuration knobs (inside the script)

    Max upload size:
        our $MAX_UPLOAD = 10 * 1024 * 1024; # bytes
    Page title:
        our $TITLE = "PNG stEg + SPL v1 (Argon2id + AES-256-GCM)";
    Argon2id parameters (in spl_pack_aesgcm):
        my $ARGON_T = 3;
        my $ARGON_M_KIB = 65536; # 64 MiB; reduce to 16384 (16 MiB) on constrained hosts
        my $ARGON_P = 2;
    Default extract behavior:
        “Download plaintext as file” is checked by default in the HTML form

All binary handling is forced to octets to avoid Unicode pitfalls—keep that behavior intact.
Usage
Browser UI

    Visit /cgi-bin/steg_tools.pl
    Embed:
        Choose a PNG
        Enter passphrase
        Optional Context (AAD; not secret)
        Enter secret text OR tick “Secret is Base64” and paste Base64
        Submit to download the PNG containing the encrypted payload
    Extract:
        Upload the PNG-with-stEg
        Enter passphrase
        By default you’ll receive a plaintext file download; toggle to view a UTF‑8 preview and Base64 instead

Context (AAD) is visible in the header and authenticated; do not put secrets there.
Programmatic API (curl)

Embed (returns PNG):

curl -sS -X POST https://your.host/cgi-bin/steg_tools.pl \
  -F action=embed \
  -F passphrase='correct horse battery staple' \
  -F context='proj=apollo|duck.png' \
  -F secret='Hello SPL v1 via curl' \
  -F png_file=@carrier.png \
  -o carrier_with_stEg.png \
  -D /dev/stderr

Embed with Base64 secret:

# Prepare Base64
echo -n 'binary\x00bytes' | base64 > secret.b64

curl -sS -X POST https://your.host/cgi-bin/steg_tools.pl \
  -F action=embed \
  -F passphrase='correct horse battery staple' \
  -F secret_is_b64=1 \
  -F secret="$(cat secret.b64)" \
  -F png_file=@carrier.png \
  -o out.png

Extract (download plaintext):

curl -sS -X POST https://your.host/cgi-bin/steg_tools.pl \
  -F action=extract \
  -F passphrase='correct horse battery staple' \
  -F download_plain=1 \
  -F base_name='plaintext' \
  -F use_ctx_in_name=1 \
  -F png_file=@carrier_with_stEg.png \
  -o plaintext.bin \
  -D /dev/stderr

Extract (preview in HTML):

curl -sS -X POST https://your.host/cgi-bin/steg_tools.pl \
  -F action=extract \
  -F passphrase='correct horse battery staple' \
  -F download_plain=0 \
  -F png_file=@carrier_with_stEg.png

Form fields:

    Embed:
        action=embed
        png_file=@... (file)
        passphrase (string)
        context (string, optional)
        secret (string; ignored if secret_is_b64=1)
        secret_is_b64=1 (optional)
    Extract:
        action=extract
        png_file=@... (file)
        passphrase (string)
        download_plain=1 (optional; default via UI)
        base_name (string, optional)
        use_ctx_in_name=1 (optional)

Responses:

    200 OK on success (image/png, application/octet-stream, or text/html)
    400 Bad Request with an HTML error page on validation/crypto failures

SPL v1 payload format (implemented here)

Binary layout (little‑endian for numeric fields):

    8 bytes: Magic = SPLDv1\0\0
    1 byte : Flags (bit 0 = has context)
    1 byte : KDF ID (1 = Argon2id)
    1 byte : AEAD ID (2 = AES‑256‑GCM)
    1 byte : Reserved (0)
    4 bytes: Argon2 time cost (t)
    4 bytes: Argon2 memory (m_kib)
    1 byte : Argon2 parallelism (p)
    1 byte : Salt length (SL)
    SL bytes: Salt
    1 byte : Nonce length (NL) — 12 for AES‑GCM
    NL bytes: Nonce
    2 bytes: Context length (CL)
    CL bytes: Context (AAD; optional; included in AEAD AAD)
    8 bytes: Ciphertext length (L)
    L bytes: Ciphertext || Tag (16‑byte GCM tag appended)

AEAD AAD is the entire header up to and including the Context; any header tampering is detected.

PNG chunk:

    Type: stEg (ancillary, private/safe‑to‑copy style)
    Data: 1‑byte frame version (1), followed by the SPL payload
    Note: Some pipelines strip unknown chunks; keep a gold‑master if needed.

Security notes

    The tool processes everything in memory and returns results immediately; it does not store payloads or passphrases server‑side.
    Always serve over HTTPS.
    Keep $MAX_UPLOAD reasonable and enforce server‑level body limits.
    Argon2id parameters can be tuned down on constrained hosts (e.g., m_kib=16384).
    Context (AAD) is not secret and is stored in plaintext in the header (but cryptographically bound). Don’t put secrets there.
    Some apps “optimize” or re‑encode PNGs and will strip unknown chunks (including stEg).

Troubleshooting

    “Not a PNG (bad signature)”
    File isn’t a true PNG or got renamed.

    “PNG parse failed: CRC mismatch for stEg”
    The PNG was altered, recompressed, or chunk data corrupted. The script forces octets and uses byte lengths; ensure clients don’t optimize/strip unknown chunks.

    “Decryption failed (integrity/auth)”
    Wrong passphrase, or header was changed (Context, salts, params). Use the exact PNG returned by Embed.

    “Packing failed: … Invalid key size / Bad AES key length (…)”
    Ensure CryptX and Crypt::Argon2 are installed and up to date. The script derives raw 32‑byte keys (or decodes the encoded form) and enforces octets.

HTTP 500 errors:
Check web server error logs. Confirm modules installed and script is executable (chmod 755).
Testing tips

    Quick round‑trip:
        Embed a short text secret into a small PNG
        Immediately extract with the same passphrase

    Verify chunk presence:

    pngcheck -v carrier_with_stEg.png

    Homebrew: brew install pngcheck. You should see: unknown ancillary chunk stEg.

    Integrity:
        Keep a SHA‑256 of the PNG after embedding if you need to detect later modification


