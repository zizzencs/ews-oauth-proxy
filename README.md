# ews-oauth-proxy

`ews-oauth-proxy` is an extremely lightweight HTTP Proxy designed to handle Microsoft Exchange Web Services (EWS) connections for mail clients that might be blocked by strict organizational policies forcing Outlook use (e.g., Office 365 or on-premises Exchange with Hybrid Modern Authentication). It intercepts standard EWS HTTPS requests, rips out basic authentication credentials provided by the mail client, seamlessly injects a headless OAuth 2.0 `Bearer` token using the Device Code Flow, and forwards the raw EWS traffic to your destination server.

*Credit where credit is due: This project was heavily inspired by DavMail. If you need a fully-featured gateway that transforms EWS into IMAP/SMTP seamlessly, DavMail is the gold standard!*

While `ews-oauth-proxy` is perfectly configured for Microsoft 365 (`outlook.office365.com`) out of the box, it can be easily adapted to any on-premises Exchange environment, ADFS deployment, or custom cloud by simply changing the target URL and authentication endpoints.

## Security Posture

**⚠️ DANGER: `ews-oauth-proxy` acts as an Unauthenticated Open Relay.**

Because this proxy is designed for local use, it **does not authenticate** incoming connections from your mail client. It simply strips any provided basic authentication and automatically injects your highly-privileged OAuth `Bearer` token into every EWS request before forwarding it.

*   **Network Access:** By default, it binds only to `127.0.0.1` (localhost). **Do not** bind it to `0.0.0.0` or a public IP unless it is protected behind a secure reverse proxy or VPN. Anyone who can connect to the proxy's port can send email and access your mailbox using your identity without any password.
*   **Token Protection:** The proxy saves your persistent refresh token locally (e.g., `.token.json`). Treat the machine housing this file as highly sensitive; if the file is copied, an attacker can access your mailbox directly from anywhere.

For a full breakdown of the proxy's security model, please read [SECURITY.md](SECURITY.md).

## Quick Start

1. Generate a local self-signed TLS cert inside the `certs` folder:
```bash
./generate-cert.sh
```
2. Run the application:
```bash
go run .
```

On the first run, the app will pause and print a message asking you to navigate to an authorization URL (usually `https://microsoft.com/devicelogin` for M365) and enter a short code to authorize the application. Once authorized, it automatically saves a refresh token and refreshes it in the background forever.

3. Point your mail client to the proxy "Exchange" server at `https://127.0.0.1:8443`. 

## Configuration

`ews-oauth-proxy` can be configured using either environment variables or a `.env` style configuration file. 
By default, the application looks for a `config.env` file in the current directory. You can specify a custom config file path by setting the `EWS_OAUTH_PROXY_CONFIG` environment variable.

The following variables are supported (via environment or config file):

* `EWS_OAUTH_PROXY_TENANT_ID` (Optional): Your Microsoft 365 Tenant ID. Defaults to `common`, which works for almost all users.
* `EWS_OAUTH_PROXY_CLIENT_ID` (Optional): Your Azure AD Client ID. Defaults to the Outlook desktop application client ID (`d3590ed6-52b3-4102-aeff-aad2292ab01c`).
* `EWS_OAUTH_PROXY_CLIENT_SECRET` (Optional): Your Azure AD Client Secret. Usually not required for the Device Code flow, but necessary for strict custom Enterprise Applications.
* `EWS_OAUTH_PROXY_LISTEN_ADDRESS` (Optional): The IP address and port to bind to. Defaults to `127.0.0.1:8443`. Set to `0.0.0.0:8443` or `:8443` to listen on all interfaces.
* `EWS_OAUTH_PROXY_USERNAME` (Optional): Username required by the proxy for basic authentication.
* `EWS_OAUTH_PROXY_PASSWORD` (Optional): Password required by the proxy for basic authentication. (Note: These are independent of your Microsoft 365 credentials).
* `EWS_OAUTH_PROXY_TOKEN_FILE` (Optional): Path to the generated token cache file. Defaults to `.token.json`.
* `EWS_OAUTH_PROXY_CERT_FILE` (Optional): Path to your TLS certificate. Defaults to `certs/cert.pem`.
* `EWS_OAUTH_PROXY_KEY_FILE` (Optional): Path to your TLS private key. Defaults to `certs/key.pem`.

**Advanced Options (For On-Premises Exchange / Custom Clouds):**
* `EWS_OAUTH_PROXY_TARGET_URL` (Optional): The Exchange server target. Defaults to `https://outlook.office365.com`.
* `EWS_OAUTH_PROXY_DEVICE_CODE_URL` (Optional): The OAuth Device Code endpoint. Defaults to `https://login.microsoftonline.com/%s/oauth2/v2.0/devicecode` (where `%s` is replaced by the Tenant ID).
* `EWS_OAUTH_PROXY_TOKEN_URL` (Optional): The OAuth Token endpoint. Defaults to `https://login.microsoftonline.com/%s/oauth2/v2.0/token` (where `%s` is replaced by the Tenant ID).
* `EWS_OAUTH_PROXY_SCOPE` (Optional): The OAuth scope. Defaults to `https://outlook.office365.com/EWS.AccessAsUser.All offline_access`.

## Well-Known OAuth IDs

If you do not have your own Azure AD Application configured, you can try using universally known Tenant and Client IDs that are already authorized by your organization as standard email clients.

**Tenant ID:**
* `common` - This is a special placeholder Tenant ID used to sign in to any Microsoft personal, work, or school account without knowing the exact directory ID.

**Client IDs:**
* `d3590ed6-52b3-4102-aeff-aad2292ab01c` - Outlook desktop application
* `27922004-5251-4030-b22d-91ecd9a37ea4` - Outlook mobile application
* `bc59ab01-8403-45c6-8796-ac3ef710b3e3` - Outlook web application
* `9e5f94bc-e8a4-4e73-b8be-63364c29d753` - Mozilla Thunderbird

## Securing the Proxy Connection

By default, the proxy acts as an **Unauthenticated Open Relay** on localhost. If you expose the proxy on your wider network (e.g., binding to `0.0.0.0:8443`), it is highly recommended to require explicit proxy authentication.

You can configure standard Basic Authentication by setting the `EWS_OAUTH_PROXY_USERNAME` and `EWS_OAUTH_PROXY_PASSWORD` variables in your `config.env`. 

When these are set, your email client must be configured with this "Proxy Password" instead of your actual corporate password. The proxy validates this password, securely drops the header, signs the request with your OAuth Bearer token, and handles the rest!

## TLS Certificates

`ews-oauth-proxy` requires a valid TLS certificate because connecting clients use basic authentication. All network traffic from your email client strictly requires TLS before the application rips out the username/password elements to protect them from snooping.

**Option 1: Self-Signed Certificate (Default)**
For local use or internal servers, you can generate a self-signed certificate using the included `generate-cert.sh` script.

By default, the script generates a certificate solely for `localhost` (127.0.0.1). 
If you are running the proxy on a remote server, pass your server's fully-qualified domain name (FQDN) and IP address directly as arguments to permanently add them to the certificate's *Subject Alternate Names* (SANs), alongside `localhost`:

```bash
# Usage: ./generate-cert.sh [FQDN] [IP]
./generate-cert.sh mail.mycompany.com 192.168.1.100
```
*Note: Your email client might warn you about "Untrusted Certificates" when using a self-signed certificate. Since this is your own private tunnel, you can safely "Accept Risk" or install the generated `cert.pem` as a trusted certificate authority in your computer.*

**Option 2: Trusted Source (Let's Encrypt / Commercial)**
If you already have a trusted certificate (e.g. managed by Certbot/Let's Encrypt, or an internal corporate Authority), you can completely bypass the script. Simply point `ews-oauth-proxy` to your existing keys by defining them in your `config.env`:

```env
EWS_OAUTH_PROXY_CERT_FILE="/etc/letsencrypt/live/mail.mycompany.com/fullchain.pem"
EWS_OAUTH_PROXY_KEY_FILE="/etc/letsencrypt/live/mail.mycompany.com/privkey.pem"
```
Ensure that the user running `ews-oauth-proxy` has read permissions for these protected files!

## Running in Docker

A `Dockerfile` is provided for containerized environments. The image is built on Alpine Linux and is extremely small.

Because the Device Code Flow requires an initial interactive login, you should run the application interactively for the first time without `-d` so you can retrieve the Microsoft authentication code from the console. You will also want to map a volume to persist your `.token.json` and certificates between container restarts.

```bash
docker build -t ews-oauth-proxy .

touch .token.json

# Step 1: Generate a local TLS certificate using the container
docker run --rm -v $(pwd)/certs:/app/certs ews-oauth-proxy ./generate-cert.sh

# Step 2: Run interactively to get the initial login code
docker run -it --rm \
  --name ews-proxy \
  -p 8443:8443 \
  -v $(pwd)/config.env:/app/config.env \
  -v $(pwd)/.token.json:/app/.token.json \
  -v $(pwd)/certs:/app/certs \
  ews-oauth-proxy

# Step 3: Once authenticated, you can safely run it as a background daemon
docker run -d \
  --name ews-proxy \
  -p 8443:8443 \
  -v $(pwd)/config.env:/app/config.env \
  -v $(pwd)/.token.json:/app/.token.json \
  -v $(pwd)/certs:/app/certs \
  ews-oauth-proxy
```

## Running as a Systemd User Service

Because `ews-oauth-proxy` relies on individual user authentication tokens, you should typically run it as a **Systemd User Service** rather than a system-wide root daemon.

1. Create a directory for your user systemd service files if it doesn't already exist:
```bash
mkdir -p ~/.config/systemd/user/
```

2. Copy the provided sample unit file to your systemd user directory:
```bash
cp ews-oauth-proxy.service ~/.config/systemd/user/
```
*(Note: Check the copied `~/.config/systemd/user/ews-oauth-proxy.service` file and adjust the `WorkingDirectory` and `ExecStart` paths if your application is located somewhere other than `~/ews-oauth-proxy`)*

3. Enable and start the service:
```bash
systemctl --user daemon-reload
systemctl --user enable --now ews-oauth-proxy.service
```

4. Check the logs (which will contain your Microsoft Device Code login prompt!):
```bash
journalctl --user -u ews-oauth-proxy.service -f
```

## Running Multiple Instances

You can easily run multiple side-by-side instances of the proxy for different email accounts (for example, two different company accounts).

To run multiple instances:
1. Copy `config.env.sample` into multiple distinct config files (e.g., `company1.env` and `company2.env`).
2. Inside each config file, assign a unique port and token file:
   * `EWS_OAUTH_PROXY_LISTEN_ADDRESS` (e.g. `127.0.0.1:8443` vs `127.0.0.1:8444`)
   * `EWS_OAUTH_PROXY_TOKEN_FILE` (e.g. `.token_company1.json` vs `.token_company2.json`)
3. Pass the specific configuration file to the application using the `EWS_OAUTH_PROXY_CONFIG` environment variable when starting it.

**Using Systemd Instantiated Units:**
For systemd users, you can elegantly handle multiple copies by using the included [Instantiated Unit](https://www.freedesktop.org/software/systemd/man/systemd.unit.html) template: `ews-oauth-proxy@.service`.

1. Copy the provided template file to your systemd user directory:
```bash
cp ews-oauth-proxy@.service ~/.config/systemd/user/
```
*(Note: As with the regular unit file, ensure the paths inside this template match your actual installation folder).*

You can then spawn multiple independent services dynamically by passing the config name:
```bash
# Starts using company1.env
systemctl --user enable --now ews-oauth-proxy@company1

# Starts using company2.env
systemctl --user enable --now ews-oauth-proxy@company2
```
