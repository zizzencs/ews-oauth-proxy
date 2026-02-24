# Security Considerations

`ews-oauth-proxy` is designed with a very specific, lightweight use case in mind: running locally on a single user's workstation to bridge a local email client to Microsoft 365. 

Because of this design, **it does not perform any authentication or validation on incoming connections from the email client.**

## The Proxy is an "Unauthenticated Open Relay"

For every incoming request, the proxy simply strips whatever password the mail client sent (if any) and injects your highly-privileged OAuth `Bearer` token before forwarding the request to the Exchange server.

**This means anyone who can connect to the proxy's IP address and port can send standard Exchange Web Services (EWS) HTTP requests using your identity.** They do not need to know your password; they can send gibberish or nothing at all, and the proxy will authorize it.

## Network Access & Binding (Listen Address)

By default, the application binds to `127.0.0.1:8443` (localhost). 
* **If bound to `127.0.0.1` (Default):** Only applications running on the same local machine can connect to the proxy and access your mailbox. This is generally safe for personal use on a single-user machine.
* **If bound to `0.0.0.0` or a public IP:** **DO NOT DO THIS.** If you expose this port to your local network or the public internet, **anyone on the network** can connect to it and access your mailbox completely unauthenticated.

If you plan to run this on a centralized server for multiple users or devices, you must **never** expose its port directly. You should put it behind a secure reverse proxy (like Nginx with mutual TLS/authentication) or a Virtual Private Network (like Tailscale/WireGuard) that enforces its own layer of access control before traffic is allowed to reach `ews-oauth-proxy`.

## Token File Security

When you authenticate, the application receives a persistent `refresh_token` and saves it to a file (`.token.json` by default).

* The code saves this file with strict `0600` permissions, meaning it is readable only by the Unix user account running the proxy.
* **Protect this file:** If malware or an attacker compromises your Unix user account, they can copy `.token.json`. With that refresh token, they can request their own access tokens directly from Microsoft from anywhere in the world and access your mailbox indefinitely, bypassing the proxy entirely. Treat the host machine where this file resides as highly sensitive.
