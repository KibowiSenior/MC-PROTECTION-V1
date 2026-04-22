# Minecraft Shield Proxy

Lightweight TCP proxy for Minecraft that adds basic DDoS protection, handshake/login filtering, and forwarding to a backend server.

## What this app does

- Listens for incoming Minecraft connections on a public port
- Applies per-IP rate limiting during handshake/login
- Temporarily blocks abusive IPs in memory
- Responds to status ping (MOTD) requests
- Optionally enforces a username whitelist
- Forwards valid login traffic to your backend Minecraft server

## Project files

- `shield.js` - main proxy and protection logic
- `config.json` - runtime settings (ports, backend, rate limits, MOTD, whitelist)
- `package.json` - Node.js metadata and run script

## Requirements

- Node.js 16+ (18+ recommended)
- Open firewall/hosting rules for your listening port
- Reachable backend Minecraft server

## Install and run

```bash
npm install
npm start
```

Start script:

```bash
node shield.js
```

## Configuration (`config.json`)

### Network

- `listenPort`: Public port where shield listens (example: `25577`)
- `backendIp`: Private/public IP of real Minecraft backend
- `backendPort`: Backend Minecraft server port

### Protection

- `maxConnPerIp`: Max connections per IP inside the rate window
- `rateLimitWindowMs`: Rate window in milliseconds
- `connectionTimeout`: Socket timeout in milliseconds during pre-forwarding stages
- `blockingDurationMs`: Temporary block duration in milliseconds for abusive IPs

### MOTD / status response

- `motd.description`: Server description shown in server list
- `motd.maxPlayers`: Maximum player count displayed
- `motd.onlinePlayers`: Online player count displayed
- `motd.versionName`: Version label text
- `motd.protocol`: Protocol version value for client compatibility display

### Whitelist

- `whitelist.enabled`: `true` to restrict logins to listed players
- `whitelist.players`: Allowed usernames when whitelist is enabled

## How traffic is handled

1. Client connects to shield listener.
2. Shield checks temporary blocklist.
3. Shield enforces per-IP rate limit.
4. Shield processes handshake state.
5. For status requests, shield returns MOTD JSON.
6. For login, shield validates whitelist (if enabled).
7. Shield opens backend connection and pipes traffic in both directions.

## Performance, ping, and traffic speed

### Ping effect (latency impact)

- Normal impact is usually low because this is a local TCP proxy layer in Node.js.
- `setNoDelay(true)` is enabled for both client and backend sockets, reducing packet delay from Nagle buffering.
- During status ping, the shield answers quickly from memory (MOTD JSON) without contacting backend server.
- Real-world ping mostly depends on network route and host quality, not only proxy logic.

### Blocking speed (how fast abuse is stopped)

- Blocklist check happens at connection start, so already-blocked IPs are dropped immediately.
- Rate-limit checks are early in the flow (before full login forwarding), so abusive bursts are cut quickly.
- Oversized pre-forwarding buffers are detected and closed fast (64 KB handshake-stage cap).
- Cleanup cycle runs every 5 seconds to remove expired limits/bans and keep memory stable.

### Traffic handling efficiency

- Uses stream piping (`clientSocket.pipe(backendSocket)` and reverse) after validation for efficient pass-through.
- Handshake packet is captured once and replayed to backend, then raw traffic is forwarded directly.
- Minimal dependencies and simple in-memory maps keep overhead low.
- No heavy cryptographic or deep packet inspection stage, so CPU overhead is generally moderate.

### Throughput and scaling notes

- Single-process Node.js design is good for lightweight to medium traffic.
- Very high attack volume can still saturate host CPU/network before app-level checks help.
- For larger deployments, combine this proxy with upstream DDoS filtering and firewall rate limits.

### Performance tuning tips

- Reduce false positives by tuning `maxConnPerIp` and `rateLimitWindowMs` to your player behavior.
- Set a sensible `blockingDurationMs` so attackers stay blocked but legitimate users can recover.
- Keep `connectionTimeout` balanced: too low may drop slow users, too high keeps dead sockets longer.
- Run on a low-latency VPS near your player region for best ping stability.

## Security and quality review (based on code)

### What is good

- Uses explicit handshake/login state handling instead of blindly forwarding first packet.
- Has per-IP connection rate limiting before backend forwarding.
- Adds temporary blocking for abusive IPs (auto-unban after expiry).
- Includes packet-size guard (64 KB cap before full forwarding) to reduce simple buffer abuse.
- Uses connection timeout to clean stale/inactive sockets.
- Adds global process error handlers so one runtime exception is less likely to crash the shield.

### Security level (realistic)

- Good as a lightweight first-layer shield for small/medium servers.
- Not a full enterprise anti-DDoS system (no distributed filtering, no SYN flood mitigation, no upstream scrubbing).
- Best used together with host firewall rules and provider-level DDoS protection.

### Important limitations

- In-memory blocklist/rate state: all bans and counters are lost on process restart.
- IP-based rate limits can affect shared networks/NAT users.
- Whitelist checks only happen at login stage (by design).
- No built-in metrics dashboard, alerting, or persistent security logs.

## Recommended hardening checklist

- Add `blockingDurationMs` in `config.json` (example: `60000` for 60 seconds).
- Keep `backendIp:backendPort` private from direct public access when possible.
- Place this proxy behind cloud/network firewall protection.
- Run with a process manager for auto-restart and log rotation.
- Monitor connection patterns and tune `maxConnPerIp` + `rateLimitWindowMs` to reduce false positives.
- Keep Node.js updated to current LTS.

## Operational notes

- Blocked IPs and counters are in-memory only and reset when process restarts.
- Use a process manager (PM2/systemd/Windows service wrapper) for production uptime.
- Keep backend server protected by allowing direct access only from trusted sources when possible.
- Tune `maxConnPerIp` and `rateLimitWindowMs` for your normal player traffic pattern.

## Quick troubleshooting

- App exits on startup: verify `config.json` is valid JSON.
- Players cannot join: confirm `backendIp` and `backendPort` are correct and reachable.
- False positives in blocking: increase `maxConnPerIp` or adjust `rateLimitWindowMs`.
- Status ping works but login fails: check whitelist configuration and backend availability.

## License

ISC (from `package.json`)
