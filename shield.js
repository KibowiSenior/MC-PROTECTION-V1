const net = require('net');
const fs = require('fs');
const path = require('path');

// --- CONFIGURATION LOADING ---
let config;
try {
    const configPath = path.join(__dirname, 'config.json');
    config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
} catch (err) {
    console.error("CRITICAL: Failed to load config.json:", err.message);
    process.exit(1);
}

// --- GLOBAL STATE ---
const ipConnections = new Map();
const blockedIPs = new Map(); // IP -> Expiration Timestamp

// --- CRASH PREVENTION: Global Error Handlers ---
process.on('uncaughtException', (err) => {
    console.error(`[CRITICAL] Uncaught Exception: ${err.message}`);
    // Do not exit, just log it.
});

process.on('unhandledRejection', (reason, promise) => {
    console.error(`[CRITICAL] Unhandled Rejection:`, reason);
});

// Cleanup Rate Limiting & Blocked IPs
setInterval(() => {
    const now = Date.now();

    // Cleanup Rate Limits
    for (const [ip, data] of ipConnections.entries()) {
        if (now - data.lastSeen > config.rateLimitWindowMs) {
            ipConnections.delete(ip);
        }
    }

    // Cleanup Expired Bans
    for (const [ip, expiry] of blockedIPs.entries()) {
        if (now > expiry) {
            blockedIPs.delete(ip);
            log(`Unbanned IP: ${ip} (Ban Expired)`);
        }
    }
}, 5000);

// --- HELPER FUNCTIONS ---
function blockIP(ip, reason) {
    if (!blockedIPs.has(ip)) {
        blockedIPs.set(ip, Date.now() + config.blockingDurationMs);
        log(`[BAN] Blocked ${ip} for ${config.blockingDurationMs / 1000}s. Reason: ${reason}`);
    }
}


// --- HELPER FUNCTIONS ---
function varIntBuf(v) {
    let buf = [];
    while (true) {
        if ((v & ~0x7F) == 0) {
            buf.push(v);
            break;
        }
        buf.push((v & 0x7F) | 0x80);
        v >>>= 7;
    }
    return Buffer.from(buf);
}

function readVarInt(buffer, offset = 0) {
    let num = 0;
    let shift = 0;
    let bytesRead = 0;
    while (true) {
        if (offset + bytesRead >= buffer.length) return null;
        const byte = buffer[offset + bytesRead];
        num |= (byte & 0x7F) << shift;
        bytesRead++;
        shift += 7;
        if ((byte & 0x80) === 0) break;
        if (shift > 35) throw new Error("VarInt too big");
    }
    return { value: num, length: bytesRead };
}

function log(msg) {
    console.log(`[Shield] ${msg}`);
}

// --- SERVER LOGIC ---
const server = net.createServer((clientSocket) => {
    // CRITICAL: Low Latency
    clientSocket.setNoDelay(true);

    const remoteAddress = clientSocket.remoteAddress;

    // 0. CHECK BLOCKLIST
    if (blockedIPs.has(remoteAddress)) {
        clientSocket.destroy(); // Silent drop
        return;
    }

    // 1. Rate Limiting Check
    const now = Date.now();
    let clientData = ipConnections.get(remoteAddress);
    if (!clientData) {
        clientData = { count: 1, lastSeen: now };
        ipConnections.set(remoteAddress, clientData);
    } else {
        if (now - clientData.lastSeen < config.rateLimitWindowMs) {
            clientData.count++;
        } else {
            clientData.count = 1;
            clientData.lastSeen = now;
        }
    }

    if (clientData.count > config.maxConnPerIp) {
        // Silent drop or destroy
        blockIP(remoteAddress, "Rate Limit Exceeded");
        clientSocket.destroy();
        return;
    }

    log(`Connect: ${remoteAddress}`);

    // Internal State
    let buffer = Buffer.alloc(0);
    let state = 0; // 0=Handshake, 1=Status, 2=Login, 3=Forwarding
    let backendSocket = null;
    let savedHandshake = null; // Store RAW handshake bytes
    let clientProtocol = 0;
    let isDestroyed = false;

    const cleanup = () => {
        if (isDestroyed) return;
        isDestroyed = true;
        if (backendSocket) backendSocket.destroy();
        clientSocket.destroy();
    };

    const onData = (data) => {
        if (isDestroyed) return;

        // If we are already forwarding, stop processing logic
        if (state === 3) return;

        // Anti-DoS: Check Buffer Size
        if (buffer.length + data.length > 65535) { // 64KB Limit for Handshake
            blockIP(remoteAddress, "Buffer Overflow (DoS Attempt)");
            cleanup();
            return;
        }

        buffer = Buffer.concat([buffer, data]);

        while (true) {
            if (state === 3 || isDestroyed) break;

            // Read Packet Length
            let lengthRes;
            try { lengthRes = readVarInt(buffer, 0); }
            catch (e) { cleanup(); return; }

            if (!lengthRes) break; // Needs more data

            const packetLen = lengthRes.value;
            const lenSize = lengthRes.length;

            if (buffer.length < lenSize + packetLen) break; // Needs more data

            // CRITICAL: Capture the exact raw packet bytes
            const fullPacket = buffer.slice(0, lenSize + packetLen);

            // Extract Payload for logic
            const packetData = buffer.slice(lenSize, lenSize + packetLen); // This is [ID] [Payload...]
            buffer = buffer.slice(lenSize + packetLen); // Advance global buffer

            // Read Packet ID
            let pOffset = 0;
            const idRes = readVarInt(packetData, 0);
            if (!idRes) { cleanup(); return; }
            const packetID = idRes.value;
            pOffset += idRes.length;

            // --- STATE MACHINE ---
            try {
                if (state === 0) { // HANDSHAKE
                    if (packetID === 0x00) {
                        const protoVer = readVarInt(packetData, pOffset); pOffset += protoVer.length;
                        clientProtocol = protoVer.value;

                        const addrLen = readVarInt(packetData, pOffset); pOffset += addrLen.length;
                        pOffset += addrLen.value; // Skip host
                        pOffset += 2; // Skip port
                        const nextStateRes = readVarInt(packetData, pOffset);
                        const nextState = nextStateRes.value;

                        // SAVE RAW HANDSHAKE
                        savedHandshake = fullPacket;

                        if (nextState === 1) state = 1; // STATUS
                        else if (nextState === 2) state = 2; // LOGIN
                        else { cleanup(); return; }
                    } else {
                        cleanup(); return;
                    }
                } else if (state === 1) { // STATUS
                    if (packetID === 0x00) { // Request
                        const jsonResponse = JSON.stringify({
                            version: { name: config.motd.versionName, protocol: clientProtocol },
                            players: { max: config.motd.maxPlayers, online: config.motd.onlinePlayers, sample: [] },
                            description: { text: config.motd.description }
                        });
                        const jsonBuf = Buffer.from(jsonResponse, 'utf8');
                        const payload = Buffer.concat([Buffer.from([0x00]), varIntBuf(jsonBuf.length), jsonBuf]);

                        // Check if writable
                        if (!clientSocket.writable) return;
                        clientSocket.write(Buffer.concat([varIntBuf(payload.length), payload]));
                    } else if (packetID === 0x01) { // Ping
                        if (!clientSocket.writable) return;
                        clientSocket.write(fullPacket); // Echo
                    }
                } else if (state === 2) { // LOGIN
                    if (packetID === 0x00) { // Login Start
                        const nameLen = readVarInt(packetData, pOffset);
                        const username = packetData.slice(pOffset + nameLen.length, pOffset + nameLen.length + nameLen.value).toString('utf8');

                        if (config.whitelist.enabled && !config.whitelist.players.includes(username)) {
                            log(`Blocked ${username} (Not Whitelisted)`);
                            // Optional: Don't ban for whitelist (maybe they typed it wrong), but for strict mode:
                            // blockIP(remoteAddress, "Not Whitelisted"); 
                            // User asked for "block ddos ip", not necessarily whitelist. Keeping whitelist as kick only.
                            cleanup();
                            return;
                        }

                        log(`Allowing Login: ${username}`);

                        // --- ENTER FORWARDING MODE ---
                        state = 3;

                        backendSocket = new net.Socket();

                        // Error handling for backend
                        backendSocket.on('error', (e) => {
                            log(`Backend Error (${username}): ${e.message}`);
                            cleanup();
                        });
                        backendSocket.on('close', () => cleanup());

                        backendSocket.connect(config.backendPort, config.backendIp, () => {
                            if (isDestroyed) {
                                backendSocket.destroy();
                                return;
                            }

                            // CRITICAL: Low Latency for Backend too
                            backendSocket.setNoDelay(true);

                            log(`Backend connected. Piping traffic...`);

                            // 1. Send Saved Handshake (Exact bytes from client)
                            if (savedHandshake) backendSocket.write(savedHandshake);

                            // 2. Send Current Login Packet (Exact bytes from client)
                            backendSocket.write(fullPacket);

                            // 3. Setup Pipe
                            // Stop our custom 'data' listener to let pipe take over efficiently
                            clientSocket.removeListener('data', onData);

                            // If we have extra data in buffer (unlikely but possible), send it
                            if (buffer.length > 0) {
                                backendSocket.write(buffer);
                                buffer = null;
                            }

                            // Pipe the rest
                            clientSocket.pipe(backendSocket);
                            backendSocket.pipe(clientSocket);
                        });
                    }
                }
            } catch (err) {
                log(`Packet Processing Error: ${err.message}`);
                cleanup();
            }
        } // End While
    };

    clientSocket.on('data', onData);

    clientSocket.on('error', (err) => {
        // Suppress common connection reset errors from log spam
        if (err.code !== 'ECONNRESET') {
            log(`Client Error: ${err.message}`);
        }
        cleanup();
    });

    // Timeout: increased to config.connectionTimeout (default 30000)
    // Only apply timeout during handshake/login. Once piping, let TCP or KeepAlive handle it.
    clientSocket.setTimeout(config.connectionTimeout, () => {
        // If we are merely piping, we might not want to kill it aggressively unless we implement keepalive checks.
        // But for safety, if NO data flows for 30s, kill it.
        // 'timeout' event only fires if no data is received/sent.
        log(`Connection Timed Out: ${remoteAddress}`);
        cleanup();
    });

    clientSocket.on('close', () => cleanup());
});

server.on('error', (err) => {
    console.error(`[CRITICAL] Server Error: ${err.message}`);
});

server.listen(config.listenPort, '0.0.0.0', () => {
    log(`Shield Active on 0.0.0.0:${config.listenPort} (v1.0.1 Stable)`);
    log(`Forwarding to ${config.backendIp}:${config.backendPort}`);
    log(`Rate Limit: ${config.maxConnPerIp}/IP per ${config.rateLimitWindowMs}ms`);
});
