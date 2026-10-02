// api/magic-users.js (Dynamic Session Token & Cloud Payment Sync)
import { randomBytes } from 'crypto';

export default async function handler(req, res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PATCH,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');

    if (req.method === 'OPTIONS') return res.status(200).end();

    const dbBaseURL = "https://ahmad-bhai-script-users-info-default-rtdb.firebaseio.com";
    const OWNER_EMAIL = "nasiriq703@gmail.com";
    const OWNER_PASS = "nasir703";

    const { action, userKey } = req.query;
    const incomingToken = req.headers['authorization'] || req.headers['token'] || req.query.token;

    try {
        // ─── 1. LOGIN ROUTE (Generates Dynamic One-Time Token) ───
        if (action === "login") {
            const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
            const email = body?.email || req.query.email;
            const password = body?.password || req.query.password;

            if (email === OWNER_EMAIL && password === OWNER_PASS) {
                // Generate secure random dynamic session token
                const newToken = randomBytes(16).toString('hex');
                const expiryTime = Date.now() + (60 * 60 * 1000); // 1-Hour Session Expiry

                // Save dynamic token in Firebase sessions node
                await fetch(`${dbBaseURL}/sessions/${newToken}.json`, {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ createdAt: Date.now(), expiresAt: expiryTime, active: true })
                });

                return res.status(200).json({ success: true, token: newToken });
            }
            return res.status(401).json({ success: false, error: "Invalid Credentials" });
        }

        // ─── GLOBAL SESSION TOKEN VERIFIER & AUTO-EXPIRE GUARD ───
        if (!incomingToken) {
            return res.status(403).json({ success: false, error: "Token Required" });
        }

        const sessionCheckRes = await fetch(`${dbBaseURL}/sessions/${incomingToken}.json`);
        const sessionData = await sessionCheckRes.json();

        if (!sessionData || !sessionData.active || Date.now() > sessionData.expiresAt) {
            // Token Invalid or Expired: Automatically invalidate session
            if (incomingToken && sessionData) {
                await fetch(`${dbBaseURL}/sessions/${incomingToken}.json`, { method: 'DELETE' });
            }
            return res.status(401).json({ success: false, error: "Session Expired or Invalid Token. Logged Out!" });
        }

        // ─── 2. LOAD ALL DATA ───
        if (action === "load") {
            const fbRes = await fetch(`${dbBaseURL}/users.json`);
            const fbData = await fbRes.json();
            return res.status(200).json({ success: true, data: fbData || {} });
        }

        // ─── 3. ADD NEW USER ───
        if (action === "add" && req.method === "POST") {
            const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
            body.paidStatus = false; // Default payment status
            const saveRes = await fetch(`${dbBaseURL}/users.json`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(body)
            });
            if (!saveRes.ok) throw new Error("Firebase Write Rejection");
            return res.status(200).json({ success: true });
        }

        // ─── 4. UPDATE PAYMENT STATUS (Saved directly in Cloud DB) ───
        if (action === "updatePayment" && (req.method === "POST" || req.method === "PATCH")) {
            if (!userKey) return res.status(400).json({ error: "Missing user key" });
            const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
            
            const patchRes = await fetch(`${dbBaseURL}/users/${userKey}.json`, {
                method: "PATCH",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ paidStatus: Boolean(body.paidStatus) })
            });

            if (!patchRes.ok) throw new Error("Firebase Patch Rejection");
            return res.status(200).json({ success: true });
        }

        // ─── 5. REMOVE USER ───
        if (action === "delete") {
            if (!userKey) return res.status(400).json({ error: "Missing user key parameter" });
            const delRes = await fetch(`${dbBaseURL}/users/${userKey}.json`, { method: "DELETE" });
            if (!delRes.ok) throw new Error("Firebase Delete Rejection");
            return res.status(200).json({ success: true });
        }

        // ─── 6. LOGOUT (Explicit Session Invalidation) ───
        if (action === "logout") {
            await fetch(`${dbBaseURL}/sessions/${incomingToken}.json`, { method: 'DELETE' });
            return res.status(200).json({ success: true });
        }

        return res.status(400).json({ error: "Invalid Action Route" });

    } catch (error) {
        return res.status(500).json({ error: "Internal Server Fault", details: error.message });
    }
}
