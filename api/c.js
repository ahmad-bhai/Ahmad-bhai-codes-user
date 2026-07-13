// api/magic-users.js (Secure Backend Layer)
export default async function handler(req, res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');

    if (req.method === 'OPTIONS') return res.status(200).end();

    // Secure Data Storage (Invisble to the world)
    const dbURL = "https://ahmad-bhai-script-users-info-default-rtdb.firebaseio.com/users";
    const OWNER_EMAIL = "nasiriq703@gmail.com";
    const OWNER_PASS = "nasir703";
    const AUTH_TOKEN = "session_token_magic_scripts_nasir"; 

    const { action, key, userKey } = req.query;
    
    // Request checking boundary
    const incomingToken = req.headers['authorization'] || req.headers['token'] || req.query.token;
    const isAuthenticated = (incomingToken === AUTH_TOKEN);

    try {
        // 1. ROUTE: LOGIN (Bina token ke allowed hai)
        if (action === "login") {
            const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
            const email = body?.email || req.query.email;
            const password = body?.password || req.query.password;

            if (email === OWNER_EMAIL && password === OWNER_PASS) {
                return res.status(200).json({ success: true, token: AUTH_TOKEN });
            }
            return res.status(401).json({ success: false, error: "Wrong Credentials" });
        }

        // 🔥 GLOBAL SECURITY GUARD: Login ke ilawa baki sab ke liye strict token validation
        if (!isAuthenticated) {
            return res.status(403).json({ success: false, error: "Unauthorized Access Blocked By Layer" });
        }

        // 2. ROUTE: LOAD DATA
        if (action === "load") {
            const fbRes = await fetch(`${dbURL}.json`);
            const fbData = await fbRes.json();
            return res.status(200).json({ success: true, data: fbData || {} });
        }

        // 3. ROUTE: ADD USER
        if (action === "add" && req.method === "POST") {
            const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
            const saveRes = await fetch(`${dbURL}.json`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(body)
            });
            if (!saveRes.ok) throw new Error("Firebase Write Rejection");
            return res.status(200).json({ success: true });
        }

        // 4. ROUTE: REMOVE USER
        if (action === "delete") {
            if (!userKey) return res.status(400).json({ error: "Missing user key target parameter" });
            const delRes = await fetch(`${dbURL}/${userKey}.json`, { method: "DELETE" });
            if (!delRes.ok) throw new Error("Firebase Delete Rejection");
            return res.status(200).json({ success: true });
        }

        return res.status(400).json({ error: "Invalid Action Route Route Selection" });

    } catch (error) {
        return res.status(500).json({ error: "Internal Server Fault Layer", details: error.message });
    }
                                         }
