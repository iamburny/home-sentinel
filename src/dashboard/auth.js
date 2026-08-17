const crypto = require("crypto");

/**
 * HTTP Basic Auth middleware checking against a single fixed user/password
 * pair. Uses a constant-time comparison so response timing can't leak how
 * many characters of the password guess were correct.
 */
function basicAuth(expectedUser, expectedPassword) {
    if (!expectedPassword) {
        throw new Error("DASHBOARD_PASSWORD must be set - refusing to start without auth configured");
    }

    return (req, res, next) => {
        const header = req.headers.authorization || "";
        const [scheme, encoded] = header.split(" ");

        if (scheme === "Basic" && encoded) {
            const decoded = Buffer.from(encoded, "base64").toString("utf8");
            const separatorIndex = decoded.indexOf(":");
            const user = decoded.slice(0, separatorIndex);
            const password = decoded.slice(separatorIndex + 1);

            if (safeEqual(user, expectedUser) && safeEqual(password, expectedPassword)) {
                return next();
            }
        }

        res.set("WWW-Authenticate", 'Basic realm="home-sentinel"');
        res.status(401).send("Authentication required");
    };
}

function safeEqual(a, b) {
    const bufA = Buffer.from(String(a));
    const bufB = Buffer.from(String(b));
    // timingSafeEqual throws on length mismatch, so pad to equal length first -
    // the length check itself doesn't need to be constant-time, only the
    // actual content comparison does.
    if (bufA.length !== bufB.length) return false;
    return crypto.timingSafeEqual(bufA, bufB);
}

module.exports = { basicAuth };
