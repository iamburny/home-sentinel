const ANTHROPIC_BETA = "experimental-cc-routine-2026-04-01";
const ANTHROPIC_VERSION = "2023-06-01";

/**
 * Fires a Claude Code routine's API trigger to start a fix session.
 * `token` is scoped to this one routine only (see docs.claude.com/en/routines)
 * - it can't read anything or reach any other routine, so it's safe to hold
 * per-project in sentinel's environment. Returns the new session id/url.
 */
async function fireRoutine(routineId, token, text) {
    const res = await fetch(`https://api.anthropic.com/v1/claude_code/routines/${routineId}/fire`, {
        method: "POST",
        headers: {
            Authorization: `Bearer ${token}`,
            "anthropic-beta": ANTHROPIC_BETA,
            "anthropic-version": ANTHROPIC_VERSION,
            "Content-Type": "application/json",
        },
        body: JSON.stringify({ text }),
    });
    if (!res.ok) {
        throw new Error(`routine fire failed: ${res.status} ${await res.text()}`);
    }
    const body = await res.json();
    return { sessionId: body.claude_code_session_id, sessionUrl: body.claude_code_session_url };
}

module.exports = { fireRoutine };
