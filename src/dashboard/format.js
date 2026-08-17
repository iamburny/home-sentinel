/** Formats an ISO timestamp as a short relative time, e.g. "4m ago". Returns "never" for null/undefined. */
function timeAgo(isoString) {
    if (!isoString) return "never";
    const diffMs = Date.now() - new Date(isoString).getTime();
    if (diffMs < 0) return "just now";
    const seconds = Math.floor(diffMs / 1000);
    if (seconds < 60) return `${seconds}s ago`;
    const minutes = Math.floor(seconds / 60);
    if (minutes < 60) return `${minutes}m ago`;
    const hours = Math.floor(minutes / 60);
    if (hours < 24) return `${hours}h ago`;
    const days = Math.floor(hours / 24);
    return `${days}d ago`;
}

module.exports = { timeAgo };
