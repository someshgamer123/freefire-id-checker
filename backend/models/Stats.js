const mongoose = require('mongoose');

const StatsSchema = new mongoose.Schema({
    // Total (Lifetime)
    totalVisitors: {
        type: Number,
        default: 0
    },
    totalClaims: {
        type: Number,
        default: 0
    },
    // Daily (For 24h, 48h, 7 days)
    dailyVisitors: {
        type: Map,
        of: Number,
        default: {}
    },
    dailyClaims: {
        type: Map,
        of: Number,
        default: {}
    },
    // Hourly (For detailed 24h graph - 24 slots)
    hourlyVisitors: {
        type: Map,
        of: Number,
        default: {}
    },
    hourlyClaims: {
        type: Map,
        of: Number,
        default: {}
    },
    // Unique (Fingerprint based)
    uniqueVisitors: {
        type: Map,
        of: Number,
        default: {}
    },
    uniqueClaims: {
        type: Map,
        of: Number,
        default: {}
    },
    // Real-time tracking (Minute-wise for 60m, Active Now)
    minuteVisitors: {
        type: Map,
        of: Number,
        default: {}
    },
    minuteClaims: {
        type: Map,
        of: Number,
        default: {}
    },
    activeSessions: {
        type: Map,
        of: Number,
        default: {}
    },
    lastUpdated: {
        type: Date,
        default: Date.now
    }
});

module.exports = mongoose.model('Stats', StatsSchema);