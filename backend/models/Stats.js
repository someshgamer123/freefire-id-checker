const mongoose = require('mongoose');

const StatsSchema = new mongoose.Schema({
    totalVisitors: {
        type: Number,
        default: 0
    },
    totalClaims: {
        type: Number,
        default: 0
    },
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
    // Real-time tracking (Minute-wise)
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