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
        type: Object,
        default: {}
    },
    dailyClaims: {
        type: Object,
        default: {}
    },
    lastUpdated: {
        type: Date,
        default: Date.now
    }
});

// No unique fields, no duplicate indexes needed
module.exports = mongoose.model('Stats', StatsSchema);
