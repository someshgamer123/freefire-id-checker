const mongoose = require('mongoose');

const StatsSchema = new mongoose.Schema({
    totalVisitors: { type: Number, default: 0 },
    totalClaims: { type: Number, default: 0 },
    // Using Object instead of Map for better compatibility with MongoDB updates
    dailyVisitors: { type: Object, default: {} },
    dailyClaims: { type: Object, default: {} },
    lastUpdated: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Stats', StatsSchema);
