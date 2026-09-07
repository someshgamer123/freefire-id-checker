const mongoose = require('mongoose');

const AdminLogSchema = new mongoose.Schema({
    userId: { type: String, required: true },
    action: { type: String, required: true },
    details: { type: mongoose.Schema.Types.Mixed, default: {} },
    ip: { type: String, default: null },
    timestamp: { type: Date, default: Date.now }
});

AdminLogSchema.index({ timestamp: -1 });

module.exports = mongoose.model('AdminLog', AdminLogSchema);
