const mongoose = require('mongoose');

const PricingSchema = new mongoose.Schema({
    pricing: {
        '3days': { type: Number, default: 50 },
        '7days': { type: Number, default: 100 },
        '15days': { type: Number, default: 200 },
        '1month': { type: Number, default: 500 }
    },
    paymentSettings: {
        method: { type: String, default: 'UPI' },
        details: { upiId: { type: String, default: 'admin@upi' } }
    },
    whatsappNumber: { type: String, default: '916372923348' }
});

module.exports = mongoose.model('Pricing', PricingSchema);
