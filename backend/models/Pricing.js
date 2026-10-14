const mongoose = require('mongoose');

const PricingSchema = new mongoose.Schema({
    pricing: {
        '7days': { type: Number, default: 100 },
        '15days': { type: Number, default: 200 },
        '30days': { type: Number, default: 400 },
        '90days': { type: Number, default: 1000 },
        '1year': { type: Number, default: 3000 }
    },
    paymentSettings: {
        method: { type: String, default: 'UPI' },
        details: {
            upiId: { type: String, default: 'admin@upi' },
            qrCode: { type: String, default: null },
            text: { type: String, default: '' }
        }
    },
    whatsappNumber: {
        type: String,
        default: '916372923348'
    },
    autoPaymentEnabled: {
        type: Boolean,
        default: false
    }
});

// No unique fields — no indexes needed
module.exports = mongoose.model('Pricing', PricingSchema);
