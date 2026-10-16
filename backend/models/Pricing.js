const mongoose = require('mongoose');

const PricingSchema = new mongoose.Schema({
    // 🎯 6 Plans — Admin controls everything
    plans: {
        type: Object,
        default: {
            'free-trial': {
                name: 'Free Trial',
                durationDays: 7,
                linkLimit: 1,
                visitorLimit: 1000,
                price: 0,
                enabled: true,
                badge: '',
                features: ['1 Active Link', '1,000 Total Visitors', 'Basic Analytics', '7 Days Validity']
            },
            'basic': {
                name: 'Basic',
                durationDays: 14,
                linkLimit: 5,
                visitorLimit: 5000,
                price: 199,
                enabled: true,
                badge: '',
                features: ['5 Active Links', '5,000 Total Visitors', 'Detailed Analytics', '14 Days Validity']
            },
            'creator': {
                name: 'Creator',
                durationDays: 14,
                linkLimit: 10,
                visitorLimit: 15000,
                price: 399,
                enabled: true,
                badge: '',
                features: ['10 Active Links', '15,000 Total Visitors', 'Detailed Analytics', '14 Days Validity']
            },
            'pro': {
                name: 'Pro',
                durationDays: 30,
                linkLimit: 25,
                visitorLimit: 50000,
                price: 799,
                enabled: true,
                badge: 'POPULAR',
                features: ['25 Active Links', '50,000 Total Visitors', 'Advanced Analytics', 'Custom Link Names', '30 Days Validity']
            },
            'business': {
                name: 'Business',
                durationDays: 90,
                linkLimit: 100,
                visitorLimit: 200000,
                price: 1999,
                enabled: true,
                badge: 'SAVE 20%',
                features: ['100 Active Links', '2,00,000 Total Visitors', 'Priority Support', 'Custom Link Names', '90 Days Validity']
            },
            'enterprise-vip': {
                name: 'Enterprise VIP',
                durationDays: 365,
                linkLimit: 'unlimited',
                visitorLimit: 'unlimited',
                price: 4999,
                enabled: true,
                badge: 'BEST VALUE',
                features: ['Unlimited Links', 'Unlimited Visitors', 'VIP Support', 'Custom Everything', '1 Year Validity']
            }
        }
    },

    // 🎛️ Payment Settings
    paymentSettings: {
        method: { type: String, default: 'UPI' },
        showUpi: { type: Boolean, default: true },  // 🆕 Toggle to show/hide UPI
        details: {
            upiId: { type: String, default: 'admin@upi' },
            qrCode: { type: String, default: null },
            text: { type: String, default: '' }
        }
    },

    whatsappNumber: { type: String, default: '916372923348' },
    autoPaymentEnabled: { type: Boolean, default: false }
});

module.exports = mongoose.model('Pricing', PricingSchema);
