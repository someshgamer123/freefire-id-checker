const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
    passcode: {
        type: String,
        required: true,
    },
    theme: {
        type: String,
        default: 'light',
        enum: ['light', 'dark']
    },
    email: {
        type: String,
        default: ''
    },
    phone: {
        type: String,
        default: ''
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

module.exports = mongoose.model('User', UserSchema);