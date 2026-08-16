const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
    email: {
        type: String,
        required: true,
        unique: true
    },
    googleId: {
        type: String,
        default: null
    },
    name: {
        type: String,
        default: ''
    },
    picture: {
        type: String,
        default: ''
    },
    theme: {
        type: String,
        default: 'light',
        enum: ['light', 'dark']
    },
    isPrimary: {
        type: Boolean,
        default: false
    },
    primarySince: {
        type: Date,
        default: null
    },
    lastLogin: {
        type: Date,
        default: Date.now
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

module.exports = mongoose.model('User', UserSchema);