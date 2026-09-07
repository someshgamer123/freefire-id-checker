const crypto = require('crypto');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');

class Security {
    static generate2FASecret() {
        return speakeasy.generateSecret({
            name: 'FreeFire ID Checker Admin',
            length: 20
        });
    }

    static verify2FAToken(secret, token) {
        return speakeasy.totp.verify({
            secret: secret,
            encoding: 'base32',
            token: token,
            window: 2
        });
    }

    static isIPWhitelisted(ip, whitelist) {
        if (!whitelist || whitelist === '0.0.0.0/0') return true;
        const ips = whitelist.split(',');
        for (const allowed of ips) {
            if (allowed.trim() === ip) return true;
        }
        return false;
    }
}

module.exports = Security;
