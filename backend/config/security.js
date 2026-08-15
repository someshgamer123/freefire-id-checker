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

    static generateBackupCodes(count = 10) {
        const codes = [];
        for (let i = 0; i < count; i++) {
            codes.push(
                Math.random().toString(36).substring(2, 8).toUpperCase() +
                '-' +
                Math.random().toString(36).substring(2, 8).toUpperCase()
            );
        }
        return codes;
    }

    static async generateQRCode(otpauthUrl) {
        try {
            return await QRCode.toDataURL(otpauthUrl);
        } catch (error) {
            console.error('QR Code generation error:', error);
            return null;
        }
    }

    static isIPWhitelisted(ip, whitelist) {
        if (!whitelist || whitelist === '0.0.0.0/0') return true;
        const ips = whitelist.split(',');
        for (const allowed of ips) {
            if (allowed.trim() === ip) return true;
            if (allowed.includes('/')) {
                const [base] = allowed.split('/');
                if (ip.startsWith(base)) return true;
            }
        }
        return false;
    }

    static generateSessionToken() {
        return crypto.randomBytes(64).toString('hex');
    }

    static getSessionExpiry(timeoutMinutes = 60) {
        return new Date(Date.now() + timeoutMinutes * 60 * 1000);
    }

    static isStrongPassword(password) {
        if (password.length < 8) return { valid: false, message: 'Must be at least 8 characters' };
        if (!/[A-Z]/.test(password)) return { valid: false, message: 'Must contain at least one uppercase letter' };
        if (!/[a-z]/.test(password)) return { valid: false, message: 'Must contain at least one lowercase letter' };
        if (!/[0-9]/.test(password)) return { valid: false, message: 'Must contain at least one number' };
        if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) return { valid: false, message: 'Must contain at least one special character' };
        return { valid: true, message: 'Strong password' };
    }
}

module.exports = Security;