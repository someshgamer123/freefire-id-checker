const nodemailer = require('nodemailer');

const SENDER_EMAIL = process.env.SENDER_EMAIL;
const SENDER_APP_PASSWORD = process.env.SENDER_APP_PASSWORD;
const SENDER_NAME = process.env.SENDER_NAME || 'LinkForge Support';
const APP_NAME = 'LinkForge';
const APP_URL = process.env.APP_URL || 'http://localhost:3001';

let transporter = null;

function getTransporter() {
    if (transporter) return transporter;
    if (!SENDER_EMAIL || !SENDER_APP_PASSWORD) {
        console.warn('⚠️ Email credentials missing. Email sending disabled.');
        return null;
    }
    transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: SENDER_EMAIL,
            pass: SENDER_APP_PASSWORD.replace(/\s/g, '')
        }
    });
    return transporter;
}

// ==================== BASE TEMPLATE ====================
function wrapEmail({ title, subtitle, bodyHtml, ctaText, ctaUrl, accentColor = '#6366f1' }) {
    return `
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${title}</title>
</head>
<body style="margin:0;padding:0;background:#0a0e17;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;color:#f8fafc;">
    <table width="100%" cellpadding="0" cellspacing="0" style="background:#0a0e17;padding:30px 15px;">
        <tr>
            <td align="center">
                <table width="100%" cellpadding="0" cellspacing="0" style="max-width:560px;background:#111726;border-radius:20px;border:1px solid rgba(255,255,255,0.08);overflow:hidden;box-shadow:0 20px 50px rgba(0,0,0,0.5);">
                    
                    <!-- HEADER -->
                    <tr>
                        <td style="background:linear-gradient(135deg,${accentColor},#8b5cf6);padding:32px 24px;text-align:center;">
                            <div style="display:inline-block;width:60px;height:60px;background:rgba(255,255,255,0.2);border-radius:16px;line-height:60px;font-size:30px;margin-bottom:12px;">⚡</div>
                            <div style="font-size:24px;font-weight:900;color:#ffffff;letter-spacing:-0.5px;">${APP_NAME}</div>
                            <div style="font-size:11px;color:rgba(255,255,255,0.85);margin-top:4px;font-weight:600;text-transform:uppercase;letter-spacing:1.5px;">Creator Control Center</div>
                        </td>
                    </tr>

                    <!-- BODY -->
                    <tr>
                        <td style="padding:36px 28px 28px;">
                            <h1 style="margin:0 0 8px;font-size:22px;font-weight:800;color:#ffffff;letter-spacing:-0.3px;">${title}</h1>
                            ${subtitle ? `<p style="margin:0 0 24px;font-size:14px;color:#94a3b8;line-height:1.6;">${subtitle}</p>` : ''}
                            <div style="font-size:14px;color:#cbd5e1;line-height:1.7;">${bodyHtml}</div>
                            ${ctaText && ctaUrl ? `
                            <div style="margin-top:28px;text-align:center;">
                                <a href="${ctaUrl}" style="display:inline-block;padding:14px 32px;background:linear-gradient(135deg,${accentColor},#8b5cf6);color:#ffffff;text-decoration:none;font-weight:800;font-size:14px;border-radius:12px;letter-spacing:0.3px;box-shadow:0 8px 22px rgba(99,102,241,0.35);">${ctaText}</a>
                            </div>` : ''}
                        </td>
                    </tr>

                    <!-- FOOTER -->
                    <tr>
                        <td style="padding:20px 28px;border-top:1px solid rgba(255,255,255,0.06);background:rgba(0,0,0,0.2);text-align:center;">
                            <p style="margin:0 0 6px;font-size:11px;color:#64748b;">© ${new Date().getFullYear()} ${APP_NAME}. All rights reserved.</p>
                            <p style="margin:0;font-size:11px;color:#475569;">You're receiving this email because you signed up on ${APP_NAME}.</p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>`;
}

// ==================== SEND FUNCTION ====================
async function sendMail(to, subject, html) {
    const t = getTransporter();
    if (!t) {
        console.warn('⚠️ Cannot send email - no transporter');
        return { success: false, error: 'Email not configured' };
    }
    try {
        const info = await t.sendMail({
            from: `"${SENDER_NAME}" <${SENDER_EMAIL}>`,
            to,
            subject,
            html
        });
        console.log(`✅ Email sent to ${to}: ${info.messageId}`);
        return { success: true, messageId: info.messageId };
    } catch (err) {
        console.error(`❌ Email send failed to ${to}:`, err.message);
        return { success: false, error: err.message };
    }
}

// ==================== EMAIL TYPES ====================

// 1. OTP Email
async function sendOtpEmail(email, otp, purpose = 'signin') {
    const html = wrapEmail({
        title: '🔐 Your Verification Code',
        subtitle: `Use this OTP to ${purpose === 'signup' ? 'create your account' : 'sign in'}. Valid for 10 minutes.`,
        bodyHtml: `
            <div style="background:rgba(99,102,241,0.1);border:1px solid rgba(99,102,241,0.3);border-radius:14px;padding:24px;text-align:center;margin:20px 0;">
                <div style="font-size:11px;color:#a5b4fc;text-transform:uppercase;letter-spacing:2px;font-weight:800;margin-bottom:10px;">Your OTP Code</div>
                <div style="font-size:38px;font-weight:900;letter-spacing:10px;color:#ffffff;font-family:'Courier New',monospace;">${otp}</div>
                <div style="font-size:11px;color:#64748b;margin-top:12px;">⏱ Expires in 10 minutes</div>
            </div>
            <p style="margin:16px 0 0;font-size:13px;color:#94a3b8;">If you didn't request this code, please ignore this email.</p>
            <div style="background:rgba(245,158,11,0.1);border:1px dashed rgba(245,158,11,0.4);border-radius:10px;padding:12px;margin-top:16px;font-size:12px;color:#fcd34d;">
                ⚠️ <strong>Can't find the OTP?</strong> Check your Spam / Junk folder.
            </div>
        `,
        accentColor: '#6366f1'
    });
    return sendMail(email, `Your ${APP_NAME} OTP Code: ${otp}`, html);
}

// 2. Welcome / Account Created
async function sendWelcomeEmail(email, name) {
    const html = wrapEmail({
        title: '🎉 Welcome to LinkForge!',
        subtitle: `Hi ${name || 'there'}, your account has been created successfully.`,
        bodyHtml: `
            <p>Thank you for joining <strong>${APP_NAME}</strong>! Your account is now under review.</p>
            <div style="background:rgba(245,158,11,0.1);border:1px solid rgba(245,158,11,0.3);border-radius:12px;padding:16px;margin:20px 0;">
                <div style="font-size:13px;font-weight:800;color:#fbbf24;margin-bottom:6px;">⏳ Pending Admin Approval</div>
                <div style="font-size:13px;color:#cbd5e1;line-height:1.6;">Our team will review your account within <strong>24 hours</strong>. Once approved, you'll be able to create tracking links.</div>
            </div>
            <p style="font-size:13px;color:#94a3b8;">You'll receive another email as soon as your account is approved.</p>
        `,
        accentColor: '#10b981'
    });
    return sendMail(email, `Welcome to ${APP_NAME} — Account Created`, html);
}

// 3. Account Approved
async function sendApprovalEmail(email, name) {
    const html = wrapEmail({
        title: '✅ Your Account is Approved!',
        subtitle: `Great news ${name || ''}! You can now log in and start creating links.`,
        bodyHtml: `
            <p>Your <strong>${APP_NAME}</strong> account has been approved by the admin.</p>
            <div style="background:rgba(16,185,129,0.1);border:1px solid rgba(16,185,129,0.3);border-radius:12px;padding:16px;margin:20px 0;">
                <div style="font-size:13px;font-weight:800;color:#34d399;margin-bottom:8px;">🎁 Free Trial Activated</div>
                <div style="font-size:13px;color:#cbd5e1;line-height:1.6;">Your free trial plan is now active. Start creating your first tracking link today!</div>
            </div>
            <p style="font-size:13px;color:#94a3b8;">Click the button below to access your dashboard.</p>
        `,
        ctaText: 'Open Dashboard',
        ctaUrl: `${APP_URL}/user-dashboard`,
        accentColor: '#10b981'
    });
    return sendMail(email, `Your ${APP_NAME} Account is Approved 🎉`, html);
}

// 4. Account Rejected
async function sendRejectionEmail(email, name) {
    const html = wrapEmail({
        title: '⚠️ Account Registration Update',
        subtitle: `Hi ${name || 'there'}, we have an update regarding your account.`,
        bodyHtml: `
            <p>Unfortunately, your <strong>${APP_NAME}</strong> account registration was not approved at this time.</p>
            <p style="font-size:13px;color:#94a3b8;">If you believe this is a mistake, please contact our support team.</p>
        `,
        accentColor: '#ef4444'
    });
    return sendMail(email, `${APP_NAME} Account Update`, html);
}

// 5. Link Created
async function sendLinkCreatedEmail(email, name, linkName, linkUrl) {
    const html = wrapEmail({
        title: '🔗 New Tracking Link Created',
        subtitle: `Hi ${name || 'there'}, your new link is ready to share!`,
        bodyHtml: `
            <div style="background:#080c14;border:1px solid rgba(99,102,241,0.3);border-radius:12px;padding:16px;margin:16px 0;">
                <div style="font-size:11px;color:#a5b4fc;text-transform:uppercase;letter-spacing:1px;font-weight:700;margin-bottom:6px;">Link Name</div>
                <div style="font-size:15px;font-weight:800;color:#ffffff;margin-bottom:14px;">${linkName}</div>
                <div style="font-size:11px;color:#a5b4fc;text-transform:uppercase;letter-spacing:1px;font-weight:700;margin-bottom:6px;">Tracking URL</div>
                <div style="font-size:12px;color:#38bdf8;word-break:break-all;font-family:monospace;">${linkUrl}</div>
            </div>
            <p style="font-size:13px;color:#94a3b8;">Share this link with your audience to start tracking visits and claims.</p>
        `,
        ctaText: 'View Dashboard',
        ctaUrl: `${APP_URL}/user-dashboard`,
        accentColor: '#6366f1'
    });
    return sendMail(email, `New Link Created: ${linkName}`, html);
}

// 6. Link Expiring Soon
async function sendLinkExpiringEmail(email, name, linkName, daysLeft, expiryDate) {
    const html = wrapEmail({
        title: '⏰ Your Link is Expiring Soon',
        subtitle: `Hi ${name || 'there'}, renew your plan to keep your link active.`,
        bodyHtml: `
            <div style="background:rgba(245,158,11,0.1);border:1px solid rgba(245,158,11,0.4);border-radius:12px;padding:16px;margin:16px 0;text-align:center;">
                <div style="font-size:32px;font-weight:900;color:#fbbf24;">${daysLeft} ${daysLeft === 1 ? 'Day' : 'Days'}</div>
                <div style="font-size:12px;color:#fcd34d;margin-top:4px;font-weight:700;">Remaining</div>
            </div>
            <p><strong>Link:</strong> ${linkName}</p>
            <p><strong>Expires on:</strong> ${expiryDate}</p>
            <p style="font-size:13px;color:#94a3b8;">After expiry, your link will stop working. Renew your plan now to avoid interruption.</p>
        `,
        ctaText: 'Renew Plan',
        ctaUrl: `${APP_URL}/user-dashboard`,
        accentColor: '#f59e0b'
    });
    return sendMail(email, `⏰ Link "${linkName}" expires in ${daysLeft} days`, html);
}

// 7. Link Expired
async function sendLinkExpiredEmail(email, name, linkName) {
    const html = wrapEmail({
        title: '🔔 Your Link Has Expired',
        subtitle: `Hi ${name || 'there'}, one of your links is no longer active.`,
        bodyHtml: `
            <p><strong>Link:</strong> ${linkName}</p>
            <div style="background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.4);border-radius:12px;padding:16px;margin:16px 0;">
                <div style="font-size:13px;font-weight:800;color:#f87171;margin-bottom:6px;">❌ Link Expired</div>
                <div style="font-size:13px;color:#cbd5e1;">This link will not track any new visits or claims until renewed.</div>
            </div>
            <p style="font-size:13px;color:#94a3b8;">Renew your plan to reactivate this link.</p>
        `,
        ctaText: 'Renew Now',
        ctaUrl: `${APP_URL}/user-dashboard`,
        accentColor: '#ef4444'
    });
    return sendMail(email, `Link Expired: ${linkName}`, html);
}

// 8. Payment / Renewal Status
async function sendPaymentEmail(email, name, status, planName, amount) {
    const isApproved = status === 'approved';
    const html = wrapEmail({
        title: isApproved ? '💰 Payment Approved!' : '❌ Payment Rejected',
        subtitle: `Hi ${name || 'there'}, here's your payment update.`,
        bodyHtml: `
            <div style="background:#080c14;border:1px solid rgba(99,102,241,0.3);border-radius:12px;padding:16px;margin:16px 0;">
                <table width="100%" style="font-size:13px;color:#cbd5e1;">
                    <tr><td style="padding:6px 0;color:#94a3b8;">Plan:</td><td style="padding:6px 0;text-align:right;font-weight:700;color:#fff;">${planName}</td></tr>
                    <tr><td style="padding:6px 0;color:#94a3b8;">Amount:</td><td style="padding:6px 0;text-align:right;font-weight:700;color:#38bdf8;">₹${amount}</td></tr>
                    <tr><td style="padding:6px 0;color:#94a3b8;">Status:</td><td style="padding:6px 0;text-align:right;font-weight:800;color:${isApproved ? '#34d399' : '#f87171'};">${status.toUpperCase()}</td></tr>
                </table>
            </div>
            ${isApproved ? '<p style="font-size:13px;color:#94a3b8;">Your plan is now active. Thank you for your payment!</p>' : '<p style="font-size:13px;color:#94a3b8;">Please contact support for more details.</p>'}
        `,
        ctaText: 'View Dashboard',
        ctaUrl: `${APP_URL}/user-dashboard`,
        accentColor: isApproved ? '#10b981' : '#ef4444'
    });
    return sendMail(email, `Payment ${status === 'approved' ? 'Approved' : 'Update'} - ${planName}`, html);
}

module.exports = {
    sendOtpEmail,
    sendWelcomeEmail,
    sendApprovalEmail,
    sendRejectionEmail,
    sendLinkCreatedEmail,
    sendLinkExpiringEmail,
    sendLinkExpiredEmail,
    sendPaymentEmail,
    sendMail
};