const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const csrf = require('csurf');
const cookieParser = require('cookie-parser');
const nodemailer = require('nodemailer');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const multer = require('multer');
const axios = require('axios');
require('dotenv').config();

console.log('Environment variables loaded:', {
    emailUser: process.env.EMAIL_USER,
    emailPass: process.env.EMAIL_PASS ? '[REDACTED]' : 'undefined',
    frontendUrl: process.env.FRONTEND_URL,
    sessionSecret: process.env.SESSION_SECRET ? '[REDACTED]' : 'undefined',
});

const app = express();
const port = process.env.PORT || 5000;

// Environment-based configuration
const isProduction = process.env.NODE_ENV === 'production';

// Multer configuration for file uploads
const storage = multer.memoryStorage();
const upload = multer({
    storage,
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        const validTypes = ['image/jpeg', 'image/png', 'application/pdf'];
        if (validTypes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('Invalid file type. Only JPEG, PNG, or PDF allowed.'));
        }
    },
}).fields([
    { name: 'idDocument', maxCount: 1 },
    { name: 'facePhoto', maxCount: 1 },
]);

// In-memory user store and verification codes (use a database in production)
const users = [];
const verificationCodes = {};
const resetCodes = {};

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.use(
    session({
        secret: process.env.SESSION_SECRET || 'a-very-secure-random-string-here-123456',
        resave: false,
        saveUninitialized: false,
        cookie: {
            secure: isProduction,
            httpOnly: true, // Changed to true for security
            maxAge: 24 * 60 * 60 * 1000,
        },
    })
);
app.use((req, res, next) => {
    console.log('Session ID:', req.sessionID, 'Path:', req.path);
    next();
});

app.use(helmet());
app.use(
    cors({
        origin: process.env.FRONTEND_URL || 'http://localhost:5000',
        credentials: true,
    })
);
app.use(csrf({ cookie: { httpOnly: true, secure: isProduction } }));

// Rate limiters
const forgotPasswordLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: { success: false, message: 'Too many requests. Please try again later.' },
});

const signupLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: { success: false, message: 'Too many signup attempts. Please try again later.' },
});

// Nodemailer configuration
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
    tls: {
        rejectUnauthorized: false, // For testing in Termux; remove in production
    },
});

// Verify email service
async function verifyTransporter() {
    try {
        await transporter.verify();
        console.log('Email service is ready at', new Date());
        return true;
    } catch (error) {
        console.error('Email service verification failed:', { error: error.message, code: error.code });
        return false;
    }
}

// Test email service on startup
verifyTransporter().then((isReady) => {
    if (isReady) {
        console.log('Email service verified successfully');
    } else {
        console.error('Email service failed to verify on startup');
    }
});

// Generate random 6-digit verification code
function generateVerificationCode() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

// Middleware to check if user is authenticated
const isAuthenticated = (req, res, next) => {
    if (!req.session.user) {
        return res.status(401).json({ success: false, message: 'Unauthorized. Please log in.' });
    }
    const user = users.find((u) => u.id === req.session.user.id);
    if (!user) {
        req.session.destroy((err) => {
            if (err) console.error('Session destroy error:', err);
        });
        return res.status(404).json({ success: false, message: 'User not found.' });
    }
    if (!user.verified || !user.identityVerified) {
        return res.status(403).json({ success: false, message: 'Account not verified. Please verify your email and identity.' });
    }
    next();
};

// Sanitize input to prevent injection
const sanitizeInput = (input) => {
    if (typeof input !== 'string') return input;
    return input.replace(/[<>"'\/]/g, '').trim();
};

// Placeholder for third-party verification service (e.g., Onfido)
async function verifyDocumentAndFace(idDocument, facePhoto, userData) {
    try {
        return { success: true, verificationId: `mock-${Date.now()}` };
    } catch (error) {
        console.error('Verification service error:', error.response ? error.response.data : error.message);
        return { success: false, message: 'Identity verification failed.' };
    }
}

// CSRF token endpoint
app.get('/api/csrf-token', (req, res) => {
    try {
        const csrfToken = req.csrfToken();
        res.json({ success: true, csrfToken });
    } catch (error) {
        console.error('CSRF token generation error:', error.stack);
        res.status(500).json({ success: false, message: 'Failed to generate CSRF token.' });
    }
});

// Test email endpoint
app.get('/api/test-email', async (req, res) => {
    try {
        const isVerified = await verifyTransporter();
        if (!isVerified) {
            return res.status(500).json({ success: false, message: 'Email service verification failed.' });
        }
        const info = await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: process.env.EMAIL_USER,
            subject: 'Test Email',
            text: 'This is a test email from your server.',
        });
        console.log('Test email sent successfully:', { messageId: info.messageId, to: process.env.EMAIL_USER });
        res.json({ success: true, message: 'Test email sent successfully.' });
    } catch (error) {
        console.error('Test email error:', { error: error.message, code: error.code, command: error.command });
        res.status(500).json({ success: false, message: `Failed to send test email: ${error.message}` });
    }
});

// Signup route
app.post('/api/signup', signupLimiter, upload, async (req, res) => {
    try {
        const { username, email, password } = req.body;
        const { idDocument, facePhoto } = req.files;
        const normalizedEmail = email.toLowerCase();

        if (!username) {
            return res.status(400).json({ success: false, message: 'Username is required.' });
        }
        if (!email) {
            return res.status(400).json({ success: false, message: 'Email is required.' });
        }
        if (!password) {
            return res.status(400).json({ success: false, message: 'Password is required.' });
        }
        if (!idDocument || !idDocument[0]) {
            return res.status(400).json({ success: false, message: 'ID document is required.' });
        }
        if (!facePhoto || !facePhoto[0]) {
            return res.status(400).json({ success: false, message: 'Face photo is required.' });
        }
        if (!/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(normalizedEmail)) {
            return res.status(400).json({ success: false, message: 'Invalid email format.' });
        }
        if (password.length < 8 || !/^(?=.*[0-9])(?=.*[!@#$%^&*])[a-zA-Z0-9!@#$%^&*]{8,}$/.test(password)) {
            return res.status(400).json({ success: false, message: 'Password must be 8+ characters with a number and special character.' });
        }
        if (username.length < 3 || username.length > 20) {
            return res.status(400).json({ success: false, message: 'Username must be 3-20 characters.' });
        }
        if (users.find((u) => u.email === normalizedEmail)) {
            return res.status(400).json({ success: false, message: 'Email already exists.' });
        }
        if (users.find((u) => u.username === username)) {
            return res.status(400).json({ success: false, message: 'Username already exists.' });
        }

        const verificationResult = await verifyDocumentAndFace(idDocument[0], facePhoto[0], { username, email: normalizedEmail });
        if (!verificationResult.success) {
            return res.status(400).json({ success: false, message: verificationResult.message || 'Identity verification failed.' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const user = {
            id: users.length + 1,
            username,
            email: normalizedEmail,
            password: hashedPassword,
            verified: false,
            identityVerified: true,
            verificationId: verificationResult.verificationId,
        };
        users.push(user);

        const code = generateVerificationCode();
        verificationCodes[normalizedEmail] = code;
        let emailSent = false;
        try {
            const info = await transporter.sendMail({
                from: process.env.EMAIL_USER,
                to: normalizedEmail,
                subject: 'Verify Your Email',
                text: `Your verification code is: ${code}`,
            });
            console.log('Verification email sent successfully:', { messageId: info.messageId, to: normalizedEmail });
            emailSent = true;
        } catch (emailError) {
            console.error('Email send error:', { error: emailError.message, code: emailError.code, command: emailError.command });
        }

        req.session.user = { id: user.id, username: user.username, email: normalizedEmail };
        console.log('Signup successful:', { id: user.id, username, email: normalizedEmail, verificationId: verificationResult.verificationId });
        res.json({
            success: true,
            message: emailSent
                ? 'Signup successful. Please check your email for the verification code.'
                : 'Signup successful, but failed to send verification email. Contact support.',
            csrfToken: req.csrfToken(),
        });
    } catch (error) {
        console.error('Signup error:', { error: error.message, stack: error.stack });
        res.status(500).json({ success: false, message: 'An error occurred during signup. Please try again later.' });
    }
});

// Email verification route
app.post('/api/verify', (req, res) => {
    try {
        const { email, code } = req.body;
        const normalizedEmail = email.toLowerCase();
        if (!email) {
            return res.status(400).json({ success: false, message: 'Email is required.' });
        }
        if (!code) {
            return res.status(400).json({ success: false, message: 'Verification code is required.' });
        }
        if (verificationCodes[normalizedEmail] !== code) {
            return res.status(400).json({ success: false, message: 'Invalid or expired verification code.' });
        }

        const user = users.find((u) => u.email === normalizedEmail);
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found.' });
        }

        user.verified = true;
        delete verificationCodes[normalizedEmail];
        console.log('Email verified successfully:', { email: normalizedEmail });
        res.json({ success: true, message: 'Email verified successfully.', csrfToken: req.csrfToken() });
    } catch (error) {
        console.error('Verification error:', { error: error.message, stack: error.stack });
        res.status(500).json({ success: false, message: 'An error occurred during verification.' });
    }
});

// Login route
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const normalizedEmail = email.toLowerCase();
        if (!email) {
            return res.status(400).json({ success: false, message: 'Email is required.' });
        }
        if (!password) {
            return res.status(400).json({ success: false, message: 'Password is required.' });
        }

        const user = users.find((u) => u.email === normalizedEmail);
        if (!user) {
            return res.status(401).json({ success: false, message: 'Invalid email or password.' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ success: false, message: 'Invalid email or password.' });
        }

        if (!user.verified || !user.identityVerified) {
            return res.status(403).json({ success: false, message: 'Please verify your email and identity.' });
        }

        req.session.user = { id: user.id, username: user.username, email: normalizedEmail };
        console.log('Login successful:', { id: user.id, username: user.username, email: normalizedEmail });
        res.json({ success: true, message: 'Login successful.', csrfToken: req.csrfToken() });
    } catch (error) {
        console.error('Login error:', { error: error.message, stack: error.stack });
        res.status(500).json({ success: false, message: 'An error occurred during login.' });
    }
});

// Check authentication status
app.get('/api/check-auth', (req, res) => {
    try {
        if (!req.session.user) {
            return res.status(401).json({ success: false, isAuthenticated: false, message: 'Unauthorized. Please log in.' });
        }
        const user = users.find((u) => u.id === req.session.user.id);
        if (!user) {
            req.session.destroy((err) => {
                if (err) console.error('Session destroy error:', err);
            });
            return res.status(404).json({ success: false, isAuthenticated: false, message: 'User not found.' });
        }
        if (!user.verified || !user.identityVerified) {
            return res.status(403).json({ success: false, isAuthenticated: false, message: 'Account not verified. Please verify your email and identity.' });
        }
        res.json({ success: true, isAuthenticated: true, user: { id: user.id, username: user.username, email: user.email } });
    } catch (error) {
        console.error('Check auth error:', { error: error.message, stack: error.stack });
        res.status(500).json({ success: false, isAuthenticated: false, message: 'An error occurred while checking authentication.' });
    }
});

// Fetch user details
app.get('/api/user', isAuthenticated, (req, res) => {
    try {
        const user = users.find((u) => u.id === req.session.user.id);
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found.' });
        }
        res.json({ success: true, user: { id: user.id, username: user.username, email: user.email, verified: user.verified, identityVerified: user.identityVerified } });
    } catch (error) {
        console.error('Fetch user details error:', { error: error.message, stack: error.stack });
        res.status(500).json({ success: false, message: 'An error occurred while fetching user details.' });
    }
});

// Forgot password - Send reset code
app.post('/api/forgot-password', forgotPasswordLimiter, async (req, res) => {
    try {
        const { email } = req.body;
        const normalizedEmail = email.toLowerCase();
        if (!email) {
            return res.status(400).json({ success: false, message: 'Email is required.' });
        }

        const user = users.find((u) => u.email === normalizedEmail);
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found.' });
        }

        const code = generateVerificationCode();
        resetCodes[normalizedEmail] = { code, expires: Date.now() + 15 * 60 * 1000 };
        let emailSent = false;
        try {
            const info = await transporter.sendMail({
                from: process.env.EMAIL_USER,
                to: normalizedEmail,
                subject: 'Password Reset Verification Code',
                text: `Your password reset code is: ${code}. It expires in 15 minutes.`,
            });
            console.log('Reset code email sent successfully:', { messageId: info.messageId, to: normalizedEmail });
            emailSent = true;
        } catch (emailError) {
            console.error('Email send error:', { error: emailError.message, code: emailError.code, command: emailError.command });
        }

        res.json({
            success: true,
            message: emailSent
                ? 'Verification code sent to your email.'
                : 'Failed to send verification code, but request processed. Contact support.',
            csrfToken: req.csrfToken(),
        });
    } catch (error) {
        console.error('Forgot password error:', { error: error.message, stack: error.stack });
        res.status(500).json({ success: false, message: 'An error occurred while sending the verification code.' });
    }
});

// Reset email
app.post('/api/reset-email', isAuthenticated, async (req, res) => {
    try {
        const { email, code } = req.body;
        const normalizedEmail = email.toLowerCase();
        if (!email) {
            return res.status(400).json({ success: false, message: 'Email is required.' });
        }
        if (!code) {
            return res.status(400).json({ success: false, message: 'Verification code is required.' });
        }

        const resetData = resetCodes[normalizedEmail];
        if (!resetData || resetData.code !== code || Date.now() > resetData.expires) {
            return res.status(400).json({ success: false, message: 'Invalid or expired verification code.' });
        }

        const user = users.find((u) => u.id === req.session.user.id);
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found.' });
        }

        user.email = normalizedEmail;
        user.verified = false; // Require re-verification for new email
        delete resetCodes[normalizedEmail];

        const newCode = generateVerificationCode();
        verificationCodes[normalizedEmail] = newCode;
        let emailSent = false;
        try {
            const info = await transporter.sendMail({
                from: process.env.EMAIL_USER,
                to: normalizedEmail,
                subject: 'Verify Your New Email',
                text: `Your verification code is: ${newCode}`,
            });
            console.log('Verification email sent:', { messageId: info.messageId, to: normalizedEmail });
            emailSent = true;
        } catch (emailError) {
            console.error('Email send error:', { error: emailError.message, code: emailError.code, command: emailError.command });
        }

        console.log('Email updated successfully:', { oldEmail: req.session.user.email, newEmail: normalizedEmail });
        req.session.user.email = normalizedEmail;
        res.json({
            success: true,
            message: emailSent
                ? 'Email updated. Please verify your new email.'
                : 'Email updated, but failed to send verification email. Contact support.',
            csrfToken: req.csrfToken(),
        });
    } catch (error) {
        console.error('Email update error:', { error: error.message, stack: error.stack });
        res.status(500).json({ success: false, message: 'An error occurred while updating the email.' });
    }
});

// Reset password
app.post('/api/reset-password', isAuthenticated, async (req, res) => {
    try {
        const { email, code, newPassword, currentPassword } = req.body;
        const normalizedEmail = email.toLowerCase();
        if (!email) {
            return res.status(400).json({ success: false, message: 'Email is required.' });
        }
        if (!newPassword) {
            return res.status(400).json({ success: false, message: 'New password is required.' });
        }
        if (!currentPassword) {
            return res.status(400).json({ success: false, message: 'Current password is required.' });
        }
        if (!/^(?=.*[0-9])(?=.*[!@#$%^&*])[a-zA-Z0-9!@#$%^&*]{8,}$/.test(newPassword)) {
            return res.status(400).json({ success: false, message: 'New password must be 8+ characters with a number and special character.' });
        }

        const user = users.find((u) => u.email === normalizedEmail && u.id === req.session.user.id);
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found.' });
        }

        // Verify current password
        const passwordMatch = await bcrypt.compare(currentPassword, user.password);
        if (!passwordMatch) {
            return res.status(401).json({ success: false, message: 'Current password is incorrect.' });
        }

        // If code is provided, validate it (for non-authenticated resets)
        if (code) {
            const resetData = resetCodes[normalizedEmail];
            if (!resetData || resetData.code !== code || Date.now() > resetData.expires) {
                return res.status(400).json({ success: false, message: 'Invalid or expired verification code.' });
            }
            delete resetCodes[normalizedEmail];
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        user.password = hashedPassword;
        console.log('Password reset successful:', { email: normalizedEmail });
        res.json({ success: true, message: 'Password reset successfully.', csrfToken: req.csrfToken() });
    } catch (error) {
        console.error('Reset password error:', { error: error.message, stack: error.stack });
        res.status(500).json({ success: false, message: 'An error occurred while resetting the password.' });
    }
});

// Delete account
app.delete('/api/delete-account', isAuthenticated, async (req, res) => {
    try {
        const userIndex = users.findIndex((u) => u.id === req.session.user.id);
        if (userIndex === -1) {
            return res.status(404).json({ success: false, message: 'User not found.' });
        }

        users.splice(userIndex, 1);
        delete verificationCodes[req.session.user.email];
        delete resetCodes[req.session.user.email];

        req.session.destroy((err) => {
            if (err) {
                console.error('Session destroy error:', err);
            }
        });

        console.log('Account deleted successfully:', { email: req.session.user.email });
        res.json({ success: true, message: 'Account deleted successfully.', csrfToken: req.csrfToken() });
    } catch (error) {
        console.error('Delete account error:', { error: error.message, stack: error.stack });
        res.status(500).json({ success: false, message: 'An error occurred while deleting the account.' });
    }
});

// Logout route
app.post('/api/logout', (req, res) => {
    try {
        req.session.destroy((err) => {
            if (err) {
                console.error('Logout error:', err);
                return res.status(500).json({ success: false, message: 'Failed to log out.' });
            }
            res.json({ success: true, message: 'Logged out successfully.', csrfToken: req.csrfToken() });
        });
    } catch (error) {
        console.error('Logout error:', { error: error.message, stack: error.stack });
        res.status(500).json({ success: false, message: 'An error occurred during logout.' });
    }
});

// Update cart
app.post('/api/update-cart', isAuthenticated, (req, res) => {
    try {
        const { cart } = req.body;
        if (!Array.isArray(cart)) {
            return res.status(400).json({ success: false, message: 'Cart must be an array of items.' });
        }
        for (const item of cart) {
            if (!item.id || !item.name || typeof item.price !== 'number' || typeof item.quantity !== 'number') {
                return res.status(400).json({ success: false, message: 'Invalid cart item format.' });
            }
        }
        req.session.cart = cart;
        console.log('Cart updated:', cart);
        res.json({ success: true, message: 'Cart updated.', csrfToken: req.csrfToken() });
    } catch (error) {
        console.error('Cart update error:', { error: error.message, stack: error.stack });
        res.status(500).json({ success: false, message: 'Failed to update cart.' });
    }
});

// Get total price and cart items
app.get('/api/total-price', isAuthenticated, async (req, res) => {
    try {
        const cart = req.session.cart || [];
        if (!cart.length) {
            return res.json({ success: true, total: 0, cartItems: [] });
        }

        const total = cart.reduce((sum, item) => sum + item.price * item.quantity, 0);
        res.json({ success: true, total, cartItems: cart });
    } catch (error) {
        console.error('Total price error:', { error: error.message, stack: error.stack });
        res.status(500).json({ success: false, message: 'Failed to fetch total price.' });
    }
});

// Handle checkout
app.post('/api/checkout', isAuthenticated, async (req, res) => {
    try {
        const { cartItems, billingInfo } = req.body;
        if (!cartItems) {
            return res.status(400).json({ success: false, message: 'Cart items are required.' });
        }
        if (!billingInfo) {
            return res.status(400).json({ success: false, message: 'Billing info is required.' });
        }
        if (!billingInfo.cardname) {
            return res.status(400).json({ success: false, message: 'Cardholder name is required.' });
        }

        const sanitizedFirstname = sanitizeInput(billingInfo.firstname).toLowerCase();
        const sanitizedCardname = sanitizeInput(billingInfo.cardname).toLowerCase();

        if (sanitizedFirstname !== sanitizedCardname) {
            return res.status(400).json({ success: false, message: 'Billing full name must match the name on the card.' });
        }

        let emailSent = false;
        try {
            const total = cartItems.reduce((sum, item) => sum + item.price * item.quantity, 0);
            const info = await transporter.sendMail({
                from: process.env.EMAIL_USER,
                to: billingInfo.email.toLowerCase(),
                subject: 'Order Confirmation',
                text: `Thank you for your order! Total: P${total.toFixed(2)}`,
            });
            console.log('Checkout email sent successfully:', { messageId: info.messageId, to: billingInfo.email.toLowerCase() });
            emailSent = true;
        } catch (emailError) {
            console.error('Checkout email error:', { error: emailError.message, code: emailError.code, command: emailError.command });
        }

        req.session.cart = [];
        console.log('Checkout processed:', {
            user: req.session.user,
            cartItems,
            billingInfo: {
                ...billingInfo,
                firstname: sanitizedFirstname,
                cardname: sanitizedCardname,
            },
        });
        res.json({
            success: true,
            message: emailSent ? 'Checkout successful' : 'Checkout successful, but failed to send confirmation email.',
            csrfToken: req.csrfToken(),
        });
    } catch (error) {
        console.error('Checkout error:', { error: error.message, stack: error.stack });
        res.status(500).json({ success: false, message: 'Failed to process checkout.' });
    }
});

// Webhook for verification results (e.g., Onfido)
app.post('/api/verification-webhook', express.raw({ type: 'application/json' }), async (req, res) => {
    try {
        const payload = JSON.parse(req.body);
        const verificationId = payload.payload.resource_id;
        const status = payload.payload.result;

        const user = users.find((u) => u.verificationId === verificationId);
        if (user) {
            user.identityVerified = status === 'clear';
            console.log('Verification updated:', { email: user.email, status });
        }
        res.status(200).send('Webhook received');
    } catch (error) {
        console.error('Webhook error:', error);
        res.status(500).send('Webhook processing failed');
    }
});

// Serve frontend routes
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/accounts.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'accounts.html'));
});

// Debug users (temporary, remove in production)
app.get('/api/debug-users', (req, res) => {
    res.json(users);
});

// Error handling
app.use((err, req, res, next) => {
    if (err instanceof multer.MulterError) {
        console.error('Multer error:', err.message);
        return res.status(400).json({ success: false, message: `File upload error: ${err.message}` });
    }
    if (err.code === 'EBADCSRFTOKEN') {
        console.error('CSRF token error:', err.message, req.body, req.headers);
        return res.status(403).json({ success: false, message: 'Invalid CSRF token. Please refresh and try again.' });
    }
    console.error('Unexpected error:', { error: err.message, stack: err.stack });
    res.status(500).json({ success: false, message: 'An unexpected error occurred.' });
});

// Start the server
const server = app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
}).on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
        console.error(`Port ${port} is already in use. Trying port ${port + 1}`);
        app.listen(port + 1, () => {
            console.log(`Server running at http://localhost:${port + 1}`);
        }).on('error', (err) => {
            console.error('Server failed to start on alternative port:', err.message);
            process.exit(1);
        });
    } else {
        console.error('Server failed to start:', err.message);
        process.exit(1);
    }
});

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
    console.error('Uncaught Exception:', { error: error.message, stack: error.stack });
});