/**
 * Enhanced Authentication Service with MFA
 * 
 * SECURITY FEATURES:
 * - Multi-factor authentication (TOTP, SMS)
 * - Secure password hashing (bcrypt 12+ rounds)
 * - Session management with Redis
 * - Device fingerprinting and tracking
 * - Anomaly detection integration
 * - Account lockout protection
 * 
 * ATTACK VECTORS MITIGATED:
 * - Password-based attacks (strong hashing)
 * - Session hijacking (secure session management)
 * - Account takeover (MFA requirement)
 * - Brute force attacks (rate limiting + lockout)
 * - Credential stuffing (anomaly detection)
 * 
 * ML INTEGRATION:
 * - Login pattern analysis
 * - Device behavior monitoring
 * - Risk-based authentication
 */

const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const twilio = require('twilio');
const crypto = require('crypto');
const redis = require('redis');
const winston = require('winston');
const anomalyDetection = require('./anomalyDetection');

class AuthService {
    constructor() {
        this.bcryptRounds = 14; // High security rounds
        this.jwtExpiry = '15m'; // Short-lived tokens
        this.refreshTokenExpiry = '7d';
        this.maxLoginAttempts = 5;
        this.lockoutDuration = 15 * 60 * 1000; // 15 minutes
        
        this.initializeServices();
        this.setupLogger();
    }

    async initializeServices() {
        // Redis for session management
        this.redis = redis.createClient({ url: process.env.REDIS_URL });
        await this.redis.connect();

        // Twilio for SMS MFA
        if (process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN) {
            this.twilioClient = twilio(
                process.env.TWILIO_ACCOUNT_SID,
                process.env.TWILIO_AUTH_TOKEN
            );
        }
    }

    setupLogger() {
        this.logger = winston.createLogger({
            level: 'info',
            format: winston.format.combine(
                winston.format.timestamp(),
                winston.format.json()
            ),
            transports: [
                new winston.transports.File({ filename: 'logs/auth.log' }),
                new winston.transports.Console()
            ]
        });
    }

    /**
     * Register new user with enhanced security
     * SECURITY: Strong password validation, secure hashing, MFA setup
     */
    async registerUser(userData, deviceInfo) {
        const { username, email, password, phoneNumber } = userData;

        try {
            // Validate password strength
            const passwordValidation = this.validatePasswordStrength(password);
            if (!passwordValidation.isValid) {
                throw new Error(`Password requirements not met: ${passwordValidation.errors.join(', ')}`);
            }

            // Check for existing user
            const existingUser = await this.findUserByEmail(email);
            if (existingUser) {
                throw new Error('User already exists');
            }

            // Hash password with high rounds
            const hashedPassword = await bcrypt.hash(password, this.bcryptRounds);

            // Generate MFA secret
            const mfaSecret = speakeasy.generateSecret({
                name: `CryptoNote (${email})`,
                issuer: 'CryptoNote Password Manager',
                length: 32
            });

            // Create user record
            const user = {
                id: this.generateUserId(),
                username,
                email,
                password: hashedPassword,
                mfaSecret: mfaSecret.base32,
                mfaEnabled: false,
                phoneNumber: phoneNumber || null,
                createdAt: new Date(),
                lastLogin: null,
                failedLoginAttempts: 0,
                accountLocked: false,
                lockoutUntil: null,
                knownDevices: [],
                securitySettings: {
                    requireMFA: true,
                    sessionTimeout: 24 * 60 * 60 * 1000, // 24 hours
                    allowedIPs: [],
                    notifyOnNewDevice: true
                }
            };

            // Store user (this would integrate with your User model)
            await this.storeUser(user);

            // Generate QR code for MFA setup
            const qrCodeUrl = await QRCode.toDataURL(mfaSecret.otpauth_url);

            // Log registration event
            this.logger.info('User registered', {
                userId: user.id,
                email: user.email,
                deviceInfo
            });

            return {
                userId: user.id,
                mfaSetupRequired: true,
                qrCode: qrCodeUrl,
                backupCodes: this.generateBackupCodes()
            };

        } catch (error) {
            this.logger.error('Registration failed', {
                email,
                error: error.message
            });
            throw error;
        }
    }

    /**
     * Authenticate user with comprehensive security checks
     * SECURITY: Rate limiting, anomaly detection, MFA verification
     */
    async authenticateUser(credentials, deviceInfo, ipAddress) {
        const { email, password, mfaToken, deviceId } = credentials;

        try {
            // Check for account lockout
            const lockoutStatus = await this.checkAccountLockout(email);
            if (lockoutStatus.isLocked) {
                throw new Error(`Account locked until ${lockoutStatus.lockoutUntil}`);
            }

            // Find user
            const user = await this.findUserByEmail(email);
            if (!user) {
                await this.recordFailedAttempt(email, ipAddress, 'USER_NOT_FOUND');
                throw new Error('Invalid credentials');
            }

            // Verify password
            const passwordValid = await bcrypt.compare(password, user.password);
            if (!passwordValid) {
                await this.recordFailedAttempt(email, ipAddress, 'INVALID_PASSWORD');
                await this.incrementFailedAttempts(user.id);
                throw new Error('Invalid credentials');
            }

            // Anomaly detection analysis
            const loginData = {
                userId: user.id,
                email,
                ipAddress,
                userAgent: deviceInfo.userAgent,
                location: await this.getLocationFromIP(ipAddress),
                lastLocation: user.lastLocation,
                timeSinceLastLogin: user.lastLogin ? Date.now() - user.lastLogin.getTime() : null,
                recentFailedAttempts: user.failedLoginAttempts,
                isNewDevice: !this.isKnownDevice(user.knownDevices, deviceId),
                vpnDetected: await this.detectVPN(ipAddress),
                recentLogins: await this.getRecentLogins(user.id)
            };

            const anomalyResult = await anomalyDetection.analyzeLoginAttempt(loginData);

            // Risk-based authentication
            if (anomalyResult.riskLevel === 'critical') {
                await this.lockAccount(user.id, 'Suspicious login activity detected');
                throw new Error('Account temporarily locked due to suspicious activity');
            }

            // MFA verification (required for high-risk or if enabled)
            if (user.mfaEnabled || anomalyResult.riskLevel === 'high') {
                if (!mfaToken) {
                    return {
                        requiresMFA: true,
                        userId: user.id,
                        riskLevel: anomalyResult.riskLevel
                    };
                }

                const mfaValid = await this.verifyMFA(user.mfaSecret, mfaToken);
                if (!mfaValid) {
                    await this.recordFailedAttempt(email, ipAddress, 'INVALID_MFA');
                    throw new Error('Invalid MFA token');
                }
            }

            // Generate session tokens
            const tokens = await this.generateTokens(user);

            // Update user login info
            await this.updateLoginInfo(user.id, {
                lastLogin: new Date(),
                lastLoginIP: ipAddress,
                lastLocation: loginData.location,
                failedLoginAttempts: 0
            });

            // Store device if new
            if (loginData.isNewDevice) {
                await this.addKnownDevice(user.id, deviceInfo);
                
                if (user.securitySettings.notifyOnNewDevice) {
                    await this.sendNewDeviceNotification(user.email, deviceInfo);
                }
            }

            // Create session
            await this.createSession(user.id, tokens.sessionId, deviceInfo);

            // Log successful login
            this.logger.info('User authenticated', {
                userId: user.id,
                email: user.email,
                riskLevel: anomalyResult.riskLevel,
                mfaUsed: !!mfaToken,
                newDevice: loginData.isNewDevice
            });

            return {
                success: true,
                user: this.sanitizeUser(user),
                tokens,
                riskLevel: anomalyResult.riskLevel
            };

        } catch (error) {
            this.logger.error('Authentication failed', {
                email,
                error: error.message,
                ipAddress
            });
            throw error;
        }
    }

    /**
     * Setup MFA for user account
     * SECURITY: Secure secret generation and verification
     */
    async setupMFA(userId, verificationToken, method = 'totp') {
        try {
            const user = await this.findUserById(userId);
            if (!user) {
                throw new Error('User not found');
            }

            let isValid = false;

            switch (method) {
                case 'totp':
                    isValid = speakeasy.totp.verify({
                        secret: user.mfaSecret,
                        encoding: 'base32',
                        token: verificationToken,
                        window: 2 // Allow 2 time steps tolerance
                    });
                    break;

                case 'sms':
                    isValid = await this.verifySMSToken(userId, verificationToken);
                    break;

                default:
                    throw new Error('Unsupported MFA method');
            }

            if (!isValid) {
                throw new Error('Invalid verification token');
            }

            // Enable MFA
            await this.updateUser(userId, {
                mfaEnabled: true,
                mfaMethod: method,
                mfaEnabledAt: new Date()
            });

            // Generate backup codes
            const backupCodes = this.generateBackupCodes();
            await this.storeBackupCodes(userId, backupCodes);

            this.logger.info('MFA enabled', {
                userId,
                method
            });

            return {
                success: true,
                backupCodes
            };

        } catch (error) {
            this.logger.error('MFA setup failed', {
                userId,
                error: error.message
            });
            throw error;
        }
    }

    /**
     * Verify MFA token
     * SECURITY: Time-based verification with replay protection
     */
    async verifyMFA(secret, token, userId = null) {
        try {
            // Check if token was recently used (replay protection)
            if (userId) {
                const recentTokens = await this.redis.smembers(`used_tokens:${userId}`);
                if (recentTokens.includes(token)) {
                    return false;
                }
            }

            const isValid = speakeasy.totp.verify({
                secret,
                encoding: 'base32',
                token,
                window: 2
            });

            // Store token to prevent replay
            if (isValid && userId) {
                await this.redis.sadd(`used_tokens:${userId}`, token);
                await this.redis.expire(`used_tokens:${userId}`, 300); // 5 minutes
            }

            return isValid;

        } catch (error) {
            this.logger.error('MFA verification failed', {
                userId,
                error: error.message
            });
            return false;
        }
    }

    /**
     * Send SMS MFA token
     * SECURITY: Rate limited, temporary tokens
     */
    async sendSMSToken(userId) {
        try {
            const user = await this.findUserById(userId);
            if (!user || !user.phoneNumber) {
                throw new Error('User not found or phone number not configured');
            }

            // Rate limiting for SMS
            const smsKey = `sms_rate:${userId}`;
            const recentSMS = await this.redis.get(smsKey);
            if (recentSMS) {
                throw new Error('SMS already sent, please wait before requesting another');
            }

            // Generate 6-digit token
            const token = crypto.randomInt(100000, 999999).toString();
            
            // Store token with expiry
            await this.redis.setex(`sms_token:${userId}`, 300, token); // 5 minutes
            
            // Set rate limit
            await this.redis.setex(smsKey, 60, '1'); // 1 minute rate limit

            // Send SMS
            if (this.twilioClient) {
                await this.twilioClient.messages.create({
                    body: `Your CryptoNote verification code is: ${token}`,
                    from: process.env.TWILIO_PHONE_NUMBER,
                    to: user.phoneNumber
                });
            }

            this.logger.info('SMS token sent', { userId });

            return { success: true };

        } catch (error) {
            this.logger.error('SMS token send failed', {
                userId,
                error: error.message
            });
            throw error;
        }
    }

    /**
     * Verify SMS token
     */
    async verifySMSToken(userId, token) {
        try {
            const storedToken = await this.redis.get(`sms_token:${userId}`);
            if (!storedToken || storedToken !== token) {
                return false;
            }

            // Delete token after successful verification
            await this.redis.del(`sms_token:${userId}`);
            return true;

        } catch (error) {
            this.logger.error('SMS token verification failed', {
                userId,
                error: error.message
            });
            return false;
        }
    }

    /**
     * Generate secure JWT tokens
     * SECURITY: Short-lived access tokens, secure refresh tokens
     */
    async generateTokens(user) {
        const sessionId = this.generateSessionId();
        
        const accessToken = jwt.sign(
            {
                userId: user.id,
                email: user.email,
                sessionId,
                type: 'access'
            },
            process.env.JWT_SECRET,
            { expiresIn: this.jwtExpiry }
        );

        const refreshToken = jwt.sign(
            {
                userId: user.id,
                sessionId,
                type: 'refresh'
            },
            process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET,
            { expiresIn: this.refreshTokenExpiry }
        );

        // Store refresh token
        await this.redis.setex(
            `refresh_token:${sessionId}`,
            7 * 24 * 60 * 60, // 7 days
            refreshToken
        );

        return {
            accessToken,
            refreshToken,
            sessionId,
            expiresIn: 15 * 60 // 15 minutes
        };
    }

    /**
     * Refresh access token
     * SECURITY: Validates refresh token and generates new access token
     */
    async refreshAccessToken(refreshToken) {
        try {
            const decoded = jwt.verify(
                refreshToken,
                process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET
            );

            if (decoded.type !== 'refresh') {
                throw new Error('Invalid token type');
            }

            // Check if refresh token exists in Redis
            const storedToken = await this.redis.get(`refresh_token:${decoded.sessionId}`);
            if (!storedToken || storedToken !== refreshToken) {
                throw new Error('Invalid refresh token');
            }

            // Get user
            const user = await this.findUserById(decoded.userId);
            if (!user) {
                throw new Error('User not found');
            }

            // Generate new access token
            const accessToken = jwt.sign(
                {
                    userId: user.id,
                    email: user.email,
                    sessionId: decoded.sessionId,
                    type: 'access'
                },
                process.env.JWT_SECRET,
                { expiresIn: this.jwtExpiry }
            );

            return {
                accessToken,
                expiresIn: 15 * 60
            };

        } catch (error) {
            this.logger.error('Token refresh failed', {
                error: error.message
            });
            throw error;
        }
    }

    /**
     * Logout user and invalidate session
     * SECURITY: Complete session cleanup
     */
    async logout(sessionId) {
        try {
            // Remove refresh token
            await this.redis.del(`refresh_token:${sessionId}`);
            
            // Remove session data
            await this.redis.del(`session:${sessionId}`);
            
            // Add to blacklist
            await this.redis.sadd('blacklisted_sessions', sessionId);
            await this.redis.expire('blacklisted_sessions', 7 * 24 * 60 * 60); // 7 days

            this.logger.info('User logged out', { sessionId });

        } catch (error) {
            this.logger.error('Logout failed', {
                sessionId,
                error: error.message
            });
            throw error;
        }
    }

    /**
     * Utility methods for security operations
     */
    validatePasswordStrength(password) {
        const minLength = 12;
        const errors = [];
        
        if (password.length < minLength) {
            errors.push(`Password must be at least ${minLength} characters`);
        }
        if (!/[A-Z]/.test(password)) {
            errors.push('Password must contain uppercase letters');
        }
        if (!/[a-z]/.test(password)) {
            errors.push('Password must contain lowercase letters');
        }
        if (!/\d/.test(password)) {
            errors.push('Password must contain numbers');
        }
        if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
            errors.push('Password must contain special characters');
        }

        return {
            isValid: errors.length === 0,
            errors
        };
    }

    generateBackupCodes() {
        const codes = [];
        for (let i = 0; i < 10; i++) {
            codes.push(crypto.randomBytes(4).toString('hex').toUpperCase());
        }
        return codes;
    }

    generateUserId() {
        return `user_${Date.now()}_${crypto.randomBytes(8).toString('hex')}`;
    }

    generateSessionId() {
        return `session_${Date.now()}_${crypto.randomBytes(16).toString('hex')}`;
    }

    sanitizeUser(user) {
        const { password, mfaSecret, ...sanitized } = user;
        return sanitized;
    }

    // Additional methods would be implemented here for:
    // - Database operations (findUserByEmail, storeUser, etc.)
    // - Device management
    // - Account lockout logic
    // - Location services
    // - VPN detection
    // - Session management
    // (Truncated for brevity)
}

module.exports = new AuthService();
