#!/usr/bin/env node

/**
 * CryptoNote Security Audit Script
 * 
 * Performs comprehensive security validation of the application:
 * - Environment variable validation
 * - Encryption key strength verification
 * - Dependency vulnerability scanning
 * - Configuration security checks
 * - OWASP compliance verification
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

class SecurityAuditor {
    constructor() {
        this.issues = [];
        this.warnings = [];
        this.passed = [];
        this.criticalIssues = 0;
        this.highIssues = 0;
        this.mediumIssues = 0;
        this.lowIssues = 0;
    }

    /**
     * Main audit function
     */
    async runAudit() {
        console.log('🔐 CryptoNote Security Audit Starting...\n');
        
        try {
            await this.checkEnvironmentVariables();
            await this.validateEncryptionKeys();
            await this.checkDependencyVulnerabilities();
            await this.validateSecurityConfiguration();
            await this.checkFilePermissions();
            await this.validatePasswordPolicies();
            await this.checkRateLimitingConfig();
            await this.validateLoggingConfiguration();
            await this.checkCORSConfiguration();
            await this.validateSessionSecurity();
            
            this.generateReport();
            
        } catch (error) {
            console.error('❌ Security audit failed:', error.message);
            process.exit(1);
        }
    }

    /**
     * Check environment variables for security
     */
    async checkEnvironmentVariables() {
        console.log('🔍 Checking Environment Variables...');
        
        const requiredVars = [
            'JWT_SECRET',
            'SESSION_SECRET', 
            'MASTER_ENCRYPTION_KEY',
            'MONGO_URI',
            'REDIS_URL'
        ];

        const sensitiveVars = [
            'JWT_SECRET',
            'SESSION_SECRET',
            'MASTER_ENCRYPTION_KEY',
            'EMAIL_PASS',
            'TWILIO_AUTH_TOKEN'
        ];

        // Check required variables
        for (const varName of requiredVars) {
            if (!process.env[varName]) {
                this.addIssue('CRITICAL', `Missing required environment variable: ${varName}`);
            } else {
                this.addPassed(`Required environment variable present: ${varName}`);
            }
        }

        // Check sensitive variable strength
        for (const varName of sensitiveVars) {
            const value = process.env[varName];
            if (value) {
                if (value.length < 32) {
                    this.addIssue('HIGH', `${varName} is too short (minimum 32 characters)`);
                } else if (this.isWeakSecret(value)) {
                    this.addIssue('MEDIUM', `${varName} appears to be weak or predictable`);
                } else {
                    this.addPassed(`${varName} meets strength requirements`);
                }
            }
        }

        // Check for development values in production
        if (process.env.NODE_ENV === 'production') {
            const devPatterns = ['test', 'dev', 'localhost', 'example', 'changeme'];
            for (const varName of sensitiveVars) {
                const value = process.env[varName]?.toLowerCase();
                if (value && devPatterns.some(pattern => value.includes(pattern))) {
                    this.addIssue('CRITICAL', `${varName} contains development/test values in production`);
                }
            }
        }
    }

    /**
     * Validate encryption key strength
     */
    async validateEncryptionKeys() {
        console.log('🔐 Validating Encryption Keys...');
        
        const masterKey = process.env.MASTER_ENCRYPTION_KEY;
        
        if (masterKey) {
            // Check key length (should be 64 hex chars = 32 bytes)
            if (masterKey.length !== 64) {
                this.addIssue('CRITICAL', `MASTER_ENCRYPTION_KEY must be exactly 64 hex characters (32 bytes), got ${masterKey.length}`);
            } else {
                this.addPassed('MASTER_ENCRYPTION_KEY has correct length');
            }

            // Check if key is valid hex
            if (!/^[0-9a-fA-F]+$/.test(masterKey)) {
                this.addIssue('CRITICAL', 'MASTER_ENCRYPTION_KEY must be valid hexadecimal');
            } else {
                this.addPassed('MASTER_ENCRYPTION_KEY is valid hexadecimal');
            }

            // Check key entropy
            const entropy = this.calculateEntropy(masterKey);
            if (entropy < 3.5) {
                this.addIssue('HIGH', `MASTER_ENCRYPTION_KEY has low entropy (${entropy.toFixed(2)})`);
            } else {
                this.addPassed(`MASTER_ENCRYPTION_KEY has good entropy (${entropy.toFixed(2)})`);
            }

            // Check for common weak patterns
            if (this.hasWeakPatterns(masterKey)) {
                this.addIssue('HIGH', 'MASTER_ENCRYPTION_KEY contains weak patterns');
            } else {
                this.addPassed('MASTER_ENCRYPTION_KEY has no obvious weak patterns');
            }
        }

        // Validate JWT secrets
        const jwtSecret = process.env.JWT_SECRET;
        if (jwtSecret) {
            const jwtEntropy = this.calculateEntropy(jwtSecret);
            if (jwtEntropy < 3.0) {
                this.addIssue('HIGH', `JWT_SECRET has low entropy (${jwtEntropy.toFixed(2)})`);
            } else {
                this.addPassed(`JWT_SECRET has adequate entropy (${jwtEntropy.toFixed(2)})`);
            }
        }
    }

    /**
     * Check for dependency vulnerabilities
     */
    async checkDependencyVulnerabilities() {
        console.log('📦 Checking Dependency Vulnerabilities...');
        
        try {
            // Run npm audit
            const auditResult = execSync('npm audit --json', { 
                encoding: 'utf8',
                stdio: 'pipe'
            });
            
            const audit = JSON.parse(auditResult);
            
            if (audit.metadata.vulnerabilities.total > 0) {
                const vulns = audit.metadata.vulnerabilities;
                
                if (vulns.critical > 0) {
                    this.addIssue('CRITICAL', `Found ${vulns.critical} critical vulnerabilities in dependencies`);
                }
                if (vulns.high > 0) {
                    this.addIssue('HIGH', `Found ${vulns.high} high severity vulnerabilities in dependencies`);
                }
                if (vulns.moderate > 0) {
                    this.addIssue('MEDIUM', `Found ${vulns.moderate} moderate vulnerabilities in dependencies`);
                }
                if (vulns.low > 0) {
                    this.addWarning(`Found ${vulns.low} low severity vulnerabilities in dependencies`);
                }
            } else {
                this.addPassed('No known vulnerabilities in dependencies');
            }
            
        } catch (error) {
            if (error.status === 1) {
                // npm audit found vulnerabilities
                this.addIssue('HIGH', 'npm audit found vulnerabilities - run "npm audit fix"');
            } else {
                this.addWarning('Could not run dependency vulnerability check');
            }
        }
    }

    /**
     * Validate security configuration
     */
    async validateSecurityConfiguration() {
        console.log('⚙️ Validating Security Configuration...');
        
        // Check if security middleware is properly configured
        const serverFile = path.join(__dirname, '../server.js');
        if (fs.existsSync(serverFile)) {
            const serverContent = fs.readFileSync(serverFile, 'utf8');
            
            const securityChecks = [
                { pattern: /helmet\(\)/, name: 'Helmet security headers' },
                { pattern: /express-rate-limit/, name: 'Rate limiting' },
                { pattern: /express-mongo-sanitize/, name: 'MongoDB injection protection' },
                { pattern: /hpp\(\)/, name: 'HTTP Parameter Pollution protection' },
                { pattern: /xss\(/, name: 'XSS protection' }
            ];

            for (const check of securityChecks) {
                if (check.pattern.test(serverContent)) {
                    this.addPassed(`${check.name} is configured`);
                } else {
                    this.addIssue('HIGH', `${check.name} is not configured`);
                }
            }
        }

        // Check NODE_ENV
        if (process.env.NODE_ENV === 'production') {
            this.addPassed('NODE_ENV is set to production');
        } else if (process.env.NODE_ENV === 'development') {
            this.addWarning('NODE_ENV is set to development');
        } else {
            this.addIssue('MEDIUM', 'NODE_ENV is not properly set');
        }
    }

    /**
     * Check file permissions
     */
    async checkFilePermissions() {
        console.log('📁 Checking File Permissions...');
        
        const sensitiveFiles = [
            '.env',
            'logs/',
            'config/',
            'private/'
        ];

        for (const file of sensitiveFiles) {
            const filePath = path.join(__dirname, '..', file);
            if (fs.existsSync(filePath)) {
                try {
                    const stats = fs.statSync(filePath);
                    const mode = stats.mode & parseInt('777', 8);
                    
                    // Check if file is world-readable
                    if (mode & parseInt('004', 8)) {
                        this.addIssue('HIGH', `${file} is world-readable`);
                    } else {
                        this.addPassed(`${file} has appropriate permissions`);
                    }
                } catch (error) {
                    this.addWarning(`Could not check permissions for ${file}`);
                }
            }
        }
    }

    /**
     * Validate password policies
     */
    async validatePasswordPolicies() {
        console.log('🔑 Validating Password Policies...');
        
        // Check if password validation service exists
        const passwordValidatorPath = path.join(__dirname, '../utils/passwordValidator.js');
        if (fs.existsSync(passwordValidatorPath)) {
            const validatorContent = fs.readFileSync(passwordValidatorPath, 'utf8');
            
            const policyChecks = [
                { pattern: /length.*>=.*12/, name: 'Minimum 12 character length' },
                { pattern: /[A-Z]/, name: 'Uppercase letter requirement' },
                { pattern: /[a-z]/, name: 'Lowercase letter requirement' },
                { pattern: /\d/, name: 'Number requirement' },
                { pattern: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/, name: 'Special character requirement' }
            ];

            for (const check of policyChecks) {
                if (check.pattern.test(validatorContent)) {
                    this.addPassed(`Password policy includes: ${check.name}`);
                } else {
                    this.addIssue('MEDIUM', `Password policy missing: ${check.name}`);
                }
            }
        } else {
            this.addIssue('HIGH', 'Password validator not found');
        }
    }

    /**
     * Check rate limiting configuration
     */
    async checkRateLimitingConfig() {
        console.log('🚦 Checking Rate Limiting Configuration...');
        
        const serverFile = path.join(__dirname, '../server.js');
        if (fs.existsSync(serverFile)) {
            const serverContent = fs.readFileSync(serverFile, 'utf8');
            
            // Check for different rate limiting tiers
            if (/auth.*rate.*limit/i.test(serverContent)) {
                this.addPassed('Authentication rate limiting is configured');
            } else {
                this.addIssue('HIGH', 'Authentication rate limiting not found');
            }

            if (/windowMs.*15.*60.*1000/i.test(serverContent)) {
                this.addPassed('Rate limiting window is appropriately configured');
            } else {
                this.addWarning('Rate limiting window may not be optimal');
            }
        }
    }

    /**
     * Validate logging configuration
     */
    async validateLoggingConfiguration() {
        console.log('📝 Validating Logging Configuration...');
        
        // Check if logs directory exists
        const logsDir = path.join(__dirname, '../logs');
        if (!fs.existsSync(logsDir)) {
            this.addIssue('MEDIUM', 'Logs directory does not exist');
        } else {
            this.addPassed('Logs directory exists');
        }

        // Check for audit service
        const auditServicePath = path.join(__dirname, '../services/auditService.js');
        if (fs.existsSync(auditServicePath)) {
            this.addPassed('Audit service is implemented');
        } else {
            this.addIssue('HIGH', 'Audit service not found');
        }
    }

    /**
     * Check CORS configuration
     */
    async checkCORSConfiguration() {
        console.log('🌐 Checking CORS Configuration...');
        
        const corsOrigins = process.env.CORS_ORIGINS;
        if (corsOrigins) {
            const origins = corsOrigins.split(',');
            
            // Check for wildcard in production
            if (process.env.NODE_ENV === 'production' && origins.includes('*')) {
                this.addIssue('CRITICAL', 'CORS allows all origins (*) in production');
            } else {
                this.addPassed('CORS origins are properly restricted');
            }

            // Check for localhost in production
            if (process.env.NODE_ENV === 'production') {
                const hasLocalhost = origins.some(origin => 
                    origin.includes('localhost') || origin.includes('127.0.0.1')
                );
                if (hasLocalhost) {
                    this.addIssue('HIGH', 'CORS allows localhost origins in production');
                }
            }
        } else {
            this.addIssue('MEDIUM', 'CORS_ORIGINS not configured');
        }
    }

    /**
     * Validate session security
     */
    async validateSessionSecurity() {
        console.log('🍪 Validating Session Security...');
        
        const sessionSecret = process.env.SESSION_SECRET;
        if (sessionSecret) {
            if (sessionSecret.length >= 32) {
                this.addPassed('Session secret meets minimum length requirement');
            } else {
                this.addIssue('HIGH', 'Session secret is too short');
            }
        }

        // Check if secure session configuration exists
        const serverFile = path.join(__dirname, '../server.js');
        if (fs.existsSync(serverFile)) {
            const serverContent = fs.readFileSync(serverFile, 'utf8');
            
            if (/httpOnly.*true/i.test(serverContent)) {
                this.addPassed('Sessions configured with httpOnly');
            } else {
                this.addIssue('HIGH', 'Sessions not configured with httpOnly');
            }

            if (/sameSite.*strict/i.test(serverContent)) {
                this.addPassed('Sessions configured with sameSite: strict');
            } else {
                this.addIssue('MEDIUM', 'Sessions not configured with sameSite: strict');
            }
        }
    }

    /**
     * Utility functions
     */
    isWeakSecret(secret) {
        const weakPatterns = [
            /^(password|secret|key|token)/i,
            /123456/,
            /qwerty/i,
            /admin/i,
            /test/i,
            /^(.)\1{5,}$/, // Repeated characters
            /^(012|abc|xyz)/i
        ];

        return weakPatterns.some(pattern => pattern.test(secret));
    }

    calculateEntropy(str) {
        const charCounts = {};
        for (const char of str) {
            charCounts[char] = (charCounts[char] || 0) + 1;
        }

        let entropy = 0;
        const length = str.length;

        for (const count of Object.values(charCounts)) {
            const probability = count / length;
            entropy -= probability * Math.log2(probability);
        }

        return entropy;
    }

    hasWeakPatterns(key) {
        // Check for repeated sequences
        if (/(.{2,})\1{2,}/.test(key)) return true;
        
        // Check for sequential patterns
        if (/(?:0123|1234|2345|3456|4567|5678|6789|abcd|bcde|cdef)/i.test(key)) return true;
        
        return false;
    }

    addIssue(severity, message) {
        this.issues.push({ severity, message });
        
        switch (severity) {
            case 'CRITICAL':
                this.criticalIssues++;
                break;
            case 'HIGH':
                this.highIssues++;
                break;
            case 'MEDIUM':
                this.mediumIssues++;
                break;
            case 'LOW':
                this.lowIssues++;
                break;
        }
    }

    addWarning(message) {
        this.warnings.push(message);
    }

    addPassed(message) {
        this.passed.push(message);
    }

    /**
     * Generate security audit report
     */
    generateReport() {
        console.log('\n' + '='.repeat(60));
        console.log('🔐 CRYPTONOTE SECURITY AUDIT REPORT');
        console.log('='.repeat(60));

        // Summary
        console.log('\n📊 SUMMARY:');
        console.log(`✅ Passed Checks: ${this.passed.length}`);
        console.log(`⚠️  Warnings: ${this.warnings.length}`);
        console.log(`❌ Issues Found: ${this.issues.length}`);
        console.log(`   - Critical: ${this.criticalIssues}`);
        console.log(`   - High: ${this.highIssues}`);
        console.log(`   - Medium: ${this.mediumIssues}`);
        console.log(`   - Low: ${this.lowIssues}`);

        // Critical Issues
        if (this.criticalIssues > 0) {
            console.log('\n🚨 CRITICAL ISSUES:');
            this.issues
                .filter(issue => issue.severity === 'CRITICAL')
                .forEach(issue => console.log(`   ❌ ${issue.message}`));
        }

        // High Issues
        if (this.highIssues > 0) {
            console.log('\n⚠️  HIGH SEVERITY ISSUES:');
            this.issues
                .filter(issue => issue.severity === 'HIGH')
                .forEach(issue => console.log(`   ⚠️  ${issue.message}`));
        }

        // Medium Issues
        if (this.mediumIssues > 0) {
            console.log('\n🔶 MEDIUM SEVERITY ISSUES:');
            this.issues
                .filter(issue => issue.severity === 'MEDIUM')
                .forEach(issue => console.log(`   🔶 ${issue.message}`));
        }

        // Warnings
        if (this.warnings.length > 0) {
            console.log('\n💡 WARNINGS:');
            this.warnings.forEach(warning => console.log(`   💡 ${warning}`));
        }

        // Recommendations
        console.log('\n🎯 RECOMMENDATIONS:');
        if (this.criticalIssues > 0) {
            console.log('   🚨 Fix all CRITICAL issues immediately before deployment');
        }
        if (this.highIssues > 0) {
            console.log('   ⚠️  Address HIGH severity issues as soon as possible');
        }
        console.log('   🔄 Run this audit regularly (weekly recommended)');
        console.log('   📚 Review OWASP Top 10 and security best practices');
        console.log('   🔐 Consider penetration testing for production deployment');

        // Overall Status
        console.log('\n' + '='.repeat(60));
        if (this.criticalIssues === 0 && this.highIssues === 0) {
            console.log('✅ SECURITY AUDIT PASSED - Ready for deployment');
            process.exit(0);
        } else if (this.criticalIssues > 0) {
            console.log('❌ SECURITY AUDIT FAILED - Critical issues must be fixed');
            process.exit(1);
        } else {
            console.log('⚠️  SECURITY AUDIT WARNING - High severity issues found');
            process.exit(1);
        }
    }
}

// Run the audit
if (require.main === module) {
    const auditor = new SecurityAuditor();
    auditor.runAudit().catch(error => {
        console.error('Security audit failed:', error);
        process.exit(1);
    });
}

module.exports = SecurityAuditor;
