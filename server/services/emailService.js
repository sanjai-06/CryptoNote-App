const nodemailer = require('nodemailer');

// Create transporter (you'll need to configure this with your email provider)
const createTransporter = () => {
  // For Gmail, you'll need to use App Passwords
  // For development, you can use Ethereal Email (fake SMTP)
  return nodemailer.createTransport({
    host: process.env.EMAIL_HOST || 'smtp.ethereal.email',
    port: process.env.EMAIL_PORT || 587,
    secure: false, // true for 465, false for other ports
    auth: {
      user: process.env.EMAIL_USER || 'ethereal.user@ethereal.email',
      pass: process.env.EMAIL_PASS || 'ethereal.pass'
    }
  });
};

// Send password change notification
const sendPasswordChangeNotification = async (userEmail, username, changeType = 'updated') => {
  try {
    const transporter = createTransporter();
    
    const mailOptions = {
      from: process.env.EMAIL_FROM || '"CryptoNote Security" <security@cryptonote.com>',
      to: userEmail,
      subject: '🔐 CryptoNote - Password Security Alert',
      html: `
        <!DOCTYPE html>
        <html>
        <head>
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
            .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
            .alert { background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin: 20px 0; }
            .footer { text-align: center; margin-top: 20px; color: #666; font-size: 12px; }
            .button { display: inline-block; padding: 12px 24px; background: #667eea; color: white; text-decoration: none; border-radius: 5px; margin: 10px 0; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>🔐 CryptoNote Security Alert</h1>
            </div>
            <div class="content">
              <h2>Password ${changeType === 'created' ? 'Created' : 'Updated'}</h2>
              <p>Hello <strong>${username}</strong>,</p>
              
              <div class="alert">
                <strong>⚠️ Security Notice:</strong> A password entry was ${changeType} in your CryptoNote vault.
              </div>
              
              <p><strong>Details:</strong></p>
              <ul>
                <li><strong>Action:</strong> Password ${changeType}</li>
                <li><strong>Time:</strong> ${new Date().toLocaleString()}</li>
                <li><strong>Account:</strong> ${userEmail}</li>
              </ul>
              
              <p>If this was you, no action is needed. If you didn't make this change, please:</p>
              <ol>
                <li>Log into your CryptoNote account immediately</li>
                <li>Change your master password</li>
                <li>Review all your stored passwords</li>
                <li>Contact support if you notice any unauthorized changes</li>
              </ol>
              
              <p>
                <a href="${process.env.FRONTEND_URL || 'http://localhost:5174'}/login" class="button">
                  Access Your Vault
                </a>
              </p>
              
              <p><strong>Security Tips:</strong></p>
              <ul>
                <li>Always use a strong, unique master password</li>
                <li>Enable two-factor authentication when available</li>
                <li>Regularly review your stored passwords</li>
                <li>Never share your master password with anyone</li>
              </ul>
            </div>
            <div class="footer">
              <p>This is an automated security notification from CryptoNote.</p>
              <p>If you have questions, contact our support team.</p>
            </div>
          </div>
        </body>
        </html>
      `
    };

    const info = await transporter.sendMail(mailOptions);
    console.log('Password change notification sent:', info.messageId);
    
    // For development with Ethereal, log the preview URL
    if (process.env.NODE_ENV === 'development') {
      console.log('Preview URL: %s', nodemailer.getTestMessageUrl(info));
    }
    
    return { success: true, messageId: info.messageId };
  } catch (error) {
    console.error('Failed to send password change notification:', error);
    return { success: false, error: error.message };
  }
};

// Send master password change notification
const sendMasterPasswordChangeNotification = async (userEmail, username) => {
  try {
    const transporter = createTransporter();
    
    const mailOptions = {
      from: process.env.EMAIL_FROM || '"CryptoNote Security" <security@cryptonote.com>',
      to: userEmail,
      subject: '🚨 CryptoNote - Master Password Changed',
      html: `
        <!DOCTYPE html>
        <html>
        <head>
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background: linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
            .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
            .critical { background: #ffebee; border: 1px solid #f44336; padding: 15px; border-radius: 5px; margin: 20px 0; }
            .footer { text-align: center; margin-top: 20px; color: #666; font-size: 12px; }
            .button { display: inline-block; padding: 12px 24px; background: #f44336; color: white; text-decoration: none; border-radius: 5px; margin: 10px 0; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>🚨 Critical Security Alert</h1>
            </div>
            <div class="content">
              <h2>Master Password Changed</h2>
              <p>Hello <strong>${username}</strong>,</p>
              
              <div class="critical">
                <strong>🚨 CRITICAL:</strong> Your CryptoNote master password has been changed.
              </div>
              
              <p><strong>Change Details:</strong></p>
              <ul>
                <li><strong>Time:</strong> ${new Date().toLocaleString()}</li>
                <li><strong>Account:</strong> ${userEmail}</li>
                <li><strong>Action:</strong> Master password updated</li>
              </ul>
              
              <p><strong>If this was you:</strong> No action needed. Your account is secure.</p>
              
              <p><strong>If this was NOT you:</strong></p>
              <ol>
                <li><strong>Immediately</strong> try to log into your account</li>
                <li>If you can't access your account, contact support immediately</li>
                <li>Check for any unauthorized password changes</li>
                <li>Consider changing passwords on other accounts that may have been compromised</li>
              </ol>
              
              <p>
                <a href="${process.env.FRONTEND_URL || 'http://localhost:5174'}/login" class="button">
                  Check Your Account
                </a>
              </p>
            </div>
            <div class="footer">
              <p>This is a critical security notification from CryptoNote.</p>
              <p>Contact support immediately if you didn't make this change.</p>
            </div>
          </div>
        </body>
        </html>
      `
    };

    const info = await transporter.sendMail(mailOptions);
    console.log('Master password change notification sent:', info.messageId);
    
    if (process.env.NODE_ENV === 'development') {
      console.log('Preview URL: %s', nodemailer.getTestMessageUrl(info));
    }
    
    return { success: true, messageId: info.messageId };
  } catch (error) {
    console.error('Failed to send master password change notification:', error);
    return { success: false, error: error.message };
  }
};

module.exports = {
  sendPasswordChangeNotification,
  sendMasterPasswordChangeNotification
};
