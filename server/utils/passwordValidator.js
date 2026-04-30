// Password strength validation utility

const validatePasswordStrength = (password) => {
  const errors = [];
  const warnings = [];
  let score = 0;

  // Check minimum length
  if (password.length < 8) {
    errors.push("Password must be at least 8 characters long");
  } else if (password.length >= 12) {
    score += 2;
  } else {
    score += 1;
    warnings.push("Consider using at least 12 characters for better security");
  }

  // Check for uppercase letters
  if (!/[A-Z]/.test(password)) {
    errors.push("Password must contain at least one uppercase letter");
  } else {
    score += 1;
  }

  // Check for lowercase letters
  if (!/[a-z]/.test(password)) {
    errors.push("Password must contain at least one lowercase letter");
  } else {
    score += 1;
  }

  // Check for numbers
  if (!/\d/.test(password)) {
    errors.push("Password must contain at least one number");
  } else {
    score += 1;
  }

  // Check for special characters
  if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
    errors.push("Password must contain at least one special character (!@#$%^&*()_+-=[]{}|;':\",./<>?)");
  } else {
    score += 1;
  }

  // Check for common patterns
  const commonPatterns = [
    /123456/,
    /password/i,
    /qwerty/i,
    /abc123/i,
    /admin/i,
    /letmein/i,
    /welcome/i,
    /monkey/i,
    /dragon/i,
    /master/i
  ];

  for (const pattern of commonPatterns) {
    if (pattern.test(password)) {
      warnings.push("Avoid using common words or patterns in your password");
      score -= 1;
      break;
    }
  }

  // Check for repeated characters
  if (/(.)\1{2,}/.test(password)) {
    warnings.push("Avoid repeating the same character multiple times");
    score -= 1;
  }

  // Check for sequential characters
  const hasSequential = /(?:abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz|012|123|234|345|456|567|678|789)/i.test(password);
  if (hasSequential) {
    warnings.push("Avoid using sequential characters (abc, 123, etc.)");
    score -= 1;
  }

  // Bonus points for length
  if (password.length >= 16) {
    score += 1;
  }
  if (password.length >= 20) {
    score += 1;
  }

  // Determine strength level
  let strength = 'weak';
  let strengthScore = Math.max(0, Math.min(10, score));

  if (strengthScore >= 8) {
    strength = 'very-strong';
  } else if (strengthScore >= 6) {
    strength = 'strong';
  } else if (strengthScore >= 4) {
    strength = 'medium';
  } else if (strengthScore >= 2) {
    strength = 'weak';
  } else {
    strength = 'very-weak';
  }

  // For master password, require at least 'strong'
  const isValidMasterPassword = errors.length === 0 && strengthScore >= 6;

  return {
    isValid: errors.length === 0,
    isValidMasterPassword,
    strength,
    score: strengthScore,
    maxScore: 10,
    errors,
    warnings,
    suggestions: generateSuggestions(password, errors, warnings)
  };
};

const generateSuggestions = (password, errors, warnings) => {
  const suggestions = [];

  if (password.length < 12) {
    suggestions.push("Use at least 12 characters for better security");
  }

  if (!/[A-Z]/.test(password) || !/[a-z]/.test(password)) {
    suggestions.push("Mix uppercase and lowercase letters");
  }

  if (!/\d/.test(password)) {
    suggestions.push("Include numbers in your password");
  }

  if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
    suggestions.push("Add special characters like !@#$%^&*");
  }

  if (errors.length === 0 && warnings.length > 0) {
    suggestions.push("Consider using a passphrase with random words");
    suggestions.push("Avoid personal information like names or dates");
  }

  return suggestions;
};

// Check if password meets minimum requirements for master password
const isStrongMasterPassword = (password) => {
  const validation = validatePasswordStrength(password);
  return validation.isValidMasterPassword;
};

// Get password strength description
const getStrengthDescription = (strength) => {
  const descriptions = {
    'very-weak': 'Very Weak - This password is easily guessable',
    'weak': 'Weak - This password could be cracked quickly',
    'medium': 'Medium - This password is okay but could be stronger',
    'strong': 'Strong - This is a good password',
    'very-strong': 'Very Strong - Excellent password security'
  };
  return descriptions[strength] || 'Unknown';
};

// Get strength color for UI
const getStrengthColor = (strength) => {
  const colors = {
    'very-weak': '#f44336',
    'weak': '#ff9800',
    'medium': '#ffeb3b',
    'strong': '#4caf50',
    'very-strong': '#2e7d32'
  };
  return colors[strength] || '#9e9e9e';
};

module.exports = {
  validatePasswordStrength,
  isStrongMasterPassword,
  getStrengthDescription,
  getStrengthColor
};
