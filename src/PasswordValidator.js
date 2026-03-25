class PasswordValidator {
  isString(password) {
    return typeof password === 'string';
  }
  
  isLengthValid(password) {
    if (!this.isString(password)) {
      return false;
    }
    
    return password.length >= 8 && password.length <= 32;
  }
  
  hasRequiredChars(password) {
    if (!this.isString(password)) {
      return false;
    }
    
    const hasUppercase = /[A-Z]/.test(password);
    const hasLowercase = /[a-z]/.test(password);
    const hasDigit = /[0-9]/.test(password);
    const hasSpecial = /[^A-Za-z0-9]/.test(password);
    
    return hasUppercase && hasLowercase && hasDigit && hasSpecial;
  }
  
  getStrength(password) {
    if (!this.isString(password) || password.length === 0) {
      return 'invalid';
    }
    
    let score = 0;
    
    if (password.length >= 8) score += 1;
    if (password.length >= 12) score += 1;
    if (/[A-Z]/.test(password)) score += 1;
    if (/[a-z]/.test(password)) score += 1;
    if (/[0-9]/.test(password)) score += 1;
    if (/[^A-Za-z0-9]/.test(password)) score += 1;
    
    if (score <= 2) return 'weak';
    if (score <= 4) return 'medium';
    return 'strong';
  }
  
  validate(password) {
    const errors = [];
    
    if (!this.isString(password)) {
      return {
        isValid: false,
        strength: 'invalid',
        errors: ['Password must be a string']
      };
    }
    
    if (password.length === 0) {
      errors.push('Password cannot be empty');
    }
    
    if (!this.isLengthValid(password)) {
      errors.push('Password length must be between 8 and 32 characters');
    }
    
    if (!/[A-Z]/.test(password)) {
      errors.push('Password must contain at least one uppercase letter');
    }
    
    if (!/[a-z]/.test(password)) {
      errors.push('Password must contain at least one lowercase letter');
    }
    
    if (!/[0-9]/.test(password)) {
      errors.push('Password must contain at least one digit');
    }
    
    if (!/[^A-Za-z0-9]/.test(password)) {
      errors.push('Password must contain at least one special character');
    }
    
    return {
      isValid: errors.length === 0,
      strength: this.getStrength(password),
      errors
    };
  }
}

module.exports = PasswordValidator;
