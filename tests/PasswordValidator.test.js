const PasswordValidator = require('../src/PasswordValidator');

describe('PasswordValidator', () => {
  let validator;
  
  beforeEach(() => {
    validator = new PasswordValidator();
  });
  
  describe('isLengthValid', () => {
    test('returns true for password with minimum valid length (8)', () => {
      expect(validator.isLengthValid('Aa1!aaaa')).toBe(true);
    });
    
    test('returns true for password with maximum valid length (32)', () => {
      expect(validator.isLengthValid('Aa1!aaaaaaaaaaaaaaaaaaaaaaaaaaaa')).toBe(true);
    });
    
    test('returns false for password shorter than 8', () => {
      expect(validator.isLengthValid('Aa1!aaa')).toBe(false);
    });
    
    test('returns false for password longer than 32', () => {
      expect(validator.isLengthValid('Aa1!aaaaaaaaaaaaaaaaaaaaaaaaaaaaa')).toBe(false);
    });
    
    test('returns false for non-string input', () => {
      expect(validator.isLengthValid(12345678)).toBe(false);
    });
  });
  
  describe('hasRequiredChars', () => {
    test('returns true when password contains all required character types', () => {
      expect(validator.hasRequiredChars('Aa1!aaaa')).toBe(true);
    });
    
    test('returns false when password has no uppercase letters', () => {
      expect(validator.hasRequiredChars('aa1!aaaa')).toBe(false);
    });
    
    test('returns false when password has no lowercase letters', () => {
      expect(validator.hasRequiredChars('AA1!AAAA')).toBe(false);
    });
    
    test('returns false when password has no digits', () => {
      expect(validator.hasRequiredChars('Aa!aaaaa')).toBe(false);
    });
    
    test('returns false when password has no special characters', () => {
      expect(validator.hasRequiredChars('Aa1aaaaa')).toBe(false);
    });
  });
  
  describe('getStrength', () => {
    test('returns invalid for empty string', () => {
      expect(validator.getStrength('')).toBe('invalid');
    });
    
    test('returns weak for simple password', () => {
      expect(validator.getStrength('abc')).toBe('weak');
    });
    
    test('returns medium for moderately strong password', () => {
      expect(validator.getStrength('Password1')).toBe('medium');
    });
    
    test('returns strong for complex password', () => {
      expect(validator.getStrength('VeryStrongPass123!')).toBe('strong');
    });
    
    test('returns invalid for non-string input', () => {
      expect(validator.getStrength(null)).toBe('invalid');
    });
  });
  
  describe('validate', () => {
    test('returns valid result for correct password', () => {
      expect(validator.validate('Aa1!aaaa')).toEqual({
        isValid: true,
        strength: 'strong',
        errors: []
      });
    });
    
    test('returns error for empty password', () => {
      const result = validator.validate('');
      
      expect(result.isValid).toBe(false);
      expect(result.errors).toContain('Password cannot be empty');
    });
    
    test('returns error for too short password', () => {
      const result = validator.validate('Aa1!aa');
      
      expect(result.isValid).toBe(false);
      expect(result.errors).toContain(
        'Password length must be between 8 and 32 characters'
      );
    });
    
    test('returns error for password without uppercase letter', () => {
      const result = validator.validate('aa1!aaaa');
      
      expect(result.isValid).toBe(false);
      expect(result.errors).toContain(
        'Password must contain at least one uppercase letter'
      );
    });
    
    test('returns error for password without lowercase letter', () => {
      const result = validator.validate('AA1!AAAA');
      
      expect(result.isValid).toBe(false);
      expect(result.errors).toContain(
        'Password must contain at least one lowercase letter'
      );
    });
    
    test('returns error for password without digit', () => {
      const result = validator.validate('Aa!aaaaa');
      
      expect(result.isValid).toBe(false);
      expect(result.errors).toContain(
        'Password must contain at least one digit'
      );
    });
    
    test('returns error for password without special character', () => {
      const result = validator.validate('Aa1aaaaa');
      
      expect(result.isValid).toBe(false);
      expect(result.errors).toContain(
        'Password must contain at least one special character'
      );
    });
    
    test('returns invalid for non-string input', () => {
      expect(validator.validate(undefined)).toEqual({
        isValid: false,
        strength: 'invalid',
        errors: ['Password must be a string']
      });
    });
    
    test('boundary: password of length 8 is valid', () => {
      expect(validator.validate('Aa1!aaaa').isValid).toBe(true);
    });
    
    test('boundary: password of length 7 is invalid', () => {
      expect(validator.validate('Aa1!aaa').isValid).toBe(false);
    });
    
    test('boundary: password of length 32 is valid', () => {
      expect(
        validator.validate('Aa1!aaaaaaaaaaaaaaaaaaaaaaaaaaaa').isValid
      ).toBe(true);
    });
    
    test('boundary: password of length 33 is invalid', () => {
      expect(
        validator.validate('Aa1!aaaaaaaaaaaaaaaaaaaaaaaaaaaaa').isValid
      ).toBe(false);
    });
  });
});
