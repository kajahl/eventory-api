import { Injectable } from '@nestjs/common';
import * as bcrypt from 'bcrypt';

@Injectable()
export class PasswordService {
    constructor() {}

    /**
     * Check if the password is strong
     * @param password The password to check
     * @returns true if the password is strong, false otherwise
     */
    isPasswordStrong(password: string): boolean {
        return this.checkPasswordStrengthWithMessage(password).length === 0;
    }

    /**
     * Check the password strength and return the errors
     * @param password The password to check
     * @returns An array of error messages if the password is weak, an empty array if the password is strong
    */
    checkPasswordStrengthWithMessage(password: string): string[] {
        const errors: string[] = [];

        const minLength = 8;
        const hasUpperCase = /[A-Z]/.test(password);
        const hasLowerCase = /[a-z]/.test(password);
        const hasNumbers = /\d/.test(password);
        const hasSpecialChars = /[!@#$%^&*(),.?":{}|<>]/.test(password);

        if (password.length < minLength) errors.push('Password must be at least 8 characters long.');
        if (!hasUpperCase) errors.push('Password must contain at least one uppercase letter.');
        if (!hasLowerCase) errors.push('Password must contain at least one lowercase letter.');
        if (!hasNumbers) errors.push('Password must contain at least one number.');
        if (!hasSpecialChars) errors.push('Password must contain at least one special character.');
        return errors;
    }

    /**
     * Hash a password asynchronously
     * @param password The password to hash
     * @returns The hashed password
     */
    async hashPassword(password: string): Promise<string> {
        const saltRounds = 10; 
        return bcrypt.hash(password, saltRounds);
    }

    /**
     * Hash a password synchronously
     * @param password The password to hash
     * @returns The hashed password
     */
    hashPasswordSync(password: string): string {
        const saltRounds = 10;
        return bcrypt.hashSync(password, saltRounds);
    }

    /**
     * Compare a password with a hashed password asynchronously
     * @param password The password to compare
     * @param hashedPassword The hashed password to compare with
     * @returns true if the passwords match, false otherwise
     */
    async comparePasswords(
        password: string,
        hashedPassword: string,
    ): Promise<boolean> {
        return bcrypt.compare(password, hashedPassword);
    }

    /**
     * Compare a password with a hashed password synchronously
     * @param password The password to compare
     * @param hashedPassword The hashed password to compare with
     * @returns true if the passwords match, false otherwise
     */
    comparePasswordsSync(
        password: string,
        hashedPassword: string,
    ): boolean {
        return bcrypt.compareSync(password, hashedPassword);
    }

    /**
     * Generate a random password
     * @param length The length of the password
     * @returns A random password
     */
    generateRandomPassword(length: number): string {
        const lowercase = 'abcdefghijklmnopqrstuvwxyz';
        const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        const numbers = '0123456789';
        const specialChars = '!@#$%^&*()_+[]{}|;:,.<>?';
        const allChars = lowercase + uppercase + numbers + specialChars;
    
        if (length < 4) {
            throw new Error('Password length must be at least 4 to include all character types.');
        }
    
        // Ensure at least one character from each group
        const password = [
            lowercase[Math.floor(Math.random() * lowercase.length)],
            uppercase[Math.floor(Math.random() * uppercase.length)],
            numbers[Math.floor(Math.random() * numbers.length)],
            specialChars[Math.floor(Math.random() * specialChars.length)],
        ];
    
        // Fill the rest of the password length with random characters
        for (let i = password.length; i < length; i++) {
            password.push(allChars[Math.floor(Math.random() * allChars.length)]);
        }
    
        // Shuffle the password to randomize character positions
        return password.sort(() => Math.random() - 0.5).join('');
    }
}