import { Test, TestingModule } from '@nestjs/testing';
import { PasswordService } from './password.service';

describe('PasswordService', () => {
    let service: PasswordService;

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
            providers: [PasswordService],
        }).compile();

        service = module.get<PasswordService>(PasswordService);
    });

    it('should be defined', () => {
        expect(service).toBeDefined();
    });

    describe('isPasswordStrong', () => {
        it('should return true for a strong password', () => {
            const result = service.isPasswordStrong('StrongP@ssw0rd');
            expect(result).toBe(true);
        });

        it('should return false for a weak password', () => {
            const result = service.isPasswordStrong('weak');
            expect(result).toBe(false);
        });
    });

    describe('checkPasswordStrengthWithMessage', () => {
        it('should return an empty array for a strong password', () => {
            const result = service.checkPasswordStrengthWithMessage('StrongP@ssw0rd');
            expect(result).toEqual([]);
        });

        it('should return an array of errors for a weak password', () => {
            const result = service.checkPasswordStrengthWithMessage('weak');
            expect(result).toEqual(
                expect.arrayContaining([
                    'Password must be at least 8 characters long.',
                    'Password must contain at least one uppercase letter.',
                    'Password must contain at least one number.',
                    'Password must contain at least one special character.',
                ]),
            );
        });

        it('should return an array of errors for a weak password', () => {
            const result = service.checkPasswordStrengthWithMessage('WEAK');
            expect(result).toEqual(
                expect.arrayContaining([
                    'Password must be at least 8 characters long.',
                    'Password must contain at least one lowercase letter.',
                    'Password must contain at least one number.',
                    'Password must contain at least one special character.',
                ]),
            );
        });
    });

    describe('hashPassword', () => {
        it('should return a hashed password', async () => {
            const password = 'StrongP@ssw0rd';
            const hashedPassword = await service.hashPassword(password);
            expect(hashedPassword).not.toEqual(password);
            expect(hashedPassword).toMatch(/^\$2[ayb]\$.{56}$/);
        });
    });

    describe('hashPasswordSync', () => {
        it('should return a hashed password synchronously', () => {
            const password = 'StrongP@ssw0rd';
            const hashedPassword = service.hashPasswordSync(password);
            expect(hashedPassword).not.toEqual(password);
            expect(hashedPassword).toMatch(/^\$2[ayb]\$.{56}$/);
        });
    });

    describe('comparePasswords', () => {
        it('should return true for matching passwords', async () => {
            const password = 'StrongP@ssw0rd';
            const hashedPassword = await service.hashPassword(password);
            const result = await service.comparePasswords(password, hashedPassword);
            expect(result).toBe(true);
        });

        it('should return false for non-matching passwords', async () => {
            const password = 'StrongP@ssw0rd';
            const hashedPassword = await service.hashPassword('DifferentP@ssw0rd');
            const result = await service.comparePasswords(password, hashedPassword);
            expect(result).toBe(false);
        });
    });

    describe('comparePasswordsSync', () => {
        it('should return true for matching passwords synchronously', () => {
            const password = 'StrongP@ssw0rd';
            const hashedPassword = service.hashPasswordSync(password);
            const result = service.comparePasswordsSync(password, hashedPassword);
            expect(result).toBe(true);
        });

        it('should return false for non-matching passwords synchronously', () => {
            const password = 'StrongP@ssw0rd';
            const hashedPassword = service.hashPasswordSync('DifferentP@ssw0rd');
            const result = service.comparePasswordsSync(password, hashedPassword);
            expect(result).toBe(false);
        });
    });

    describe('generateRandomPassword', () => {
        it('should generate a password of the specified length', async () => {
            const length = 12;
            const password = service.generateRandomPassword(length);
            expect(password).toHaveLength(length);
        });

        it('should generate a password containing alphanumeric and special characters', async () => {
            const password = service.generateRandomPassword(12);
            expect(password).toMatch(/[a-z]/);
            expect(password).toMatch(/[A-Z]/); 
            expect(password).toMatch(/\d/); 
            expect(password).toMatch(/[!@#$%^&*(),.?":{}|<>]/);
        });
    });
});
