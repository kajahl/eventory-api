import { Test, TestingModule } from '@nestjs/testing';
import { EmailService } from './email.service';
import { Repository } from 'typeorm';
import { JwtService } from '@nestjs/jwt';
import UserEntity from '../../entities/user.entity';
import { getRepositoryToken } from '@nestjs/typeorm';
import { BadRequestException } from '@nestjs/common';

describe('EmailService', () => {
    let service: EmailService;
    let userRepository: Repository<UserEntity>;
    let jwtService: JwtService;

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
            providers: [
                EmailService,
                {
                    provide: getRepositoryToken(UserEntity),
                    useClass: Repository,
                },
                {
                    provide: JwtService,
                    useValue: {
                        sign: jest.fn(),
                        verifyAsync: jest.fn()
                    },
                },
            ],
        }).compile();

        service = module.get<EmailService>(EmailService);
        userRepository = module.get<Repository<UserEntity>>(getRepositoryToken(UserEntity));
        jwtService = module.get<JwtService>(JwtService);
    });

    it('should be defined', () => {
        expect(service).toBeDefined();
    });

    describe('createTokenForEmailRequestChange', () => {
        it('should create a JWT token with userId and email', async () => {
            const userId = '123';
            const email = 'test@example.com';
            jest.spyOn(jwtService, 'sign').mockReturnValue('mockToken');

            const token = await service.createTokenForEmailRequestChange(userId, email);

            expect(jwtService.sign).toHaveBeenCalledWith({ userId, email });
            expect(token).toBe('mockToken');
        });
    });

    describe('isEmailTaken', () => {
        it('should return true if email is already taken', async () => {
            const email = 'test@example.com';
            jest.spyOn(userRepository, 'findOne').mockResolvedValue({ email } as UserEntity);

            const result = await service.isEmailTaken(email);

            expect(userRepository.findOne).toHaveBeenCalledWith({
                where: { email },
            });
            expect(result).toBe(true);
        });

        it('should return false if email is not taken', async () => {
            const email = 'test@example.com';
            jest.spyOn(userRepository, 'findOne').mockResolvedValue(null);

            const result = await service.isEmailTaken(email);

            expect(userRepository.findOne).toHaveBeenCalledWith({
                where: { email },
            });
            expect(result).toBe(false);
        });
    });

    describe('hasUserRequestedEmailChange', () => {
        it('should return true if user has requested an email change', async () => {
            const userId = '123';
            const user = { id: userId, pendingEmail: 'new@example.com', email: 'old@example.com' } as UserEntity;
            jest.spyOn(userRepository, 'findOne').mockResolvedValue(user);

            const result = await service.hasUserRequestedEmailChange(userId);

            expect(userRepository.findOne).toHaveBeenCalledWith({ where: { id: userId } });
            expect(result).toBe(true);
        });

        it('should return false if user has not requested an email change', async () => {
            const userId = '123';
            const user = { id: userId, pendingEmail: undefined, email: 'old@example.com' } as UserEntity;
            jest.spyOn(userRepository, 'findOne').mockResolvedValue(user);

            const result = await service.hasUserRequestedEmailChange(userId);

            expect(userRepository.findOne).toHaveBeenCalledWith({ where: { id: userId } });
            expect(result).toBe(false);
        });
    });

    describe('hasUserVerifiedEmail', () => {
        it('should return true if user has verified their email', async () => {
            const userId = '123';
            const user = { id: userId, email: 'new@example.com', pendingEmail: undefined } as UserEntity;
            jest.spyOn(userRepository, 'findOne').mockResolvedValue(user);
            const result = await service.hasUserVerifiedEmail(userId);

            expect(userRepository.findOne).toHaveBeenCalledWith({ where: { id: userId } });
            expect(result).toBe(true);
        });

        it('should return false if user has not verified their first email', async () => {
            const userId = '123';
            const user = { id: userId, email: 'new@example.com', pendingEmail: 'new@example.com' } as UserEntity;
            jest.spyOn(userRepository, 'findOne').mockResolvedValue(user);
            const result = await service.hasUserVerifiedEmail(userId);
            expect(userRepository.findOne).toHaveBeenCalledWith({ where: { id: userId } });
            expect(result).toBe(false);
        });

        it('should return true even if user requested change - first email is verified', async () => {
            const userId = '123';
            const user = { id: userId, email: 'old@example.com', pendingEmail: 'new@example.com' } as UserEntity;
            jest.spyOn(userRepository, 'findOne').mockResolvedValue(user);
            const result = await service.hasUserVerifiedEmail(userId);
            expect(userRepository.findOne).toHaveBeenCalledWith({ where: { id: userId } });
            expect(result).toBe(true);
        });
    });

    describe('verifyEmail', () => {
        it('should throw BadRequestException if token is invalid', async () => {
            const email = 'new@example.com';
            const confirmToken = 'invalidToken';

            jest.spyOn(jwtService, 'verifyAsync').mockRejectedValue(new Error('Invalid token'));

            await expect(service.verifyEmail(email, confirmToken)).rejects.toThrow(BadRequestException);

            expect(jwtService.verifyAsync).toHaveBeenCalledWith(confirmToken, { secret: process.env.JWT_SECRET });
        });

        it('should return false if user is not found', async () => {
            const email = 'new@example.com';
            const confirmToken = 'mockToken';

            jest.spyOn(jwtService, 'verifyAsync').mockResolvedValue({ userId: '123', email: 'new@example.com' });
            jest.spyOn(userRepository, 'findOne').mockResolvedValue(null);

            const result = await service.verifyEmail(email, confirmToken);

            expect(jwtService.verifyAsync).toHaveBeenCalledWith(confirmToken, { secret: process.env.JWT_SECRET });
            expect(userRepository.findOne).toHaveBeenCalledWith({
                where: { pendingEmail: email, pendingEmailToken: confirmToken },
            });
            expect(result).toBe(false);
        });

        it('should throw BadRequestException if email is already taken', async () => {
            const email = 'new@example.com';
            const confirmToken = 'mockToken';
            const user = {
                email: 'old@example.com',
                pendingEmail: email,
                pendingEmailToken: confirmToken,
            } as UserEntity;

            jest.spyOn(jwtService, 'verifyAsync').mockResolvedValue({ userId: '123', email: 'new@example.com' });
            jest.spyOn(userRepository, 'findOne').mockResolvedValue(user);
            jest.spyOn(service, 'isEmailTaken').mockResolvedValue(true);
            jest.spyOn(userRepository, 'save').mockResolvedValue(user);

            await expect(service.verifyEmail(email, confirmToken)).rejects.toThrow(BadRequestException);

            expect(jwtService.verifyAsync).toHaveBeenCalledWith(confirmToken, { secret: process.env.JWT_SECRET });
            expect(userRepository.findOne).toHaveBeenCalledWith({
                where: { pendingEmail: email, pendingEmailToken: confirmToken },
            });
            expect(service.isEmailTaken).toHaveBeenCalledWith(email);
            expect(userRepository.save).toHaveBeenCalledWith({
                ...user,
                pendingEmail: undefined,
                pendingEmailToken: undefined,
            });
        });

        it('should verify email and update user entity if token and email are valid', async () => {
            const email = 'new@example.com';
            const confirmToken = 'mockToken';
            const user = {
                email: 'old@example.com',
                pendingEmail: email,
                pendingEmailToken: confirmToken,
            } as UserEntity;

            jest.spyOn(jwtService, 'verifyAsync').mockResolvedValue({ userId: '123', email: 'new@example.com' });
            jest.spyOn(userRepository, 'findOne').mockResolvedValue(user);
            jest.spyOn(service, 'isEmailTaken').mockResolvedValue(false);
            jest.spyOn(userRepository, 'save').mockResolvedValue(user);

            const result = await service.verifyEmail(email, confirmToken);

            expect(jwtService.verifyAsync).toHaveBeenCalledWith(confirmToken, { secret: process.env.JWT_SECRET });
            expect(userRepository.findOne).toHaveBeenCalledWith({
                where: { pendingEmail: email, pendingEmailToken: confirmToken },
            });
            expect(userRepository.save).toHaveBeenCalledWith({
                ...user,
                email,
                pendingEmail: undefined,
                pendingEmailToken: undefined,
            });
            expect(result).toBe(true);
        });
    });

    describe('setAndGetPendingEmailToken', () => {
        it('should set pending email and token for the user', async () => {
            const user = { id: '123', email: 'old@example.com' } as UserEntity;
            const newEmail = 'new@example.com';
            jest.spyOn(service, 'createTokenForEmailRequestChange').mockResolvedValue('mockToken');
            jest.spyOn(userRepository, 'save').mockResolvedValue(user);

            const token = await service.setAndGetPendingEmailToken(user, newEmail);

            expect(service.createTokenForEmailRequestChange).toHaveBeenCalledWith(user.id, newEmail);
            expect(userRepository.save).toHaveBeenCalledWith({
                ...user,
                email: user.email,
                pendingEmail: newEmail,
                pendingEmailToken: 'mockToken',
            });
            expect(token).toBe('mockToken');
        });

        it('should change first email if overrideFirstEmail is set true', async () => {
            const user = { id: '123', email: 'old@example.com' } as UserEntity;
            const newEmail = 'new@example.com';
            jest.spyOn(service, 'createTokenForEmailRequestChange').mockResolvedValue('mockToken');
            jest.spyOn(userRepository, 'save').mockResolvedValue(user);

            const token = await service.setAndGetPendingEmailToken(user, newEmail, true);

            expect(service.createTokenForEmailRequestChange).toHaveBeenCalledWith(user.id, newEmail);
            expect(userRepository.save).toHaveBeenCalledWith({
                ...user,
                email: newEmail,
                pendingEmail: newEmail,
                pendingEmailToken: 'mockToken',
            });
            expect(token).toBe('mockToken');
        });
    });

    describe('requestEmailChange', () => {
        it('should return false if user not found', async () => {
            const userId = '123';
            jest.spyOn(userRepository, 'findOne').mockResolvedValue(null);
            const result = await service.requestEmailChange(userId, 'any');
            expect(userRepository.findOne).toHaveBeenCalledWith({ where: { id: userId } });
            expect(result).toBe(false);
        });

        it('should throw BadRequestException if user want to change email to the same email', async () => {
            const userId = '123';
            const user = { id: userId, email: 'old@example.com' } as UserEntity;
            const newEmail = 'old@example.com';
            jest.spyOn(userRepository, 'findOne').mockResolvedValue(user);

            await expect(service.requestEmailChange(userId, newEmail)).rejects.toThrow(BadRequestException);
            expect(userRepository.findOne).toHaveBeenCalledWith({ where: { id: userId } });
        });

        it('should throw BadRequestException if user want to change first email which is already used', async () => {
            const userId = '123';
            const user = { id: userId, email: 'old@example.com' } as UserEntity;
            const newEmail = 'old@example.com';
            jest.spyOn(userRepository, 'findOne').mockResolvedValue(user);
            jest.spyOn(service, 'isEmailTaken').mockResolvedValue(true);

            await expect(service.requestEmailChange(userId, newEmail)).rejects.toThrow(BadRequestException);
            expect(userRepository.findOne).toHaveBeenCalledWith({ where: { id: userId } });
        });

        it('should return true if user want to change first email which is not used', async () => {
            const userId = '123';
            const firstEmail = 'first@example.com';
            const user = { id: userId, email: firstEmail, pendingEmail: firstEmail } as UserEntity;
            const newEmail = 'new@example.com';
            jest.spyOn(userRepository, 'findOne').mockResolvedValue(user);
            jest.spyOn(service, 'isEmailTaken').mockResolvedValue(false);
            jest.spyOn(service, 'setAndGetPendingEmailToken').mockResolvedValue('mockToken');

            await expect(service.requestEmailChange(userId, newEmail)).resolves.toBe(true)
            expect(userRepository.findOne).toHaveBeenCalledWith({ where: { id: userId } });
            expect(service.isEmailTaken).toHaveBeenCalledWith(newEmail);
            expect(service.setAndGetPendingEmailToken).toHaveBeenCalledWith(user, newEmail, true);
        });

        it('should return true if user want to change email which is not used with active pending email', async () => {
            const userId = '123';
            const user = { id: userId, email: 'old@example.com', pendingEmail: 'pending@example.com' } as UserEntity;
            const newEmail = 'new@example.com';
            jest.spyOn(userRepository, 'findOne').mockResolvedValue(user);
            jest.spyOn(service, 'isEmailTaken').mockResolvedValue(false);
            jest.spyOn(service, 'setAndGetPendingEmailToken').mockResolvedValue('mockToken');

            await expect(service.requestEmailChange(userId, newEmail)).resolves.toBe(true)
            expect(userRepository.findOne).toHaveBeenCalledWith({ where: { id: userId } });
            expect(service.setAndGetPendingEmailToken).toHaveBeenCalledWith(user, newEmail, false);
        });
    })
});
