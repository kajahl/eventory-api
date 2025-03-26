import { Test, TestingModule } from '@nestjs/testing';
import { TokenService } from './token.service';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { RefreshTokenEntity } from '../../entities/RefreshToken.entity';
import { AccessTokenEntity } from '../../entities/AccessToken.entity';
import * as crypto from 'crypto';
import { InternalServerErrorException } from '@nestjs/common';
import { JwtPayload } from '../../types';

describe('TokenService', () => {
    let service: TokenService;
    let jwtService: JwtService;
    let configService: ConfigService;
    let refreshTokenRepository: Repository<RefreshTokenEntity>;
    let accessTokenRepository: Repository<AccessTokenEntity>;

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
            providers: [
                TokenService,
                JwtService,
                ConfigService,
                {
                    provide: getRepositoryToken(RefreshTokenEntity),
                    useClass: Repository,
                },
                {
                    provide: getRepositoryToken(AccessTokenEntity),
                    useClass: Repository,
                },
            ],
        }).compile();

        service = module.get<TokenService>(TokenService);
        jwtService = module.get<JwtService>(JwtService);
        configService = module.get<ConfigService>(ConfigService);
        refreshTokenRepository = module.get<Repository<RefreshTokenEntity>>(getRepositoryToken(RefreshTokenEntity));
        accessTokenRepository = module.get<Repository<AccessTokenEntity>>(getRepositoryToken(AccessTokenEntity));
    });

    describe('hashToken', () => {
        it('should hash the token using SHA-256', () => {
            const token = 'test-token';
            const mockUpdate = jest.fn().mockReturnThis();
            const mockDigest = jest.fn().mockReturnValue('hashed-token');

            jest.spyOn(crypto, 'createHash').mockReturnValue({
                update: mockUpdate,
                digest: mockDigest,
            } as any);

            const hashedToken = service['hashToken'](token);

            expect(crypto.createHash).toHaveBeenCalledWith('sha256');
            expect(mockUpdate).toHaveBeenCalledWith(token);
            expect(mockDigest).toHaveBeenCalledWith('hex');
            expect(hashedToken).toBe('hashed-token');
        });
    });

    describe('calculateExpirationTime', () => {
        const tolerance = 10 * 1000; // 10 seconds

        it('should calculate expiration time for minutes', () => {
            const expirationTime = '5m';
            const result = service['calculateExpirationTime'](expirationTime);

            const expected = new Date();
            expected.setMinutes(expected.getMinutes() + 5);

            const difference = Math.abs(result.getTime() - expected.getTime());
            expect(difference).toBeLessThanOrEqual(tolerance);
        });

        it('should calculate expiration time for hours', () => {
            const expirationTime = '2h';
            const result = service['calculateExpirationTime'](expirationTime);

            const expected = new Date();
            expected.setHours(expected.getHours() + 2);

            const difference = Math.abs(result.getTime() - expected.getTime());
            expect(difference).toBeLessThanOrEqual(tolerance);
        });

        it('should calculate expiration time for days', () => {
            const expirationTime = '1d';
            const result = service['calculateExpirationTime'](expirationTime);

            const expected = new Date();
            expected.setDate(expected.getDate() + 1);

            const difference = Math.abs(result.getTime() - expected.getTime());
            expect(difference).toBeLessThanOrEqual(tolerance);
        });

        it('should throw an error for invalid format', () => {
            const expirationTime = 'invalid';

            expect(() => service['calculateExpirationTime'](expirationTime)).toThrow(
                `Invalid expiration time format: ${expirationTime}`,
            );
        });

        it('should throw an error for unsupported time unit', () => {
            const expirationTime = '10x';

            expect(() => service['calculateExpirationTime'](expirationTime)).toThrow(
                `Unsupported time unit in expiration time: x`,
            );
        });
    });

    describe('generateRefreshToken', () => {
        it('should generate a refresh token and save it to the database', async () => {
            const payload = { sub: 'user-id', timestamp: Date.now() };
            const mockRefreshToken = 'mock-refresh-token';
            const mockExpiresAt = new Date();

            jest.spyOn(service['jwtService'], 'sign').mockReturnValue(mockRefreshToken);
            jest.spyOn(service as any, 'calculateExpirationTime').mockReturnValue(mockExpiresAt);
            jest.spyOn(service as any, 'saveRefreshToken').mockResolvedValue(true);

            const result = await service['generateRefreshToken'](payload);

            expect(service['jwtService'].sign).toHaveBeenCalledWith(payload, {
                secret: service.RefreshTokenSecretKey,
                expiresIn: service.RefreshTokenExpirationTime,
            });
            expect(service['calculateExpirationTime']).toHaveBeenCalledWith(service.RefreshTokenExpirationTime);
            expect(service['saveRefreshToken']).toHaveBeenCalledWith(payload.sub, mockRefreshToken, mockExpiresAt);
            expect(result).toBe(mockRefreshToken);
        });

        it('should throw an error if saving the refresh token fails', async () => {
            const payload = { sub: 'user-id', timestamp: Date.now() };
            const mockRefreshToken = 'mock-refresh-token';
            const mockExpiresAt = new Date();

            jest.spyOn(service['jwtService'], 'sign').mockReturnValue(mockRefreshToken);
            jest.spyOn(service as any, 'calculateExpirationTime').mockReturnValue(mockExpiresAt);
            jest.spyOn(service as any, 'saveRefreshToken').mockRejectedValue(
                new InternalServerErrorException('Database error'),
            );

            await expect(service['generateRefreshToken'](payload)).rejects.toThrow('Database error');
        });
    });

    describe('generateAccessToken', () => {
        it('should generate an access token based on a valid refresh token', async () => {
            const refreshToken = 'valid-refresh-token';
            const mockPayload = { sub: 'user-id', timestamp: Date.now() };
            const mockAccessToken = 'mock-access-token';
            const mockExpiresAt = new Date();
            const mockRefreshTokenEntity = { id: 1 } as any as RefreshTokenEntity;

            jest.spyOn(service['jwtService'], 'verify').mockReturnValue(mockPayload);
            jest.spyOn(service as any, 'hashToken').mockReturnValue('hashed-refresh-token');
            jest.spyOn(service as any, 'getRefreshTokenByHash').mockResolvedValue(mockRefreshTokenEntity);
            jest.spyOn(service['jwtService'], 'sign').mockReturnValue(mockAccessToken);
            jest.spyOn(service as any, 'calculateExpirationTime').mockReturnValue(mockExpiresAt);
            const saveAccessTokenSpy = jest.spyOn(service as any, 'saveAccessToken').mockResolvedValue(true);

            const result = await service['generateAccessToken'](refreshToken);

            expect(service['jwtService'].verify).toHaveBeenCalledWith(refreshToken, {
                secret: service.RefreshTokenSecretKey,
            });
            expect(service['hashToken']).toHaveBeenCalledWith(refreshToken);
            expect(service['getRefreshTokenByHash']).toHaveBeenCalledWith('hashed-refresh-token');
            expect(service['jwtService'].sign).toHaveBeenCalledWith(
                { sub: mockPayload.sub, timestamp: mockPayload.timestamp },
                { secret: service.AccessTokenSecretKey, expiresIn: service.AccessTokenExpirationTime },
            );
            expect(service['calculateExpirationTime']).toHaveBeenCalledWith(service.AccessTokenExpirationTime);
            expect(saveAccessTokenSpy).toHaveBeenCalledWith(
                mockPayload.sub,
                mockAccessToken,
                mockExpiresAt,
                mockRefreshTokenEntity,
            );
            expect(result).toBe(mockAccessToken);
        });

        it('should throw a BadRequestException if the refresh token is invalid', async () => {
            const refreshToken = 'invalid-refresh-token';

            jest.spyOn(service['jwtService'], 'verify').mockImplementation(() => {
                throw new Error('Invalid token');
            });

            await expect(service['generateAccessToken'](refreshToken)).rejects.toThrow(
                'Something went wrong while generating access token',
            );
        });

        it('should throw a BadRequestException if the refresh token does not exist in the database', async () => {
            const refreshToken = 'valid-refresh-token';
            const mockPayload = { sub: 'user-id', timestamp: Date.now() };

            jest.spyOn(service['jwtService'], 'verify').mockReturnValue(mockPayload);
            jest.spyOn(service as any, 'hashToken').mockReturnValue('hashed-refresh-token');
            jest.spyOn(service as any, 'getRefreshTokenByHash').mockResolvedValue(null);

            await expect(service['generateAccessToken'](refreshToken)).rejects.toThrow('Invalid refresh token');
        });
    });

    describe('generateTokens', () => {
        it('should generate both access and refresh tokens', async () => {
            const refreshToken = 'mock-refresh-token';
            const accessToken = 'mock-access-token';

            jest.spyOn(service as any, 'generateRefreshToken').mockResolvedValue(refreshToken);
            jest.spyOn(service as any, 'generateAccessToken').mockResolvedValue(accessToken);

            const payload: JwtPayload = { sub: 'user-id', timestamp: Date.now() };
            const result = await service.generateTokens(payload);

            expect(service['generateRefreshToken']).toHaveBeenCalledWith(payload);
            expect(service['generateAccessToken']).toHaveBeenCalledWith(refreshToken);
            expect(result).toEqual({ accessToken, refreshToken });
        });
    });

    describe('regenerateAccessToken', () => {
        it('should regenerate the access token using the refresh token', async () => {
            const refreshToken = 'mock-refresh-token';
            const refreshTokenHash = 'hashed-refresh-token';
            const accessToken = 'new-access-token';

            jest.spyOn(service as any, 'hashToken').mockReturnValue(refreshTokenHash);
            jest.spyOn(service as any, 'getRefreshTokenByHash').mockResolvedValue({
                id: 1,
            } as any as RefreshTokenEntity);
            jest.spyOn(service as any, 'generateAccessToken').mockResolvedValue(accessToken);

            const result = await service.regenerateAccessToken(refreshToken);

            expect(service['hashToken']).toHaveBeenCalledWith(refreshToken);
            expect(service['generateAccessToken']).toHaveBeenCalledWith(refreshToken);
            expect(result).toEqual(accessToken);
        });

        it('should throw an error if the refresh token is invalid', async () => {
            const refreshToken = 'mock-refresh-token';
            const refreshTokenHash = 'hashed-refresh-token';

            jest.spyOn(service as any, 'hashToken').mockReturnValue(refreshTokenHash);
            jest.spyOn(service as any, 'getRefreshTokenByHash').mockReturnValue(null);

            await expect(service.regenerateAccessToken(refreshToken)).rejects.toThrow('Invalid refresh token');
        });
    });

    describe('getAccessTokenByHash', () => {
        it('should return the access token by hash', async () => {
            const hashedToken = 'hashed-token';
            const mockAccessTokenEntity = {} as any as AccessTokenEntity;

            jest.spyOn(accessTokenRepository, 'findOne').mockResolvedValue(mockAccessTokenEntity);

            const result = await service['getAccessTokenByHash'](hashedToken);

            expect(accessTokenRepository.findOne).toHaveBeenCalledWith({
                where: { tokenHash: hashedToken },
                relations: { relatedRefreshToken: true },
            });
            expect(result).toBe(mockAccessTokenEntity);
        });

        it('should throw an error if the access token is not found', async () => {
            const hashedToken = 'hashed-token';
            jest.spyOn(accessTokenRepository, 'findOne').mockResolvedValue(null);
            await expect(service['getAccessTokenByHash'](hashedToken)).resolves.toBe(null);
        });
    });

    describe('getRefreshTokenByHash', () => {
        it('should return the refresh token by hash', async () => {
            const hashedToken = 'hashed-token';
            const mockRefreshTokenEntity = {} as any as RefreshTokenEntity;

            jest.spyOn(refreshTokenRepository, 'findOne').mockResolvedValue(mockRefreshTokenEntity);

            const result = await service['getRefreshTokenByHash'](hashedToken);

            expect(refreshTokenRepository.findOne).toHaveBeenCalledWith({
                where: { tokenHash: hashedToken },
                relations: { accessTokens: true },
            });
            expect(result).toBe(mockRefreshTokenEntity);
        });

        it('should throw an error if the refresh token is not found', async () => {
            const hashedToken = 'hashed-token';
            jest.spyOn(refreshTokenRepository, 'findOne').mockResolvedValue(null);
            await expect(service['getRefreshTokenByHash'](hashedToken)).resolves.toBe(null);
        });
    });

    describe('getUserRefreshTokens', () => {
        // TODO
    })

    describe('getRelatedRefreshTokenIdByAccessToken', () => {
        // TODO
    })

    describe('isUserOwnerOfTokenId', () => {
        // TODO
    })

    describe('saveAccessToken', () => {
        it('should save the access token to the database', async () => {
            const userId = 'user-id';
            const accessToken = 'mock-access-token';
            const expiresAt = new Date();
            const refreshTokenEntity = {} as any as RefreshTokenEntity;

            const hashedToken = 'hashed-access-token';
            jest.spyOn(service as any, 'hashToken').mockReturnValue(hashedToken);
            // TODO: mock new AccessTokenEntity() - values
            jest.spyOn(accessTokenRepository, 'save').mockResolvedValue({} as any);

            const result = await service['saveAccessToken'](userId, accessToken, expiresAt, refreshTokenEntity);

            expect(service['hashToken']).toHaveBeenCalledWith(accessToken);
            expect(accessTokenRepository.save).toHaveBeenCalled();
            expect(result).toBe(true);
        });

        it('should throw an error if saving the access token fails', async () => {
            const userId = 'user-id';
            const accessToken = 'mock-access-token';
            const expiresAt = new Date();
            const refreshTokenEntity = {} as any as RefreshTokenEntity;

            const hashedToken = 'hashed-access-token';
            jest.spyOn(service as any, 'hashToken').mockReturnValue(hashedToken);
            // TODO: mock new AccessTokenEntity() - values
            jest.spyOn(accessTokenRepository, 'save').mockRejectedValue(
                new InternalServerErrorException('Database error'),
            );

            await expect(() =>
                service['saveAccessToken'](userId, accessToken, expiresAt, refreshTokenEntity),
            ).rejects.toThrow('Something went wrong while saving access token');

            expect(service['hashToken']).toHaveBeenCalledWith(accessToken);
            expect(accessTokenRepository.save).toHaveBeenCalled();
        });
    });

    describe('saveRefreshToken', () => {
        it('should save the refresh token to the database', async () => {
            const userId = 'user-id';
            const refreshToken = 'mock-refresh-token';
            const expiresAt = new Date();

            const hashedToken = 'hashed-refresh-token';
            jest.spyOn(service as any, 'hashToken').mockReturnValue(hashedToken);
            // TODO: mock new RefreshTokenEntity() - values
            jest.spyOn(refreshTokenRepository, 'save').mockResolvedValue({} as any);

            const result = await service['saveRefreshToken'](userId, refreshToken, expiresAt);

            expect(service['hashToken']).toHaveBeenCalledWith(refreshToken);
            expect(refreshTokenRepository.save).toHaveBeenCalled();
            expect(result).toBe(true);
        });

        it('should throw an error if saving the refresh token fails', async () => {
            const userId = 'user-id';
            const refreshToken = 'mock-refresh-token';
            const expiresAt = new Date();

            const hashedToken = 'hashed-refresh-token';
            jest.spyOn(service as any, 'hashToken').mockReturnValue(hashedToken);
            // TODO: mock new RefreshTokenEntity() - values
            jest.spyOn(refreshTokenRepository, 'save').mockRejectedValue(
                new InternalServerErrorException('Database error'),
            );

            await expect(() => service['saveRefreshToken'](userId, refreshToken, expiresAt)).rejects.toThrow(
                'Something went wrong while saving refresh token',
            );

            expect(service['hashToken']).toHaveBeenCalledWith(refreshToken);
            expect(refreshTokenRepository.save).toHaveBeenCalled();
        });
    });

    describe('isAccessTokenValid', () => {
        it('should create hash and call isAccessTokenValidByHash', async () => {
            const hashedToken = 'hashed-token';
            jest.spyOn(service as any, 'hashToken').mockReturnValue(hashedToken);
            jest.spyOn(service as any, 'isAccessTokenValidByHash').mockResolvedValue(true);

            const accessToken = 'mock-access-token';
            await service.isAccessTokenValid(accessToken);

            expect(service['hashToken']).toHaveBeenCalledWith(accessToken);
            expect(service['isAccessTokenValidByHash']).toHaveBeenCalledWith(hashedToken);
        });

        it('should return true if token is valid', async () => {
            const valid = true;

            const hashedToken = 'hashed-token';
            jest.spyOn(service as any, 'hashToken').mockReturnValue(hashedToken);
            jest.spyOn(service as any, 'isAccessTokenValidByHash').mockResolvedValue(valid);

            const accessToken = 'mock-access-token';
            const result = await service.isAccessTokenValid(accessToken);
            expect(result).toBe(true);
        });

        it('should return false if token is invalid', async () => {
            const valid = false;

            const hashedToken = 'hashed-token';
            jest.spyOn(service as any, 'hashToken').mockReturnValue(hashedToken);
            jest.spyOn(service as any, 'isAccessTokenValidByHash').mockResolvedValue(valid);

            const accessToken = 'mock-access-token';
            const result = await service.isAccessTokenValid(accessToken);
            expect(result).toBe(false);
        });
    });

    describe('isAccessTokenValidByHash', () => {
        it('should return true if access token is valid', async () => {
            const hashedToken = 'hashed-token';
            const mockAccessTokenEntity = { expiresAt: new Date(Date.now() + 10000) } as any as AccessTokenEntity;

            jest.spyOn(service as any, 'getAccessTokenByHash').mockResolvedValue(mockAccessTokenEntity);

            const result = await service['isAccessTokenValidByHash'](hashedToken);

            expect(service['getAccessTokenByHash']).toHaveBeenCalledWith(hashedToken);
            expect(result).toBe(true);
        });

        it('should return false if access token is expired', async () => {
            const hashedToken = 'hashed-token';
            const mockAccessTokenEntity = {
                expiresAt: new Date(Date.now() - 10000),
                tokenHash: hashedToken,
            } as any as AccessTokenEntity;

            jest.spyOn(service as any, 'getAccessTokenByHash').mockResolvedValue(mockAccessTokenEntity);
            jest.spyOn(service as any, 'removeAccessTokenByHash').mockResolvedValue(true);

            const result = await service['isAccessTokenValidByHash'](hashedToken);

            expect(service['getAccessTokenByHash']).toHaveBeenCalledWith(hashedToken);
            expect(service['removeAccessTokenByHash']).toHaveBeenCalledWith(hashedToken);
            expect(result).toBe(false);
        });

        it('should return false if access token is not found', async () => {
            const hashedToken = 'hashed-token';
            jest.spyOn(service as any, 'getAccessTokenByHash').mockResolvedValue(null);
            const result = await service['isAccessTokenValidByHash'](hashedToken);
            expect(service['getAccessTokenByHash']).toHaveBeenCalledWith(hashedToken);
            expect(result).toBe(false);
        });
    });

    describe('isRefreshTokenValid', () => {
        it('should create hash and call isRefreshTokenValidByHash', async () => {
            const hashedToken = 'hashed-token';

            jest.spyOn(service as any, 'hashToken').mockReturnValue(hashedToken);
            jest.spyOn(service as any, 'isRefreshTokenValidByHash').mockResolvedValue(true);

            const refreshToken = 'mock-refresh-token';
            await service.isRefreshTokenValid(refreshToken);

            expect(service['hashToken']).toHaveBeenCalledWith(refreshToken);
            expect(service['isRefreshTokenValidByHash']).toHaveBeenCalledWith(hashedToken);
        });

        it('should return true if token is valid', async () => {
            const hashedToken = 'hashed-token';

            const valid = true;
            jest.spyOn(service as any, 'hashToken').mockReturnValue(hashedToken);
            jest.spyOn(service as any, 'isRefreshTokenValidByHash').mockResolvedValue(valid);

            const refreshToken = 'mock-refresh-token';
            const result = await service.isRefreshTokenValid(refreshToken);
            expect(result).toBe(true);
        });

        it('should return false if token is invalid', async () => {
            const hashedToken = 'hashed-token';

            const valid = false;
            jest.spyOn(service as any, 'hashToken').mockReturnValue(hashedToken);
            jest.spyOn(service as any, 'isRefreshTokenValidByHash').mockResolvedValue(valid);

            const refreshToken = 'mock-refresh-token';
            const result = await service.isRefreshTokenValid(refreshToken);
            expect(result).toBe(false);
        });
    });

    describe('isRefreshTokenValidByHash', () => {
        it('should return true if refresh token is valid', async () => {
            const hashedToken = 'hashed-token';
            const mockRefreshTokenEntity = { expiresAt: new Date(Date.now() + 10000) } as any as RefreshTokenEntity;

            jest.spyOn(service as any, 'getRefreshTokenByHash').mockResolvedValue(mockRefreshTokenEntity);

            const result = await service['isRefreshTokenValidByHash'](hashedToken);

            expect(service['getRefreshTokenByHash']).toHaveBeenCalledWith(hashedToken);
            expect(result).toBe(true);
        });

        it('should return false if refresh token is expired', async () => {
            const hashedToken = 'hashed-token';
            const mockRefreshTokenEntity = {
                expiresAt: new Date(Date.now() - 10000),
                tokenHash: hashedToken,
            } as any as RefreshTokenEntity;

            jest.spyOn(service as any, 'getRefreshTokenByHash').mockResolvedValue(mockRefreshTokenEntity);
            jest.spyOn(service as any, 'removeRefreshTokenByHash').mockResolvedValue(true);

            const result = await service['isRefreshTokenValidByHash'](hashedToken);

            expect(service['getRefreshTokenByHash']).toHaveBeenCalledWith(hashedToken);
            expect(service['removeRefreshTokenByHash']).toHaveBeenCalledWith(hashedToken);
            expect(result).toBe(false);
        });

        it('should return false if refresh token is not found', async () => {
            const hashedToken = 'hashed-token';
            jest.spyOn(service as any, 'getRefreshTokenByHash').mockResolvedValue(null);
            const result = await service['isRefreshTokenValidByHash'](hashedToken);
            expect(service['getRefreshTokenByHash']).toHaveBeenCalledWith(hashedToken);
            expect(result).toBe(false);
        });
    });

    describe('removeUserTokens', () => {
        it('should remove all tokens for a user', async () => {
            const userId = 'user-id';
            const mockRefreshTokenEntity = { id: 1 } as any as RefreshTokenEntity;
            const mockAccessTokenEntity = { id: 1 } as any as AccessTokenEntity;

            jest.spyOn(refreshTokenRepository, 'find').mockResolvedValue([mockRefreshTokenEntity]);
            jest.spyOn(accessTokenRepository, 'find').mockResolvedValue([mockAccessTokenEntity]);
            jest.spyOn(refreshTokenRepository, 'remove').mockResolvedValue({} as any);
            jest.spyOn(accessTokenRepository, 'remove').mockResolvedValue({} as any);

            const result = await service['removeUserTokens'](userId);

            expect(refreshTokenRepository.find).toHaveBeenCalledWith({ where: { userId } });
            expect(accessTokenRepository.find).toHaveBeenCalledWith({ where: { userId } });
            expect(refreshTokenRepository.remove).toHaveBeenCalledWith([mockRefreshTokenEntity]);
            expect(accessTokenRepository.remove).toHaveBeenCalledWith([mockAccessTokenEntity]);
            expect(result).toBe(true);
        });

        it('should return not call methods if tokens are not found', async () => {
            const userId = 'user-id';
            jest.spyOn(refreshTokenRepository, 'find').mockResolvedValue([]);
            jest.spyOn(accessTokenRepository, 'find').mockResolvedValue([]);
            jest.spyOn(refreshTokenRepository, 'remove');
            jest.spyOn(accessTokenRepository, 'remove');

            const result = await service['removeUserTokens'](userId);

            expect(refreshTokenRepository.find).toHaveBeenCalledWith({ where: { userId } });
            expect(accessTokenRepository.find).toHaveBeenCalledWith({ where: { userId } });
            expect(refreshTokenRepository.remove).not.toHaveBeenCalled();
            expect(accessTokenRepository.remove).not.toHaveBeenCalled();
            expect(result).toBe(true);
        });
    });
    
    describe('removeRefreshToken', () => {
        it('should use hashToken and call removeRefreshTokenByHash', async () => {
            const hashedToken = 'hashed-token';
            const refreshToken = 'mock-refresh-token';

            jest.spyOn(service as any, 'hashToken').mockReturnValue(hashedToken);
            jest.spyOn(service as any, 'removeRefreshTokenByHash').mockResolvedValue(true);

            const result = await service['removeRefreshToken'](refreshToken);

            expect(service['hashToken']).toHaveBeenCalledWith(refreshToken);
            expect(service['removeRefreshTokenByHash']).toHaveBeenCalledWith(hashedToken);
            expect(result).toBe(true);
        });
    });

    describe('removeRefreshTokenByHash', () => {
        it('should remove the refresh token by hash', async () => {
            const hashedToken = 'hashed-token';
            const mockRefreshTokenEntity = { id: 1 } as any as RefreshTokenEntity;
            jest.spyOn(service as any, 'getRefreshTokenByHash').mockResolvedValue(mockRefreshTokenEntity);
            jest.spyOn(refreshTokenRepository, 'remove').mockResolvedValue({} as any);
            jest.spyOn(accessTokenRepository, 'find').mockResolvedValue(["remaining"] as any);
            jest.spyOn(accessTokenRepository, 'remove').mockResolvedValue({} as any);

            const result = await service['removeRefreshTokenByHash'](hashedToken);

            expect(service['getRefreshTokenByHash']).toHaveBeenCalledWith(hashedToken);
            expect(refreshTokenRepository.remove).toHaveBeenCalledWith(mockRefreshTokenEntity);
            expect(accessTokenRepository.find).toHaveBeenCalledWith({ where: { relatedRefreshToken: mockRefreshTokenEntity } });
            expect(accessTokenRepository.remove).toHaveBeenCalledWith(["remaining"]);
            expect(result).toBe(true);
        });

        it('should throw error if something went wrong while removing refresh token', async () => {
            const hashedToken = 'hashed-token';
            const mockRefreshTokenEntity = { id: 1 } as any as RefreshTokenEntity;
            jest.spyOn(service as any, 'getRefreshTokenByHash').mockResolvedValue(mockRefreshTokenEntity);
            jest.spyOn(refreshTokenRepository, 'remove').mockRejectedValue(new Error('Database error'));

            await expect(() => service['removeRefreshTokenByHash'](hashedToken)).rejects.toThrow('Something went wrong while removing refresh token');
            expect(service['getRefreshTokenByHash']).toHaveBeenCalledWith(hashedToken);
            expect(refreshTokenRepository.remove).toHaveBeenCalledWith(mockRefreshTokenEntity);
        });

        it('should throw error if something went wrong while removing remaining access tokens', async () => {
            const hashedToken = 'hashed-token';
            const mockRefreshTokenEntity = { id: 1 } as any as RefreshTokenEntity;
            jest.spyOn(service as any, 'getRefreshTokenByHash').mockResolvedValue(mockRefreshTokenEntity);
            jest.spyOn(refreshTokenRepository, 'remove').mockResolvedValue({} as any);
            jest.spyOn(accessTokenRepository, 'find').mockResolvedValue(["remaining"] as any);
            jest.spyOn(accessTokenRepository, 'remove').mockRejectedValue(new Error('Database error'));

            await expect(() => service['removeRefreshTokenByHash'](hashedToken)).rejects.toThrow('Something went wrong while removing access tokens');

            expect(service['getRefreshTokenByHash']).toHaveBeenCalledWith(hashedToken);
            expect(refreshTokenRepository.remove).toHaveBeenCalledWith(mockRefreshTokenEntity);
            expect(accessTokenRepository.find).toHaveBeenCalledWith({ where: { relatedRefreshToken: mockRefreshTokenEntity } });
            expect(accessTokenRepository.remove).toHaveBeenCalledWith(["remaining"]);
        });

        it('should return false if refresh token is not found', async () => {
            const hashedToken = 'hashed-token';
            jest.spyOn(service as any, 'getRefreshTokenByHash').mockResolvedValue(null);
            jest.spyOn(refreshTokenRepository, 'remove').mockResolvedValue({} as any);

            const result = await service['removeRefreshTokenByHash'](hashedToken);
            
            expect(service['getRefreshTokenByHash']).toHaveBeenCalledWith(hashedToken);
            expect(refreshTokenRepository.remove).not.toHaveBeenCalled();
            expect(result).toBe(false);
        });
    });

    describe('removeRefreshTokenById', () => {
        // TODO
    })

    describe('removeAccessToken', () => {
        it('should use hashToken and call removeAccessTokenByHash', async () => {
            const hashedToken = 'hashed-token';
            const accessToken = 'mock-access-token';

            jest.spyOn(service as any, 'hashToken').mockReturnValue(hashedToken);
            jest.spyOn(service as any, 'removeAccessTokenByHash').mockResolvedValue(true);

            const result = await service['removeAccessToken'](accessToken);

            expect(service['hashToken']).toHaveBeenCalledWith(accessToken);
            expect(service['removeAccessTokenByHash']).toHaveBeenCalledWith(hashedToken);
            expect(result).toBe(true);
        });
    });

    describe('removeAccessTokenByHash', () => {
        it('should remove the access token by hash', async () => {
            const hashedToken = 'hashed-token';
            const mockAccessTokenEntity = { id: 1 } as any as AccessTokenEntity;
            jest.spyOn(service as any, 'getAccessTokenByHash').mockResolvedValue(mockAccessTokenEntity);
            jest.spyOn(accessTokenRepository, 'remove').mockResolvedValue({} as any);

            const result = await service['removeAccessTokenByHash'](hashedToken);

            expect(service['getAccessTokenByHash']).toHaveBeenCalledWith(hashedToken);
            expect(accessTokenRepository.remove).toHaveBeenCalledWith(mockAccessTokenEntity);
            expect(result).toBe(true);
        });

        it('should return false if access token is not found', async () => {
            const hashedToken = 'hashed-token';
            jest.spyOn(service as any, 'getAccessTokenByHash').mockResolvedValue(null);
            jest.spyOn(accessTokenRepository, 'remove').mockResolvedValue({} as any);

            const result = await service['removeAccessTokenByHash'](hashedToken);

            expect(service['getAccessTokenByHash']).toHaveBeenCalledWith(hashedToken);
            expect(accessTokenRepository.remove).not.toHaveBeenCalled();
            expect(result).toBe(false);
        });
    });

    describe('destroyRelatedTokens', () => {
        it('should remove related refresh token when access token is provided', async () => {
            const anyToken = 'mock-access-token';
            const tokenHash = 'hashed-access-token';
            const mockAccessTokenEntity = {
                relatedRefreshToken: { tokenHash: 'hashed-refresh-token' },
            } as any as AccessTokenEntity;
    
            jest.spyOn(service as any, 'hashToken').mockReturnValue(tokenHash);
            jest.spyOn(service as any, 'getAccessTokenByHash').mockResolvedValue(mockAccessTokenEntity);
            jest.spyOn(service as any, 'removeRefreshTokenByHash').mockResolvedValue(true);
    
            const result = await service.destroyRelatedTokens(anyToken);
    
            expect(service['hashToken']).toHaveBeenCalledWith(anyToken);
            expect(service['getAccessTokenByHash']).toHaveBeenCalledWith(tokenHash);
            expect(service['removeRefreshTokenByHash']).toHaveBeenCalledWith('hashed-refresh-token');
            expect(result).toBe(true);
        });
    
        it('should throw an error if related refresh token is not found', async () => {
            const anyToken = 'mock-access-token';
            const tokenHash = 'hashed-access-token';
            const mockAccessTokenEntity = {
                relatedRefreshToken: null,
            } as any as AccessTokenEntity;
    
            jest.spyOn(service as any, 'hashToken').mockReturnValue(tokenHash);
            jest.spyOn(service as any, 'getAccessTokenByHash').mockResolvedValue(mockAccessTokenEntity);
    
            await expect(service.destroyRelatedTokens(anyToken)).rejects.toThrow(
                'Related refresh token not found',
            );
    
            expect(service['hashToken']).toHaveBeenCalledWith(anyToken);
            expect(service['getAccessTokenByHash']).toHaveBeenCalledWith(tokenHash);
        });
    
        it('should remove refresh token when refresh token is provided', async () => {
            const anyToken = 'mock-refresh-token';
            const tokenHash = 'hashed-refresh-token';
            const mockRefreshTokenEntity = {} as any as RefreshTokenEntity;
    
            jest.spyOn(service as any, 'hashToken').mockReturnValue(tokenHash);
            jest.spyOn(service as any, 'getAccessTokenByHash').mockResolvedValue(null);
            jest.spyOn(service as any, 'getRefreshTokenByHash').mockResolvedValue(mockRefreshTokenEntity);
            jest.spyOn(service as any, 'removeRefreshTokenByHash').mockResolvedValue(true);
    
            const result = await service.destroyRelatedTokens(anyToken);
    
            expect(service['hashToken']).toHaveBeenCalledWith(anyToken);
            expect(service['getAccessTokenByHash']).toHaveBeenCalledWith(tokenHash);
            expect(service['getRefreshTokenByHash']).toHaveBeenCalledWith(tokenHash);
            expect(service['removeRefreshTokenByHash']).toHaveBeenCalledWith(tokenHash);
            expect(result).toBe(true);
        });
    
        it('should throw an error if token is invalid', async () => {
            const anyToken = 'invalid-token';
            const tokenHash = 'hashed-invalid-token';
    
            jest.spyOn(service as any, 'hashToken').mockReturnValue(tokenHash);
            jest.spyOn(service as any, 'getAccessTokenByHash').mockResolvedValue(null);
            jest.spyOn(service as any, 'getRefreshTokenByHash').mockResolvedValue(null);
    
            await expect(service.destroyRelatedTokens(anyToken)).rejects.toThrow('Invalid token');
    
            expect(service['hashToken']).toHaveBeenCalledWith(anyToken);
            expect(service['getAccessTokenByHash']).toHaveBeenCalledWith(tokenHash);
            expect(service['getRefreshTokenByHash']).toHaveBeenCalledWith(tokenHash);
        });
    });
});
