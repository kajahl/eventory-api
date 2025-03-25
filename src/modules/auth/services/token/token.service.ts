import { BadRequestException, ConsoleLogger, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as crypto from 'crypto';
import { RefreshTokenEntity } from '../../entities/RefreshToken.entity';
import { AccessTokenEntity } from '../../entities/AccessToken.entity';
import { JwtPayload } from '../../types';

@Injectable()
export class TokenService {
    constructor(
        private readonly jwtService: JwtService,
        private readonly configService: ConfigService,
        @InjectRepository(RefreshTokenEntity) private readonly refreshTokenRepository: Repository<RefreshTokenEntity>,
        @InjectRepository(AccessTokenEntity) private readonly accessTokenRepository: Repository<AccessTokenEntity>,
    ) {}
    
    // Config 

    /**
     * Get the secret key for signing JWT access tokens.
     * @returns The secret key for signing JWT access tokens.
     */
    get AccessTokenSecretKey(): string {
        return this.configService.get<string>('JWT_ACCESS_SECRET', 'jwt-access-secret');
    }

    /**
     * Get the secret key for signing JWT refresh tokens.
     * @returns The secret key for signing JWT refresh tokens.
     */
    get RefreshTokenSecretKey(): string {
        return this.configService.get<string>('JWT_REFRESH_SECRET', 'jwt-refresh-secret');
    }

    /**
     * Get the expiration time for JWT access tokens.
     * @returns The expiration time for JWT access tokens.
     */
    get AccessTokenExpirationTime(): string {
        return this.configService.get<string>('JWT_EXPIRATION_TIME', '5m');
    }

    /**
     * Get the expiration time for JWT refresh tokens.
     * @returns The expiration time for JWT refresh tokens.
     */
    get RefreshTokenExpirationTime(): string {
        return this.configService.get<string>('JWT_EXPIRATION_TIME', '7d');
    }

    /**
     * Generate a hash of the provided token using SHA-256.
     * @param token The token to hash.
     * @returns The hashed token as a hexadecimal string.
     */
    private hashToken(token: string): string {
        return crypto.createHash('sha256').update(token).digest('hex');
    }

    // Internal

    /**
     * Calculates the expiration time based on the provided expiration time string.
     * @param expirationTime The expiration time string (e.g., "5m", "1h", "2d").
     * @returns The calculated expiration time as a Date object.
     * @throws Error if the expiration time format is invalid.
     */
    private calculateExpirationTime(expirationTime: string): Date {
        const expires = new Date();
        const timeUnit = expirationTime.slice(-1); // Get the last character (e.g., "m", "h", "d")
        const timeValue = parseInt(expirationTime.slice(0, -1), 10); // Get the numeric part

        if (isNaN(timeValue)) throw new Error(`Invalid expiration time format: ${expirationTime}`);

        switch (timeUnit) {
            case 'm':
                expires.setMinutes(expires.getMinutes() + timeValue);
                break;
            case 'h':
                expires.setHours(expires.getHours() + timeValue);
                break;
            case 'd':
                expires.setDate(expires.getDate() + timeValue);
                break;
            default:
                throw new Error(`Unsupported time unit in expiration time: ${timeUnit}`);
        }

        return expires;
    }

    // Generate tokens

    /**
     * Generates a refresh token based on the provided payload.
     * @param payload The payload to include in the refresh token.
     * @returns The generated refresh token as a string.
     */
    private async generateRefreshToken(payload: JwtPayload): Promise<string> {
        const refreshToken = this.jwtService.sign(payload, {
            secret: this.RefreshTokenSecretKey,
            expiresIn: this.RefreshTokenExpirationTime,
        });

        const expiresAt = this.calculateExpirationTime(this.RefreshTokenExpirationTime);
        await this.saveRefreshToken(payload.sub, refreshToken, expiresAt);

        return refreshToken;
    }

    /**
     * Generates an access token based on the provided refresh token.
     * @param refreshToken The refresh token to use for generating the access token.
     * @returns The generated access token as a string.
     * @throws BadRequestException if the refresh token is invalid.
     */
    private async generateAccessToken(refreshToken: string): Promise<string> {
        try {
            const payload: JwtPayload = this.jwtService.verify(refreshToken, { secret: this.RefreshTokenSecretKey });

            const refreshTokenHash = this.hashToken(refreshToken);
            const relatedRefreshToken = await this.getRefreshTokenByHash(refreshTokenHash);
            if (!relatedRefreshToken) throw new BadRequestException('Invalid refresh token');

            // destructure the payload to get the user ID and timestamp
            // cannot use payload directly because it has exp and iat properties
            const { sub, timestamp } = payload;

            const accessToken = this.jwtService.sign(
                { sub, timestamp },
                { secret: this.AccessTokenSecretKey, expiresIn: this.AccessTokenExpirationTime },
            );

            const expiresAt = this.calculateExpirationTime(this.AccessTokenExpirationTime);
            await this.saveAccessToken(payload.sub, accessToken, expiresAt, relatedRefreshToken);
            return accessToken;
        } catch (error) {
            if(error instanceof BadRequestException) throw error;

            console.error(error);
            throw new InternalServerErrorException('Something went wrong while generating access token');
        }
    }

    // Generate tokens (public)

    /**
     * Generates both access and refresh tokens based on the provided payload.
     * @param payload The payload to include in the tokens.
     * @returns An object containing the generated access token and refresh token.
     */
    async generateTokens(payload: JwtPayload): Promise<{ accessToken: string; refreshToken: string }> {
        const refreshToken = await this.generateRefreshToken(payload);
        const accessToken = await this.generateAccessToken(refreshToken);
        return { accessToken, refreshToken };
    }

    /**
     * Regenerates the access token based on the provided refresh token.
     * @param refreshToken The refresh token to use for regenerating the access token.
     * @returns The regenerated access token as a string.
     * @throws UnauthorizedException if the refresh token is invalid.
     */
    async regenerateAccessToken(refreshToken: string): Promise<string> {
        const refreshTokenHash = this.hashToken(refreshToken);
        const relatedRefreshToken = await this.getRefreshTokenByHash(refreshTokenHash);
        if (!relatedRefreshToken) throw new UnauthorizedException('Invalid refresh token');

        return this.generateAccessToken(refreshToken);
    }

    // Getters

    /**
     * Retrieves the access token entity based on the provided hash.
     * @param hash The hash of the access token.
     * @returns The access token entity if found, otherwise null.
     */
    private async getAccessTokenByHash(hash: string): Promise<AccessTokenEntity | null> {
        const accessToken = await this.accessTokenRepository.findOne({ where: { tokenHash: hash } });
        return accessToken || null;
    }

    /**
     * Retrieves the refresh token entity based on the provided hash.
     * @param hash The hash of the refresh token.
     * @returns The refresh token entity if found, otherwise null.
     */
    private async getRefreshTokenByHash(hash: string): Promise<RefreshTokenEntity | null> {
        const refreshToken = await this.refreshTokenRepository.findOne({ where: { tokenHash: hash } });
        return refreshToken || null;
    }

    // Save

    /**
     * Saves the access token entity to the database.
     * @param userId UserId related to the access token
     * @param accessToken Access token
     * @param expiresAt Expiration date of the access token
     * @param relatedRefreshToken Related refresh token entity
     */
    private async saveAccessToken(
        userId: string,
        accessToken: string,
        expiresAt: Date,
        relatedRefreshToken: RefreshTokenEntity,
    ): Promise<boolean> {
        const hashedToken = this.hashToken(accessToken);
        const accessTokenEntity = new AccessTokenEntity();

        accessTokenEntity.userId = userId;
        accessTokenEntity.tokenHash = hashedToken;
        accessTokenEntity.expiresAt = expiresAt;
        accessTokenEntity.relatedRefreshToken = relatedRefreshToken;

        await this.accessTokenRepository.save(accessTokenEntity).catch((e) => {
            console.error(e);
            throw new InternalServerErrorException('Something went wrong while saving access token');
        });
        return true;
    }

    /**
     * Saves the refresh token entity to the database.
     * @param userId UserId related to the refresh token
     * @param refreshToken Refresh token
     * @param expiresAt Expiration date of the refresh token
     */
    private async saveRefreshToken(userId: string, refreshToken: string, expiresAt: Date): Promise<boolean> {
        const hashedToken = this.hashToken(refreshToken);

        const refreshTokenEntity = new RefreshTokenEntity();
        refreshTokenEntity.userId = userId;
        refreshTokenEntity.tokenHash = hashedToken;
        refreshTokenEntity.expiresAt = expiresAt;

        await this.refreshTokenRepository.save(refreshTokenEntity).catch((e) => {
            console.error(e);
            throw new InternalServerErrorException('Something went wrong while saving refresh token');
        });
        return true;
    }

    // Validators

    /**
     * Checks if the provided access token is valid.
     * @param accessToken The access token to check.
     * @returns True if the access token is valid, false otherwise.
     */
    async isAccessTokenValid(accessToken: string): Promise<boolean> {
        const accessTokenHash = this.hashToken(accessToken);
        return this.isAccessTokenValidByHash(accessTokenHash);
    }

    /**
     * Checks if the access token is valid by its hash.
     * @param accessTokenHash The hash of the access token to check.
     * @returns True if the access token is valid, false otherwise.
     */
    async isAccessTokenValidByHash(accessTokenHash: string): Promise<boolean> {
        const accessToken = await this.getAccessTokenByHash(accessTokenHash);
        if (!accessToken) return false;

        const currentTime = new Date();
        if (currentTime > accessToken.expiresAt) {
            await this.removeAccessTokenByHash(accessToken.tokenHash);
            return false;
        }

        return true;
    }

    /**
     * Checks if the provided refresh token is valid.
     * @param refreshToken The refresh token to check.
     * @returns True if the refresh token is valid, false otherwise.
     */
    async isRefreshTokenValid(refreshToken: string): Promise<boolean> {
        const refreshTokenHash = this.hashToken(refreshToken);
        return this.isRefreshTokenValidByHash(refreshTokenHash);
    }

    /**
     * Checks if the refresh token is valid by its hash.
     * @param refreshTokenHash The hash of the refresh token to check.
     * @returns True if the refresh token is valid, false otherwise.
     */
    async isRefreshTokenValidByHash(refreshTokenHash: string): Promise<boolean> {
        const refreshTokenEntity = await this.getRefreshTokenByHash(refreshTokenHash);
        if (!refreshTokenEntity) return false;

        const currentTime = new Date();
        if (currentTime > refreshTokenEntity.expiresAt) {
            await this.removeRefreshTokenByHash(refreshTokenHash);
            return false;
        }

        return true;
    }

    // Remove

    /**
     * Removes all tokens (access and refresh) associated with the provided user ID.
     * @param userId The user ID whose tokens should be removed.
     * @returns true
     * @throws InternalServerErrorException if something went wrong while removing tokens.
     */
    async removeUserTokens(userId: string): Promise<boolean> {
        const refreshTokens = await this.refreshTokenRepository.find({ where: { userId } });
        if (refreshTokens.length > 0) await this.refreshTokenRepository.remove(refreshTokens).catch((e) => {
            throw new InternalServerErrorException('Something went wrong while removing refresh tokens');
        });

        // Access tokens should be removed when refresh tokens are removed (cascade delete)
        // Only safety check
        const accessTokens = await this.accessTokenRepository.find({ where: { userId } });
        if (accessTokens.length > 0) await this.accessTokenRepository.remove(accessTokens).catch((e) => {
            throw new InternalServerErrorException('Something went wrong while removing access tokens');
        });

        return true; //TODO: Opis i testy
    }

    /**
     * Removes the refresh token from the database.
     * @param refreshToken The refresh token to remove.
     * @returns True if the refresh token was removed, false otherwise.
     */
    async removeRefreshToken(refreshToken: string): Promise<boolean> {
        const refreshTokenHash = this.hashToken(refreshToken);
        return this.removeRefreshTokenByHash(refreshTokenHash);
    }

    /**
     * Removes the refresh token associated with the provided hash.
     * @param refreshTokenHash The hash of the refresh token to remove.
     * @returns True if the refresh token was removed, false otherwise.
     */
    async removeRefreshTokenByHash(refreshTokenHash: string): Promise<boolean> {
        const refreshToken = await this.getRefreshTokenByHash(refreshTokenHash);
        if (!refreshToken) return false;
        await this.refreshTokenRepository.remove(refreshToken).catch((e) => {
            throw new InternalServerErrorException('Something went wrong while removing refresh token');
        });

        // Related access tokens should be removed when refresh tokens are removed (cascade delete)
        // Only safety check
        // await this.accessTokenRepository.delete({ relatedRefreshToken: refreshToken }); 
        // //TODO: To generuje błędy, do sprawdzenia
        const remainingAccessTokens = await this.accessTokenRepository.find({ where: { relatedRefreshToken: refreshToken } });
        if (remainingAccessTokens.length > 0) await this.accessTokenRepository.remove(remainingAccessTokens).catch((e) => {
            throw new InternalServerErrorException('Something went wrong while removing access tokens');
        });
        return true;
    }

    /**
     * Removes the access token from the database.
     * @param accessToken The access token to remove.
     * @returns True if the access token was removed, false otherwise.
     */
    async removeAccessToken(accessToken: string): Promise<boolean> {
        const accessTokenHash = this.hashToken(accessToken);
        return this.removeAccessTokenByHash(accessTokenHash);
    }

    /**
     * Removes the access token associated with the provided hash.
     * @param accessTokenHash The hash of the access token to remove.
     * @returns True if the access token was removed, false otherwise.
     */
    async removeAccessTokenByHash(accessTokenHash: string): Promise<boolean> {
        const accessToken = await this.getAccessTokenByHash(accessTokenHash);
        if (!accessToken) return false;
        await this.accessTokenRepository.remove(accessToken)
        return true;
    }
}
