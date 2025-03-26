import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, LessThan } from 'typeorm';
import { Cron } from '@nestjs/schedule';
import { RefreshTokenEntity } from '../../entities/RefreshToken.entity';
import { AccessTokenEntity } from '../../entities/AccessToken.entity';

@Injectable()
export class TokenCleanupService {
    constructor(
        @InjectRepository(RefreshTokenEntity)
        private readonly refreshTokenRepository: Repository<RefreshTokenEntity>,
        @InjectRepository(AccessTokenEntity)
        private readonly accessTokenRepository: Repository<AccessTokenEntity>,
    ) {}

    @Cron('*/5 * * * *')
    async cleanupExpiredAndBlacklistedTokens(): Promise<void> {
        const now = new Date();

        await this.refreshTokenRepository.delete({
            expiresAt: LessThan(now)
        });

        await this.accessTokenRepository.delete({
            expiresAt: LessThan(now)
        });
    }
}