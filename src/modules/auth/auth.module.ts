import { Module } from '@nestjs/common';
import { AuthController } from './controllers/auth/auth.controller';
import { AuthService } from './services/auth/auth.service';
import { UsersModule } from '../users/users.module';
import { PassportModule } from '@nestjs/passport';
import { LocalStrategy } from './strategies/Local.strategy';
import { JwtModule } from '@nestjs/jwt';
import { AccessJwtStrategy } from './strategies/AccessJwt.strategy';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TokenService } from './services/token/token.service';
import { TokenCleanupService } from './services/token-cleanup/token-cleanup.service';
import { TypeOrmModule } from '@nestjs/typeorm';
import { RefreshTokenEntity } from './entities/RefreshToken.entity';
import { AccessTokenEntity } from './entities/AccessToken.entity';
import { AnyJwtStrategy } from './strategies/AnyJwt.strategy';
import { RefreshJwtStrategy } from './strategies/RefreshJwt.strategy';

@Module({
    imports: [
        UsersModule,
        PassportModule,
        JwtModule.register({}),
        TypeOrmModule.forFeature([RefreshTokenEntity, AccessTokenEntity])
    ],
    controllers: [AuthController],
    providers: [AuthService, LocalStrategy, AccessJwtStrategy, TokenService, TokenCleanupService, AnyJwtStrategy, RefreshJwtStrategy],
})
export class AuthModule {}
