import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { JwtPayload, SignInData } from '../types';
import { Inject, UnauthorizedException } from '@nestjs/common';
import { TokenService } from '../services/token/token.service';
import { Request } from 'express';
import { JwtService } from '@nestjs/jwt';

export class AnyJwtStrategy extends PassportStrategy(Strategy, 'any-jwt') {
    constructor(
        @Inject(TokenService) private readonly tokenService: TokenService,
        @Inject(JwtService) private readonly jwtService: JwtService,
    ) {
        super({
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
            ignoreExpiration: false,
            passReqToCallback: true,
            secretOrKeyProvider: (request, rawJwtToken, done) => {
                const token = ExtractJwt.fromAuthHeaderAsBearerToken()(request);
                if (!token) {
                    return done(new UnauthorizedException('Token not found in request'), '');
                }

                try {
                    this.jwtService.verify(token, {
                        secret: this.tokenService.AccessTokenSecretKey
                    });
                    return done(null, this.tokenService.AccessTokenSecretKey);
                } catch (error) {}

                try {
                    this.jwtService.verify(token, {
                        secret: this.tokenService.RefreshTokenSecretKey
                    });
                    return done(null, this.tokenService.RefreshTokenSecretKey);
                } catch (error) {}

                return done(new UnauthorizedException('Invalid token'), '');
            }
        });
    }

    async validate(req: Request, payload: JwtPayload): Promise<SignInData> {
        const token = ExtractJwt.fromAuthHeaderAsBearerToken()(req);
        if (!token) throw new UnauthorizedException('Token not found in request');

        // Sprawdź, czy token jest Access lub Refresh
        const isAccessTokenValid = this.tokenService.isAccessTokenValid(token);
        const isRefreshTokenValid = this.tokenService.isRefreshTokenValid(token);

        if (!isAccessTokenValid && !isRefreshTokenValid) {
            throw new UnauthorizedException('Invalid token');
        }

        return {
            userId: payload.sub,
            timestamp: payload.timestamp,
        };
    }
}