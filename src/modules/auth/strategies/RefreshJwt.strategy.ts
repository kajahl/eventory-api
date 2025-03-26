import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { JwtPayload, SignInData } from '../types';
import { Inject, UnauthorizedException } from '@nestjs/common';
import { TokenService } from '../services/token/token.service';
import { Request } from 'express';

export class RefreshJwtStrategy extends PassportStrategy(Strategy, 'refresh-jwt') {
    constructor(
        @Inject(TokenService) private readonly tokenService: TokenService,
    ) {
        super({
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
            ignoreExpiration: false,
            secretOrKey: tokenService.RefreshTokenSecretKey,
            passReqToCallback: true
        });
    }

    async validate(req: Request, payload: JwtPayload): Promise<SignInData> {
        const token = ExtractJwt.fromAuthHeaderAsBearerToken()(req);
        if(!token) throw new UnauthorizedException('Token not found in request');
        const isValid = await this.tokenService.isRefreshTokenValid(token);
        if (!isValid) throw new UnauthorizedException('Invalid refresh token');

        return {
            userId: payload.sub,
            timestamp: payload.timestamp,
        };
    }
}
