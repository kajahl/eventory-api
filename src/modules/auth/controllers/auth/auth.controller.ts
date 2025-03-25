import {
    BadRequestException,
    Body,
    Controller,
    Get,
    Inject,
    InternalServerErrorException,
    Post,
    Request,
    UseGuards,
} from '@nestjs/common';
import { LocalPassportAuthGuard } from '../../guards/LocalPassport.guard';
import { Request as Req } from 'express';
import { AuthService } from '../../services/auth/auth.service';
import { AccessJwtPassportAuthGuard } from '../../guards/AccessJwtPassport.guard';
import { AnyJwtPassportAuthGuard } from '../../guards/AnyJwtPassport.guard';
import { RefreshJwtPassportAuthGuard } from '../../guards/RefreshJwtPassport.guard';
import { TokenService } from '../../services/token/token.service';
import VerifyTokenDto from '../../dtos/VerifyToken.dto';
import { SignInData, TokenType } from '../../types';

@Controller('auth')
export class AuthController {
    constructor(
        @Inject(AuthService) private readonly authService: AuthService,
        @Inject(TokenService) private readonly tokenService: TokenService,
    ) {}

    @UseGuards(LocalPassportAuthGuard)
    @Post('login')
    async login(@Request() req: Req): Promise<any> {
        return this.authService.signIn(req.user as SignInData);
    }

    @UseGuards(AccessJwtPassportAuthGuard)
    @Get('me')
    async me(@Request() req: Req): Promise<any> {
        return req.user;
    }

    @UseGuards(RefreshJwtPassportAuthGuard)
    @Post('token')
    async renewAccessToken(@Request() req: Req): Promise<any> {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) throw new Error('Token is required');

        const accessToken = await this.tokenService.regenerateAccessToken(token).catch((e: Error) => {
            throw new InternalServerErrorException(`Error regenerating access token: ${e.message}`);
        });

        return {
            accessToken,
        };
    }

    @Post('verify')
    async verifyAccessToken(@Body() data: VerifyTokenDto): Promise<any> {
        const { type, token } = data;
        if (!type || !token) throw new BadRequestException('Type and token are required');

        let isValid = false;
        if (type === TokenType.ACCESS) isValid = await this.tokenService.isAccessTokenValid(token);
        if (type === TokenType.REFRESH) isValid = await this.tokenService.isRefreshTokenValid(token);

        return {
            isValid,
        };
    }

    @UseGuards(AnyJwtPassportAuthGuard)
    @Post('logout')
    async logout(@Request() req: Req): Promise<any> {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) throw new BadRequestException('Token is required');
        return this.tokenService.destroyRelatedTokens(token);
    }
}
