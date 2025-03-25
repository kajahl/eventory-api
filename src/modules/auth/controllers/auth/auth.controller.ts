import { BadRequestException, Body, Controller, Get, Inject, InternalServerErrorException, Post, Request, Response, UseGuards } from '@nestjs/common';
import { LocalPassportAuthGuard } from '../../guards/LocalPassport.guard';
import { Request as Req, Response as Res } from 'express';
import { AuthService } from '../../services/auth/auth.service';
import { AccessJwtPassportAuthGuard } from '../../guards/AccessJwtPassport.guard';
import { AnyJwtPassportAuthGuard } from '../../guards/AnyJwtPassport.guard';
import { RefreshJwtPassportAuthGuard } from '../../guards/RefreshJwtPassport.guard';
import { TokenService } from '../../services/token/token.service';
import VerifyTokenDto from '../../dtos/VerifyToken.dto';
import { TokenType } from '../../types';

@Controller('auth')
export class AuthController {
    constructor(
        @Inject(AuthService) private readonly authService: AuthService,
        @Inject(TokenService) private readonly tokenService: TokenService,
    ) {}

    @UseGuards(LocalPassportAuthGuard)
    @Post('login')
    async login(@Request() req: Req): Promise<any> {
        return this.authService.signIn(req.user as any); //TODO ?
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

        const accessToken = this.tokenService.regenerateAccessToken(token).catch(e => {
            throw new InternalServerErrorException(`Error regenerating access token: ${e.message}`);
        })

        return {
            accessToken
        }
    }

    @Post('verify')
    async verifyAccessToken(@Body() data: VerifyTokenDto): Promise<any> {
        const { type, token } = data;
        if (!type || !token) throw new BadRequestException('Type and token are required');

        let isValid = false;
        if (type === TokenType.ACCESS) isValid = await this.tokenService.isAccessTokenValid(token);
        if (type === TokenType.REFRESH) isValid = await this.tokenService.isRefreshTokenValid(token);

        return {
            isValid
        }
    }

    @UseGuards(AnyJwtPassportAuthGuard)
    @Post('logout')
    async logout(@Request() req: Req): Promise<any> {
        // const token = req.headers.authorization?.split(' ')[1];
        // if (!token) throw new BadRequestException('Token is required');

        // if (await this.tokenService.isAccessTokenValid(token)) {
        //     await this.tokenService.removeAccessToken(token)
        //     return {
        //         message: 'Logged out successfully',
        //         tokenType: TokenType.ACCESS
        //     }
        // }

        // if (await this.tokenService.isRefreshTokenValid(token)) {
        //     await this.tokenService.removeRefreshToken(token)
        //     return {
        //         message: 'Logged out successfully',
        //         tokenType: TokenType.REFRESH
        //     }
        // }

        // throw new BadRequestException('Token is not valid');
        const userId = (req.user as any).userId;
        if(!userId) throw new BadRequestException('Not logged in');

        this.tokenService.removeUserTokens(userId)
        return 
    }

}
