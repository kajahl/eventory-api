import {
    BadRequestException,
    Body,
    ClassSerializerInterceptor,
    Controller,
    Delete,
    ForbiddenException,
    Get,
    Inject,
    InternalServerErrorException,
    Param,
    Post,
    Request,
    UseGuards,
    UseInterceptors,
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
import { UsersService } from 'src/modules/users/services/users/users.service';

@Controller('auth')
export class AuthController {
    constructor(
        @Inject(AuthService) private readonly authService: AuthService,
        @Inject(TokenService) private readonly tokenService: TokenService,
        @Inject(UsersService) private readonly usersService: UsersService,
    ) {}

    @UseGuards(LocalPassportAuthGuard)
    @Post('login')
    async login(@Request() req: Req): Promise<any> {
        return this.authService.signIn(req.user as SignInData);
    }

    @UseGuards(AccessJwtPassportAuthGuard)
    @UseInterceptors(ClassSerializerInterceptor)
    @Get('me')
    async me(@Request() req: Req): Promise<any> {
        const user = req.user as SignInData;
        if (!user) throw new BadRequestException('User ID is required');
        return this.usersService.getById(user.userId);
    }

    @UseGuards(AccessJwtPassportAuthGuard)
    @Get('me/sessions')
    async getSessions(@Request() req: Req): Promise<any> {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) throw new BadRequestException('Token is required');
        const user = req.user as SignInData;
        if (!user) throw new BadRequestException('User ID is required');

        const refreshTokens = await this.tokenService.getUserRefreshTokens(user.userId)
        const currentRefreshTokenId = await this.tokenService.getRelatedRefreshTokenIdByAccessToken(token);

        return {
            sessions: [
                refreshTokens.map(t => ({
                    id: t.id,
                    createdAt: t.createdAt,
                }))
            ],
            total: refreshTokens.length,
            currentSession: currentRefreshTokenId,
        };
    }

    @UseGuards(AccessJwtPassportAuthGuard)
    @Delete('me/sessions')
    async deleteAllSessions(@Request() req: Req): Promise<any> {
        const user = req.user as SignInData;
        if (!user) throw new BadRequestException('User ID is required');

        // UserId is already checked in the guard - it is the same as the one in the token
        this.tokenService.removeUserTokens(user.userId)

        return {
            message: 'All sessions deleted successfully',
        };
    }

    @UseGuards(AccessJwtPassportAuthGuard)
    @Delete('me/sessions/:id')
    async deleteSession(
        @Request() req: Req,
        @Param('id') tokenId: string
    ): Promise<any> {
        const user = req.user as SignInData;
        if (!user) throw new BadRequestException('User ID is required');
        const isUserOwnerOfTokenId = await this.tokenService.isUserOwnerOfTokenId(user.userId, TokenType.REFRESH, tokenId);
        if (!isUserOwnerOfTokenId) throw new ForbiddenException('You are not allowed to delete this session');

        await this.tokenService.removeRefreshTokenById(tokenId)

        return {
            message: `Session with ID ${tokenId} deleted successfully`,
        };
    }

    @UseGuards(RefreshJwtPassportAuthGuard)
    @Post('token')
    async renewAccessToken(@Request() req: Req): Promise<any> {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) throw new Error('Token is required');

        const accessToken = await this.tokenService.regenerateAccessToken(token)

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
