import { Inject, Injectable } from '@nestjs/common';
import { PasswordService } from 'src/modules/users/services/password/password.service';
import { UsersService } from 'src/modules/users/services/users/users.service';
import { AuthResult, JwtPayload, SignInData } from '../../types';
import { TokenService } from '../token/token.service';

@Injectable()
export class AuthService {
    constructor(
        @Inject(UsersService) private readonly usersService: UsersService,
        @Inject(PasswordService) private readonly passwordService: PasswordService,
        @Inject(TokenService) private readonly tokenService: TokenService
    ) {}

    async signIn(user: SignInData): Promise<AuthResult> {
        const tokenPayload : JwtPayload = {
            sub: user.userId,
            timestamp: user.timestamp,
        }

        const { accessToken, refreshToken } = await this.tokenService.generateTokens(tokenPayload);

        return {
            accessToken,
            refreshToken,
            user: {
                sub: user.userId,
                timestamp: user.timestamp,
            },
        }
    }

    async validateUser(email: string, password: string): Promise<null | SignInData> {
        const user = await this.usersService.getByEmail(email).catch(() => null);
        if (!user) return null;

        const isPasswordValid = await this.passwordService.comparePasswords(password, user.password);
        if (!isPasswordValid) return null;

        return {
            userId: user.id,
            timestamp: new Date().getTime()
        };
    }
}
