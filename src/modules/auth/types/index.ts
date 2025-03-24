export type JwtPayload = { sub: string, timestamp: number };
export type SignInData = { userId: string, timestamp: number }
export type AuthResult = { accessToken: string, refreshToken: string, user: object } | null;

export enum TokenType {
    ACCESS = 'access',
    REFRESH = 'refresh',
}