import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class RefreshJwtPassportAuthGuard extends AuthGuard('refresh-jwt') {}