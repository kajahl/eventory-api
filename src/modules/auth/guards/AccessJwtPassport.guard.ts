import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class AccessJwtPassportAuthGuard extends AuthGuard('access-jwt') {}