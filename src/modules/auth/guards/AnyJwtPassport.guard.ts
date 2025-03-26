import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class AnyJwtPassportAuthGuard extends AuthGuard('any-jwt') {}