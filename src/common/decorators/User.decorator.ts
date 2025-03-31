import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { SignInData } from 'src/modules/auth/types';

export const User = createParamDecorator((data: unknown, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    return request.user as SignInData;
});
