import { CanActivate, ExecutionContext, Inject, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { UserRolesService } from '../services/user-roles/user-roles.service';
import { SignInData } from 'src/modules/auth/types';
import { getRoleScopeMapping, Scope } from '../types';

@Injectable()
export class ScopeAccessGuard implements CanActivate {
    constructor(
        private readonly reflector: Reflector,
        @Inject(UserRolesService) private readonly userRolesService: UserRolesService,
    ) {}

    async canActivate(context: ExecutionContext): Promise<boolean> {
        const requiredScopes: Scope[] = this.reflector.get<Scope[]>('scopes', context.getHandler());
        if (!requiredScopes) return true;

        const request = context.switchToHttp().getRequest();
        const user = request.user as SignInData;
        if (!user) return false; 

        const userRoles = await this.userRolesService.getUserRoles(user.userId);
        const scopes = userRoles.map(r => getRoleScopeMapping()[r.role.name]).flat();

        return requiredScopes.every(scope => scopes.includes(scope));
    }
}