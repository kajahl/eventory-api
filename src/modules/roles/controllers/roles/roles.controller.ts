import {
    BadRequestException,
    ClassSerializerInterceptor,
    Controller,
    Delete,
    Get,
    HttpCode,
    HttpStatus,
    Inject,
    Param,
    ParseBoolPipe,
    ParseEnumPipe,
    Post,
    Query,
    UseGuards,
    UseInterceptors,
} from '@nestjs/common';
import { RoleEntity } from '../../entities/Role.entity';
import { RolesService } from '../../services/roles/roles.service';
import { UserRolesService } from '../../services/user-roles/user-roles.service';
import { Role, Scope } from '../../types';
import { ScopeAccessGuard } from '../../guards/ScopeAccess.guard';
import { Scopes } from '../../decorators/Scopes.decorator';
import { AccessJwtPassportAuthGuard } from 'src/modules/auth/guards/AccessJwtPassport.guard';
import { User } from 'src/common/decorators/User.decorator';
import { SignInData } from 'src/modules/auth/types';

@Controller('roles')
@UseGuards(AccessJwtPassportAuthGuard, ScopeAccessGuard) // JWT first
export class RolesController {
    constructor(
        @Inject(RolesService) private readonly rolesService: RolesService,
        @Inject(UserRolesService) private readonly userRolesService: UserRolesService,
    ) {}

    @Get('')
    @Scopes(Scope.RolesRead)
    async getAllRoles() {
        const roles = await this.rolesService.getRoles();
        return roles.map((role: RoleEntity) => ({
            roleId: role.id,
            name: role.name,
        }));
    }

    @Get('/me')
    @Scopes(Scope.RolesReadMe)
    async getMyRoles(
        @User() loggedUser: SignInData
    ) {
        const userRoles = await this.userRolesService.getUserRoles(loggedUser.userId);
        return userRoles.map(ur => ur.role).map(role => ({
            roleId: role.id,
            name: role.name,
        }));
    }

    @UseInterceptors(ClassSerializerInterceptor)
    @Get(':roleEnum/users')
    @Scopes(Scope.RolesReadUsers)
    async getUsersByRoleId(@Param('roleEnum', new ParseEnumPipe(Role)) role: Role) {
        const users = await this.userRolesService.getUsersWithRole(role);
        return {
            role: role,
            users: users,
        };
    }

    @Post(':roleEnum/users/:userId')
    @HttpCode(HttpStatus.CREATED)
    @Scopes(Scope.RolesManage)
    async addUserToRole(
        @User() loggedUser: SignInData,
        @Query('confirm', new ParseBoolPipe({ optional: true })) confirm: boolean,
        @Param('roleEnum', new ParseEnumPipe(Role)) role: Role,
        @Param('userId') userId: string,
    ) {
        if (loggedUser.userId === userId) {
            if (!confirm)
                throw new BadRequestException(`Are you trying to assign role to yourself? Use ?confirm=true to confirm`);
        }
        const user = await this.userRolesService.assingRoleToUser(userId, role);
        return user;
    }

    @Delete(':roleEnum/users/:userId')
    @HttpCode(HttpStatus.NO_CONTENT)
    @Scopes(Scope.RolesManage)
    async removeUserFromRole(
        @User() loggedUser: SignInData,
        @Query('confirm', new ParseBoolPipe({ optional: true })) confirm: boolean,
        @Param('roleEnum', new ParseEnumPipe(Role)) role: Role,
        @Param('userId') userId: string,
    ) {
        if (loggedUser.userId === userId) {
            if (!confirm)
                throw new BadRequestException(`Are you trying to remove your own role? Use ?confirm=true to confirm`);
        }
        const user = await this.userRolesService.removeRoleFromUser(userId, role);
        return user;
    }
}
