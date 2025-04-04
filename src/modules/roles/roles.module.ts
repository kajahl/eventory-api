import { forwardRef, Module, OnModuleInit } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { RoleEntity } from './entities/Role.entity';
import { RolesService } from './services/roles/roles.service';
import { RolesController } from './controllers/roles/roles.controller';
import { UserRoleEntity } from './entities/UserRole.entity';
import { UserRolesService } from './services/user-roles/user-roles.service';
import { UsersModule } from '../users/users.module';
import { AuthModule } from '../auth/auth.module';

@Module({
    imports: [
        TypeOrmModule.forFeature([RoleEntity, UserRoleEntity]),
        forwardRef(() => UsersModule),
        AuthModule,
    ],
    providers: [RolesService, UserRolesService],
    controllers: [RolesController],
    exports: [RolesService, UserRolesService],
})
export class RolesModule implements OnModuleInit {
    constructor(
        private readonly rolesService: RolesService,
    ) {}

    async onModuleInit() {
        await this.rolesService.syncRolesInDatabase();
    }
}