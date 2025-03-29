import { BadRequestException, Inject, Injectable, NotFoundException } from '@nestjs/common';
import { UserRoleEntity } from '../../entities/UserRole.entity';
import { UsersService } from 'src/modules/users/services/users/users.service';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Role } from '../../types';
import { RolesService } from '../roles/roles.service';
import UserEntity from 'src/modules/users/entities/user.entity';

@Injectable()
export class UserRolesService {
    constructor(
        @InjectRepository(UserRoleEntity) private readonly userRoleRepository: Repository<UserRoleEntity>,
        @Inject(UsersService) private readonly usersService: UsersService,
        @Inject(RolesService) private readonly rolesService: RolesService,
    ) {}

    /**
     * Assign role to user
     * @param userId User ID
     * @param role Role to assign
     * @returns True if role was assigned successfully
     * @throws BadRequestException if user already has this role
     * @throws NotFoundException if user or role not found
     */
    async assingRoleToUser(userId: string, role: Role): Promise<boolean> {
        const userEntity = await this.usersService.getById(userId);
        const roleEntity = await this.rolesService.getRole(role);

        const userHasRole = await this.isUserHasRole(userId, role);
        if (userHasRole) throw new BadRequestException(`User already has this role`);

        const userRole = this.userRoleRepository.create({
            user: userEntity,
            role: roleEntity,
        });
        await this.userRoleRepository.save(userRole);

        return true;
    }

    /**
     * Remove role from user
     * @param userId User ID
     * @param role Role to remove
     * @returns True if role was removed successfully
     * @throws BadRequestException if user doesn't have this role
     * @throws NotFoundException if user or role not found
     */
    async removeRoleFromUser(userId: string, role: Role): Promise<boolean> {
        const userEntity = await this.usersService.getById(userId);
        const roleEntity = await this.rolesService.getRole(role);

        const userHasRole = await this.isUserHasRole(userId, role);
        if (!userHasRole) throw new BadRequestException(`User doesn't have this role`);

        await this.userRoleRepository.delete({
            user: userEntity,
            role: roleEntity,
        });

        return true;
    }

    /**
     * Check if user has role
     * @param userId User ID
     * @param role Role to check
     * @returns True if user has role, false otherwise
     * @throws NotFoundException if user or role not found
     */
    async isUserHasRole(userId: string, role: Role): Promise<boolean> {
        const userEntity = await this.usersService.getById(userId);
        const roleEntity = await this.rolesService.getRole(role);

        const userRole = await this.userRoleRepository.findOne({
            where: {
                user: userEntity,
                role: roleEntity,
            },
        });

        return !!userRole;
    }

    async getUsersWithRole(role: Role): Promise<UserEntity[]> {
        const roleEntity = await this.rolesService.getRole(role);

        const usersWithRole = await this.userRoleRepository.find({
            where: {
                role: roleEntity,
            },
            relations: {
                user: true
            }
        });

        return usersWithRole.map(userRole => userRole.user);
    }

    async getUserRoles(userId: string): Promise<UserRoleEntity[]> {
        const userEntity = await this.usersService.getById(userId);

        const userRoles = await this.userRoleRepository.find({
            where: {
                user: userEntity,
            },
            relations: {
                role: true
            }
        });

        return userRoles;
    }
}
