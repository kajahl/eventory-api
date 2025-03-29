import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { RoleEntity } from '../../entities/Role.entity';
import { In, Repository } from 'typeorm';
import { Role, RolePriority } from '../../types';

@Injectable()
export class RolesService {
    constructor(
        @InjectRepository(RoleEntity) private readonly roleRepository: Repository<RoleEntity>,
    ) {}

    /**
     * Synchronize roles in the database with the roles defined in the enum
     * This method checks if all roles defined in the Role enum exist in the database.
     */
    async syncRolesInDatabase(): Promise<void> {
        const rolesToSync = Object.values(Role).map(role => ({ name: role }));
        const existingRoles = await this.roleRepository.find({ where: { name: In(rolesToSync.map(r => r.name)) } });
        const existingRoleNames = existingRoles.map(role => role.name);

        // Check if database contains roles that are not in the enum
        const rolesOnlyInDatabase = existingRoleNames.filter(role => !Object.values(Role).includes(role as Role));
        if (rolesOnlyInDatabase.length > 0) {
            throw new Error(`Roles in database not found in enum: ${rolesOnlyInDatabase.join(', ')}. Remove role from database or add to enum.`);
        }

        const missingRoles = rolesToSync.filter(role => !existingRoleNames.includes(role.name));
        missingRoles.forEach(r => {
            const roleEntity = new RoleEntity();
            roleEntity.name = r.name;
            roleEntity.priority = RolePriority[r.name as keyof typeof RolePriority] || 0;
            this.roleRepository.save(roleEntity).then(v => {
                console.log(`Added missing role: ${v.name} with priority ${v.priority} to the database with id ${v.id}`);
            }).catch(err => {
                throw new Error(`Error adding role ${r.name} to the database: ${err.message}.`);
            });
        });
    }

    /**
     * Get all roles from the database
     * @returns A promise that resolves to an array of RoleEntity objects
     */
    async getRoles(): Promise<RoleEntity[]> {
        return this.roleRepository.find();
    }

    /**
     * Get a role by its ID
     * @param role Role type to find
     * @returns A promise that resolves to a RoleEntity object
     * @throws NotFoundException if the role is not found
     */
    async getRole(role: Role): Promise<RoleEntity> {
        const roleEntity = await this.roleRepository.findOne({ where: { name: role } });
        if (!roleEntity) throw new NotFoundException(`Role ${role} not found`);
        return roleEntity;
    }
}