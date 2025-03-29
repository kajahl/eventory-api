import { Column, Entity, OneToMany, PrimaryGeneratedColumn } from 'typeorm';
import { Role } from '../types';
import { UserRoleEntity } from './UserRole.entity';

@Entity('roles')
export class RoleEntity {
    @PrimaryGeneratedColumn('uuid')
    id: string;

    @Column({ type: 'enum', enum: Role, unique: true })
    name: Role;

    @Column({ type: 'int', default: 0 })
    priority: number;

    @OneToMany(() => UserRoleEntity, (userRole) => userRole.role)
    userRoles: UserRoleEntity[];
}