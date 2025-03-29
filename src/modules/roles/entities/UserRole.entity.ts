import { Entity, ManyToOne, PrimaryGeneratedColumn } from 'typeorm';
import UserEntity from '../../users/entities/user.entity';
import { RoleEntity } from './Role.entity';

@Entity('user_roles')
export class UserRoleEntity {
    @PrimaryGeneratedColumn('uuid')
    id: string;

    @ManyToOne(() => UserEntity, (user) => user.userRoles, { onDelete: 'CASCADE' })
    user: UserEntity;

    @ManyToOne(() => RoleEntity, (role) => role.userRoles, { onDelete: 'CASCADE' })
    role: RoleEntity;
}