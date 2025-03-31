import { Exclude, Expose } from 'class-transformer';
import { UserRoleEntity } from 'src/modules/roles/entities/UserRole.entity';
import { Column, CreateDateColumn, Entity, OneToMany, PrimaryGeneratedColumn, UpdateDateColumn } from 'typeorm';

@Entity('users')
export default class UserEntity {
    @PrimaryGeneratedColumn('uuid')
    id: string;

    @Column({ name: 'firstname', type: 'varchar', length: 64 })
    firstname: string;

    @Column({ name: 'lastname', type: 'varchar', length: 64 })
    lastname: string;

    /*
    Email is assigned while creating the user - it does not mean the user has verified the email.
    If PendingEmail is not null, it means that the user need to verify the new email + PendingEmailToken should contain token to verify the new email.
    PendingEmailToken is used to verify the new email.
    If PendingEmail is null, it means that the user has verified the email and there is no request for changing the email.
  */

    @Column({ name: 'email', type: 'varchar', length: 128, unique: true })
    email: string;

    @Expose()
    get isEmailConfirmed(): boolean {
        return this.email !== this.pendingEmail;
    }

    @Exclude()
    @Column({
        name: 'pending_email',
        type: 'varchar',
        length: 128,
        nullable: true,
    })
    pendingEmail?: string;

    @Column({ name: 'pending_email_token', nullable: true })
    @Exclude()
    pendingEmailToken?: string;

    @Expose()
    get isEmailChangeRequested(): boolean {
        return this.pendingEmail?.length !== 0 && this.email !== this.pendingEmail;
    }

    @Column({ name: 'password' })
    @Exclude()
    password: string;

    @CreateDateColumn({ name: 'created_at', type: 'timestamp' })
    createdAt: Date;

    @UpdateDateColumn({ name: 'updated_at', type: 'timestamp' })
    updatedAt: Date;

    constructor(partial: Partial<UserEntity>) {
        Object.assign(this, partial);
    }

    @Expose()
    get fullName(): string {
        return `${this.firstname} ${this.lastname}`;
    }

    @OneToMany(() => UserRoleEntity, (userRole) => userRole.user)
    userRoles: UserRoleEntity[];
}
