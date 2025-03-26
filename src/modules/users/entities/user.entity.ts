import { Exclude, Expose } from 'class-transformer';
import { Column, CreateDateColumn, Entity, PrimaryGeneratedColumn, UpdateDateColumn } from 'typeorm';

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
        return this.pendingEmail !== undefined && this.email !== this.pendingEmail;
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
        return this.pendingEmail !== undefined;
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
}
