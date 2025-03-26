import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, UpdateDateColumn, OneToMany } from 'typeorm';
import { AccessTokenEntity } from './AccessToken.entity';

@Entity('refresh_tokens')
export class RefreshTokenEntity {
    @PrimaryGeneratedColumn('uuid')
    id: string;

    @Column({ type: 'uuid' })
    userId: string;

    @Column({ name: 'token_hash', type: 'text' })
    tokenHash: string;

    @OneToMany(() => AccessTokenEntity, (accessToken) => accessToken.relatedRefreshToken)
    accessTokens: AccessTokenEntity[];

    @CreateDateColumn()
    createdAt: Date;

    @UpdateDateColumn()
    updatedAt: Date;

    @Column({ type: 'timestamp', nullable: false })
    expiresAt: Date;
}