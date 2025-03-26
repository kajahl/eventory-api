import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, UpdateDateColumn, ManyToOne } from 'typeorm';
import { RefreshTokenEntity } from './RefreshToken.entity';

@Entity('access_tokens')
export class AccessTokenEntity {
    @PrimaryGeneratedColumn('uuid')
    id: string;

    @Column({ type: 'uuid' })
    userId: string;

    @Column({ name: 'token_hash', type: 'text' })
    tokenHash: string;
    
    @ManyToOne(() => RefreshTokenEntity, (refreshToken) => refreshToken.accessTokens, {
        onDelete: 'CASCADE',
    })
    relatedRefreshToken: RefreshTokenEntity;

    @CreateDateColumn()
    createdAt: Date;

    @UpdateDateColumn()
    updatedAt: Date;

    @Column({ type: 'timestamp', nullable: false })
    expiresAt: Date;
}