import { BadRequestException, Inject, Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import UserEntity from '../../entities/user.entity';
import { Repository } from 'typeorm';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class EmailService {
    constructor(
        @InjectRepository(UserEntity) private readonly userRepository: Repository<UserEntity>,
        @Inject(JwtService) private readonly jwtService: JwtService
    ) {}

    async createTokenForEmailRequestChange(userId: string, email: string): Promise<string> {
        const payload = { userId, email };
        return this.jwtService.sign(payload);
    }

    async isEmailTaken(email: string): Promise<boolean> {
        const user = await this.userRepository.findOne({
            where: { email }
        });
        return !!user;
    }

    async hasUserRequestedEmailChange(userId: string): Promise<boolean> {
        const user = await this.userRepository.findOne({
            where: { id: userId },
        });
        
        if (user == null) return false;
        if (user.pendingEmail == undefined) return false;
        // First email, there is no change request
        // User did not confirm first email
        if (user.pendingEmail == user.email) return false; 
        return true;
    }

    async hasUserVerifiedEmail(userId: string): Promise<boolean> {
        const user = await this.userRepository.findOne({
            where: { id: userId },
        });
        
        if (user == null) return false;
        if (user.pendingEmail !== undefined && user.email == user.pendingEmail) return false;
        return true;
    }

    async verifyEmail(email: string, confirmToken: string): Promise<boolean> {
        const isTokenValid = await this.jwtService.verifyAsync(confirmToken, {
            secret: process.env.JWT_SECRET
        }).catch(() => false);
        if (!isTokenValid) throw new BadRequestException('Invalid token');

        // There can be possibility someone request change email, then someone else create user with same email - it should be rejected if email is already taken (cannot verify email if already has been verified by someone else)
        const user = await this.userRepository.findOne({
            where: { 
                pendingEmail: email, 
                pendingEmailToken: confirmToken 
            },
        });

        if (user == null) return false;
        if(await this.isEmailTaken(email)) {
            user.pendingEmail = undefined;
            user.pendingEmailToken = undefined;
            await this.userRepository.save(user);
            throw new BadRequestException('Email already taken');
        }
        
        user.email = email;
        user.pendingEmail = undefined;
        user.pendingEmailToken = undefined;

        await this.userRepository.save(user);
        return true;
    }

    async setAndGetPendingEmailToken(user: UserEntity, email: string, overrideFirstEmail: boolean = false): Promise<string> {
        const token = await this.createTokenForEmailRequestChange(user.id, email);

        if(overrideFirstEmail) user.email = email;
        user.pendingEmail = email;
        user.pendingEmailToken = token;

        await this.userRepository.save(user);

        return token;
    }

    async requestEmailChange(userId: string, email: string): Promise<boolean> {
        const user = await this.userRepository.findOne({
            where: { id: userId },
        });

        if (user == null) return false;
        if (user.email === email) throw new BadRequestException('Email is already set to this email');

        // User want to change first email to another email & did not confirm first email
        if (user.email === user.pendingEmail) {
            // In this case both email fields fill be the same, we need to check if email is already taken
            if(await this.isEmailTaken(email)) throw new BadRequestException('Email already taken');
        }

        const token = this.setAndGetPendingEmailToken(user, email, user.email === user.pendingEmail);

        // TODO: Send email with token

        return true;
    }
}
