import { Module } from '@nestjs/common';
import { UsersService } from './services/users/users.service';
import { UsersController } from './controllers/users/users.controller';
import { PasswordService } from './services/password/password.service';
import { EmailService } from './services/email/email.service';
import { TypeOrmModule } from '@nestjs/typeorm';
import UserEntity from './entities/user.entity';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule, ConfigService } from '@nestjs/config';

@Module({
    imports: [
        TypeOrmModule.forFeature([UserEntity]),
        JwtModule.registerAsync({
            imports: [ConfigModule],
            inject: [ConfigService],
            useFactory: async (configService: ConfigService) => ({
                secret: configService.get<string>('JWT_SECRET', 'jwt-secret'),
                signOptions: {
                    expiresIn: configService.get<string>('JWT_EXPIRES_IN', '1h'),
                },
            }),
        }),
    ],
    providers: [UsersService, PasswordService, EmailService],
    controllers: [UsersController],
    exports: [UsersService, PasswordService, EmailService],
})
export class UsersModule {}
