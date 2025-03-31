import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { UsersModule } from './modules/users/users.module';
import UserEntity from './modules/users/entities/user.entity';
import { AuthModule } from './modules/auth/auth.module';
import { RefreshTokenEntity } from './modules/auth/entities/RefreshToken.entity';
import { AccessTokenEntity } from './modules/auth/entities/AccessToken.entity';
import { ScheduleModule } from '@nestjs/schedule';
import { RolesModule } from './modules/roles/roles.module';
import { RoleEntity } from './modules/roles/entities/Role.entity';
import { UserRoleEntity } from './modules/roles/entities/UserRole.entity';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
    }),
    TypeOrmModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: async (configService: ConfigService) => ({
        type: 'postgres',
        host: configService.get<string>('DATABASE_HOST'),
        port: configService.get<number>('DATABASE_PORT'),
        username: configService.get<string>('DATABASE_USER'),
        password: configService.get<string>('DATABASE_PASSWORD'),
        database: configService.get<string>('DATABASE_NAME'),
        autoLoadEntities: true,
        synchronize: configService.get<boolean>('DATABASE_SYNCHRONIZE'),
        entities: [
            UserEntity,
            RoleEntity, UserRoleEntity,
            RefreshTokenEntity, AccessTokenEntity
        ],
      }),
    }),
    ScheduleModule.forRoot({
        cronJobs: true
    }),
    UsersModule,
    AuthModule,
    RolesModule
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
