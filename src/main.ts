import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import * as session from 'express-session';
import * as cookieParser from 'cookie-parser';
import * as cors from 'cors';

async function bootstrap() {
    const app = await NestFactory.create(AppModule);
    app.use(
        cors({
            origin: '*',
            credentials: true,
        }),
    );
    app.use(cookieParser());
    app.use(
        session({
            secret: process.env.SESSION_SECRET ?? 'my-secret',
            resave: false,
            saveUninitialized: false,
            cookie: {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                maxAge: 24 * 60 * 60 * 1000,
            },
        }),
    );
    app.useGlobalPipes(new ValidationPipe());

    await app.listen(process.env.PORT ?? 3000);
}
bootstrap();
