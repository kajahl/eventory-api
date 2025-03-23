import { IsEmail, IsEmpty, IsNotEmpty, IsOptional, Length } from 'class-validator';

export default class CreateUserDto {
    @IsEmpty()
    @IsOptional()
    id: undefined;

    @Length(2, 64)
    firstname: string;

    @Length(2, 64)
    lastname: string;

    @IsNotEmpty()
    @IsEmail()
    email: string;

    @IsNotEmpty()
    @IsEmail()
    confirm_email: string;

    @IsNotEmpty()
    @Length(6, 64)
    password: string;

    @IsNotEmpty()
    @Length(6, 64)
    confirm_password: string;

    @IsEmpty()
    @IsOptional()
    created_at: undefined;

    @IsEmpty()
    @IsOptional()
    updated_at: undefined;
}