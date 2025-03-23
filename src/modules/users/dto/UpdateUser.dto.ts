import { IsEmail, IsEmpty, IsNotEmpty, IsOptional, Length } from 'class-validator';

export default class UpdateUserDto {
    @IsEmpty()
    @IsOptional()
    id: undefined;

    @Length(2, 64)
    @IsOptional()
    firstname: string;

    @Length(2, 64)
    @IsOptional()
    lastname: string;

    @IsNotEmpty()
    @IsEmail()
    @IsOptional()
    email: string;

    @IsNotEmpty()
    @IsEmail()
    @IsOptional()
    confirm_email: string;

    @IsOptional()
    @IsNotEmpty()
    @Length(6, 64)
    password: string;

    @IsOptional()
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