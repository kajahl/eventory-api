import { IsEnum, IsNotEmpty, IsString } from "class-validator";
import { TokenType } from "../types";

export default class VerifyTokenDto {
    @IsEnum(TokenType)
    @IsNotEmpty()
    type: TokenType

    @IsString()
    @IsNotEmpty()
    token: string
}