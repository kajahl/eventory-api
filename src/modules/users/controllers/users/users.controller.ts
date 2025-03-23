import { Body, ClassSerializerInterceptor, Controller, Delete, Get, Inject, Param, Patch, Post, UseInterceptors } from '@nestjs/common';
import { UsersService } from '../../services/users/users.service';
import CreateUserDto from '../../dto/CreateUser.dto';
import UpdateUserDto from '../../dto/UpdateUser.dto';

@Controller('users')
@UseInterceptors(ClassSerializerInterceptor)
export class UsersController {
    constructor(
        @Inject(UsersService) private readonly usersService: UsersService,
    ) {}

    @Get()
    getUsers() {
        return this.usersService.getAll();
    }

    @Get('id/:id')
    getUserById(
        @Param('id') id: string,
    ) {
        return this.usersService.getById(id)
    }

    @Post('create')
    createUser(
        @Body() user: CreateUserDto,
    ) {
        return this.usersService.createUser(user);
    }

    @Patch('id/:id')
    updateUser(
        @Param('id') id: string,
        @Body() user: UpdateUserDto,
    ) {
        return this.usersService.updateUser(id, user);
    }

    @Delete('id/:id')
    deleteUser(
        @Param('id') id: string,
    ) {
        return this.usersService.deleteUser(id);
    }
    
}
