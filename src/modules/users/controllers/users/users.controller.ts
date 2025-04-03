import { Body, ClassSerializerInterceptor, Controller, Delete, ForbiddenException, Get, Inject, Param, Patch, Post, UseGuards, UseInterceptors } from '@nestjs/common';
import { UsersService } from '../../services/users/users.service';
import CreateUserDto from '../../dto/CreateUser.dto';
import UpdateUserDto from '../../dto/UpdateUser.dto';
import { AccessJwtPassportAuthGuard } from 'src/modules/auth/guards/AccessJwtPassport.guard';
import { ScopeAccessGuard } from 'src/modules/roles/guards/ScopeAccess.guard';
import { Scopes } from 'src/modules/roles/decorators/Scopes.decorator';
import { Scope } from 'src/modules/roles/types';
import { User } from 'src/common/decorators/User.decorator';
import { SignInData } from 'src/modules/auth/types';

@Controller('users')
@UseInterceptors(ClassSerializerInterceptor)
@UseGuards(AccessJwtPassportAuthGuard, ScopeAccessGuard) // JWT first
export class UsersController {
    constructor(
        @Inject(UsersService) private readonly usersService: UsersService,
    ) {}

    // Get All

    @Get()
    @Scopes(Scope.UsersRead)
    getUsers() {
        return this.usersService.getAll();
    }

    // Get User

    @Get('me')
    @Scopes(Scope.UsersReadMe)
    getMe(
        @User() user: SignInData,
    ) {
        return this.usersService.getById(user.userId);
    }

    @Get('id/:id')
    @Scopes(Scope.UsersRead)
    getUserById(
        @Param('id') id: string,
    ) {
        return this.usersService.getById(id)
    }

    // Create

    @Post('create')
    createUser(
        @Body() user: CreateUserDto,
    ) {
        return this.usersService.createUser(user);
    }

    // Update

    @Patch('id/:id')
    @Scopes(Scope.UsersUpdate)
    updateUser(
        @Param('id') id: string,
        @Body() data: UpdateUserDto,
    ) {
        return this.usersService.updateUser(id, data);
    }

    @Patch('me')
    @Scopes(Scope.UsersUpdate)
    updateMe(
        @User() user: SignInData,
        @Body() data: UpdateUserDto,
    ) {
        return this.usersService.updateUser(user.userId, data);
    }

    // Delete

    @Delete('id/:id')
    @Scopes(Scope.UsersDelete)
    deleteUser(
        @Param('id') id: string,
    ) {
        return this.usersService.deleteUser(id);
    }

    @Delete('me')
    @Scopes(Scope.UsersDeleteMe)
    deleteMe(
        @User() user: SignInData,
        @Body() data: UpdateUserDto,
    ) {
        return this.usersService.updateUser(user.userId, data);
    }
    
}
