import { Test, TestingModule } from '@nestjs/testing';
import { UsersController } from './users.controller';
import { UsersService } from '../../services/users/users.service';
import CreateUserDto from '../../dto/CreateUser.dto';
import UpdateUserDto from '../../dto/UpdateUser.dto';
import UserEntity from '../../entities/user.entity';

describe('UsersController', () => {
    let controller: UsersController;
    let service: UsersService;

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
            controllers: [UsersController],
            providers: [
                {
                    provide: UsersService,
                    useValue: {
                        getAll: jest.fn(),
                        getById: jest.fn(),
                        createUser: jest.fn(),
                        updateUser: jest.fn(),
                        deleteUser: jest.fn(),
                    },
                },
            ],
        }).compile();

        controller = module.get<UsersController>(UsersController);
        service = module.get<UsersService>(UsersService);
    });

    it('should be defined', () => {
        expect(controller).toBeDefined();
    });

    describe('getUsers', () => {
        it('should return a list of users', async () => {
            const mockUsers = [{ id: '1', firstname: 'John', lastname: 'Doe' }] as UserEntity[];
            jest.spyOn(service, 'getAll').mockResolvedValue(mockUsers);

            const result = await controller.getUsers();

            expect(service.getAll).toHaveBeenCalled();
            expect(result).toEqual(mockUsers);
        });
    });

    describe('getUserById', () => {
        it('should return a user by ID', async () => {
            const mockUser = { id: '1', firstname: 'John', lastname: 'Doe' } as UserEntity;
            jest.spyOn(service, 'getById').mockResolvedValue(mockUser);

            const result = await controller.getUserById('1');

            expect(service.getById).toHaveBeenCalledWith('1');
            expect(result).toEqual(mockUser);
        });
    });

    describe('createUser', () => {
        it('should create a new user', async () => {
            const createUserDto: CreateUserDto = {
                firstname: 'John',
                lastname: 'Doe',
                email: 'john.doe@example.com',
                confirm_email: 'john.doe@example.com',
                password: 'StrongP@ssw0rd',
                confirm_password: 'StrongP@ssw0rd',
            } as CreateUserDto;
            const { id, created_at, updated_at, ...userDetails } = createUserDto;
            const mockUser = {
                id: '1',
                created_at: new Date(),
                updated_at: new Date(),
                ...userDetails,
            } as any as UserEntity;
            jest.spyOn(service, 'createUser').mockResolvedValue(mockUser);

            const result = await controller.createUser(createUserDto);

            expect(service.createUser).toHaveBeenCalledWith(createUserDto);
            expect(result).toEqual(mockUser);
        });
    });

    describe('updateUser', () => {
        it('should update a user by ID', async () => {
            const updateUserDto: UpdateUserDto = {
                firstname: 'Jane',
                lastname: 'Doe',
                email: 'jane.doe@example.com',
                confirm_email: 'jane.doe@example.com',
                password: 'NewP@ssw0rd',
                confirm_password: 'NewP@ssw0rd',
            } as UpdateUserDto;
            const { id, created_at, updated_at, ...userDetails } = updateUserDto;
            const mockUser = { id: '1', ...userDetails } as any as UserEntity;
            jest.spyOn(service, 'updateUser').mockResolvedValue(mockUser);

            const result = await controller.updateUser('1', updateUserDto);

            expect(service.updateUser).toHaveBeenCalledWith('1', updateUserDto);
            expect(result).toEqual(mockUser);
        });
    });

    describe('deleteUser', () => {
        it('should delete a user by ID', async () => {
            jest.spyOn(service, 'deleteUser').mockResolvedValue(undefined);

            const result = await controller.deleteUser('1');

            expect(service.deleteUser).toHaveBeenCalledWith('1');
            expect(result).toBeUndefined();
        });
    });
});
