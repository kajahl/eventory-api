import { Test, TestingModule } from '@nestjs/testing';
import { UsersService } from './users.service';
import { Repository } from 'typeorm';
import { getRepositoryToken } from '@nestjs/typeorm';
import UserEntity from '../../entities/user.entity';
import { EmailService } from '../email/email.service';
import { PasswordService } from '../password/password.service';
import { BadRequestException, NotFoundException } from '@nestjs/common';
import CreateUserDto from '../../dto/CreateUser.dto';
import UpdateUserDto from '../../dto/UpdateUser.dto';

describe('UsersService', () => {
    let service: UsersService;
    let userRepository: Repository<UserEntity>;
    let emailService: EmailService;
    let passwordService: PasswordService;

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
            providers: [
                UsersService,
                {
                    provide: getRepositoryToken(UserEntity),
                    useClass: Repository,
                },
                {
                    provide: EmailService,
                    useValue: {
                        isEmailTaken: jest.fn(),
                        setAndGetPendingEmailToken: jest.fn(),
                        requestEmailChange: jest.fn(),
                    },
                },
                {
                    provide: PasswordService,
                    useValue: {
                        checkPasswordStrengthWithMessage: jest.fn(),
                        hashPasswordSync: jest.fn(),
                        isPasswordStrong: jest.fn(),
                    },
                },
            ],
        }).compile();

        service = module.get<UsersService>(UsersService);
        userRepository = module.get<Repository<UserEntity>>(getRepositoryToken(UserEntity));
        emailService = module.get<EmailService>(EmailService);
        passwordService = module.get<PasswordService>(PasswordService);
    });

    it('should be defined', () => {
        expect(service).toBeDefined();
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
            const { id, updated_at, created_at, ...createUserDtoWithoutId } = createUserDto;
            const mockUser = {
                id: '1',
                updatedAt: new Date(),
                createdAt: new Date(),
                ...createUserDtoWithoutId,
            } as any as UserEntity;

            jest.spyOn(emailService, 'isEmailTaken').mockResolvedValue(false);
            jest.spyOn(passwordService, 'checkPasswordStrengthWithMessage').mockReturnValue([]);
            jest.spyOn(passwordService, 'hashPasswordSync').mockReturnValue('hashedPassword');
            jest.spyOn(userRepository, 'create').mockReturnValue(mockUser);
            jest.spyOn(userRepository, 'save').mockResolvedValue(mockUser);

            const result = await service.createUser(createUserDto);

            expect(emailService.isEmailTaken).toHaveBeenCalledWith(createUserDto.email);
            expect(passwordService.checkPasswordStrengthWithMessage).toHaveBeenCalledWith(createUserDto.password);
            expect(passwordService.hashPasswordSync).toHaveBeenCalledWith(createUserDto.password);
            expect(userRepository.create).toHaveBeenCalledWith({
                firstname: createUserDto.firstname,
                lastname: createUserDto.lastname,
                password: 'hashedPassword',
                email: createUserDto.email,
                createdAt: expect.any(Date),
                updatedAt: expect.any(Date),
            });
            expect(userRepository.save).toHaveBeenCalledWith(mockUser);
            expect(result).toEqual(mockUser);
        });

        it('should throw BadRequestException if email is already taken', async () => {
            const createUserDto: CreateUserDto = {
                firstname: 'John',
                lastname: 'Doe',
                email: 'john.doe@example.com',
                confirm_email: 'john.doe@example.com',
                password: 'StrongP@ssw0rd',
                confirm_password: 'StrongP@ssw0rd',
            } as CreateUserDto;

            jest.spyOn(emailService, 'isEmailTaken').mockResolvedValue(true);

            await expect(service.createUser(createUserDto)).rejects.toThrow(BadRequestException);
            expect(emailService.isEmailTaken).toHaveBeenCalledWith(createUserDto.email);
        });
    });

    describe('getAll', () => {
        it('should return all users', async () => {
            const mockUsers = [{ id: '1', firstname: 'John', lastname: 'Doe' }] as UserEntity[];
            jest.spyOn(userRepository, 'find').mockResolvedValue(mockUsers);

            const result = await service.getAll();

            expect(userRepository.find).toHaveBeenCalled();
            expect(result).toEqual(mockUsers);
        });
    });

    describe('getById', () => {
        it('should return a user by ID', async () => {
            const mockUser = { id: '1', firstname: 'John', lastname: 'Doe' } as UserEntity;
            jest.spyOn(userRepository, 'findOne').mockResolvedValue(mockUser);

            const result = await service.getById('1');

            expect(userRepository.findOne).toHaveBeenCalledWith({ where: { id: '1' } });
            expect(result).toEqual(mockUser);
        });

        it('should throw NotFoundException if user is not found', async () => {
            jest.spyOn(userRepository, 'findOne').mockResolvedValue(null);

            await expect(service.getById('1')).rejects.toThrow(NotFoundException);
            expect(userRepository.findOne).toHaveBeenCalledWith({ where: { id: '1' } });
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
            const mockUser = { id: '1', firstname: 'John', lastname: 'Doe' } as UserEntity;

            jest.spyOn(service, 'getById').mockResolvedValue(mockUser);
            jest.spyOn(emailService, 'isEmailTaken').mockResolvedValue(false);
            jest.spyOn(passwordService, 'hashPasswordSync').mockReturnValue('hashedPassword');
            jest.spyOn(userRepository, 'save').mockResolvedValue(mockUser);

            const result = await service.updateUser('1', updateUserDto);

            expect(service.getById).toHaveBeenCalledWith('1');
            expect(emailService.isEmailTaken).toHaveBeenCalledWith(updateUserDto.email);
            expect(passwordService.hashPasswordSync).toHaveBeenCalledWith(updateUserDto.password);
            expect(userRepository.save).toHaveBeenCalledWith(mockUser);
            expect(result).toEqual(mockUser);
        });
    });

    describe('deleteUser', () => {
        it('should delete a user by ID', async () => {
            const mockUser = { id: '1', firstname: 'John', lastname: 'Doe' } as UserEntity;

            jest.spyOn(service, 'getById').mockResolvedValue(mockUser);
            jest.spyOn(userRepository, 'remove').mockResolvedValue(mockUser);

            await service.deleteUser('1');

            expect(service.getById).toHaveBeenCalledWith('1');
            expect(userRepository.remove).toHaveBeenCalledWith(mockUser);
        });
    });
});
