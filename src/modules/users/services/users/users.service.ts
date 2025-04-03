import { Injectable, NotFoundException, BadRequestException, Inject } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import UserEntity from '../../entities/user.entity';
import CreateUserDto from '../../dto/CreateUser.dto';
import { PasswordService } from '../password/password.service';
import UpdateUserDto from '../../dto/UpdateUser.dto';
import { EmailService } from '../email/email.service';

@Injectable()
export class UsersService {
    constructor(
        @InjectRepository(UserEntity)
        private readonly userRepository: Repository<UserEntity>,
        @Inject(PasswordService)
        private readonly passwordService: PasswordService,
        @Inject(EmailService) private readonly emailService: EmailService,
    ) {}

    /**
     * Create a new user
     * @param createUserDto CreateUserDto
     * @returns UserEntity
     */
    async createUser(createUserDto: CreateUserDto): Promise<UserEntity> {
        const { password, confirm_password, email, confirm_email, firstname, lastname } = createUserDto;

        if (await this.emailService.isEmailTaken(email)) throw new BadRequestException('Email already in use');
        if (email !== confirm_email) throw new BadRequestException('Email and confirm email do not match');
        if (password !== confirm_password) throw new BadRequestException('Password and confirm password do not match');
        const passwordErrors = this.passwordService.checkPasswordStrengthWithMessage(password);
        if (passwordErrors.length !== 0) throw new BadRequestException(`Password is too weak: ${passwordErrors.join(', ')}`);

        const newUser = this.userRepository.create({
            firstname: firstname,
            lastname: lastname,
            password: this.passwordService.hashPasswordSync(password),
            email: email,
            createdAt: new Date(),
            updatedAt: new Date(),
        });
        const savedUser = await this.userRepository.save(newUser);

        const token = this.emailService.setAndGetPendingEmailToken(savedUser, email);
        // TODO: Send token to email

        return savedUser;
    }

    /**
     * Get all users
     * @returns UserEntity[]
     */
    async getAll(): Promise<UserEntity[]> {
        const users = await this.userRepository.find();
        return users;
    }

    /**
     * Get user by ID
     * @param id User ID
     * @returns UserEntity
     * @throws NotFoundException if user not found
     */
    async getById(id: string): Promise<UserEntity> {
        const user = await this.userRepository.findOne({ where: { id } });
        if (!user) throw new NotFoundException(`User with ID ${id} not found`);
        return user;
    }

    /**
     * Get user by email
     * @param email User email
     * @returns UserEntity
     * @throws NotFoundException if user not found
     */
    async getByEmail(email: string): Promise<UserEntity> {
        const user = await this.userRepository.findOne({ where: { email } });
        if (!user) throw new NotFoundException(`User with email ${email} not found`);
        return user;
    }

    /**
     * Find user by partial data
     * @param user Partial user data or array of partial user data
     * @returns UserEntity | null
     */
    async find(user: Partial<UserEntity> | Partial<UserEntity>[]): Promise<UserEntity | null> {
        const found = this.userRepository.findOne({ where: user });
        return found;
    }

    /**
     * Update user by ID
     * @param id User ID
     * @param updateUserDto UpdateUserDto
     * @returns UserEntity
     * @throws NotFoundException if user not found
     * @throws BadRequestException if email or password is invalid
     * @throws BadRequestException if email is already taken
     * @throws BadRequestException if email and confirm email do not match
     * @throws BadRequestException if password and confirm password do not match
     * @throws BadRequestException if password is too weak
     */
    async updateUser(id: string, updateUserDto: UpdateUserDto): Promise<UserEntity> {
        const user = await this.getById(id);
        const { email, confirm_email } = updateUserDto;
        if (email) {
            if (email !== confirm_email) throw new BadRequestException('Email and confirm email do not match');
            if (await this.emailService.isEmailTaken(email)) throw new BadRequestException('Email already in use');
        }

        const { password, confirm_password } = updateUserDto;
        if (password) {
            if (password !== confirm_password) throw new BadRequestException('Password and confirm password do not match');
            if (this.passwordService.isPasswordStrong(password)) throw new BadRequestException('Password is too weak');
        }

        // Fields to update
        const { firstname, lastname } = updateUserDto;

        if (firstname) user.firstname = firstname;
        if (lastname) user.lastname = lastname;
        if (email) await this.emailService.requestEmailChange(user.id, email);
        if (password) user.password = this.passwordService.hashPasswordSync(password);
        user.updatedAt = new Date();

        const savedUser = await this.userRepository.save(user);
        return savedUser;
    }

    /**
     * Delete user by ID
     * @param id User ID
     * @returns boolean
     * @throws NotFoundException if user not found
     */
    async deleteUser(id: string): Promise<boolean> {
        const user = await this.getById(id);
        await this.userRepository.remove(user);
        return true;
    }
}
