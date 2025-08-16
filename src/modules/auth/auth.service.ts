import {
  ConflictException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { SendOtpDto } from './dto/send-otp.dto';
import { OtpService } from './otp.service';
import { LoginAuthDto } from './dto/create-auth.dto';
import { PrismaService } from 'src/core/database/prisma.service';
import bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { RegisterDto } from './dto/register-auth.dto';

@Injectable()
export class AuthService {
  constructor(
    private otpService: OtpService,
    private readonly db: PrismaService,
    private readonly jwt: JwtService,
  ) {}
  async sendOtp(body: SendOtpDto) {
    const { phone_number } = body;
    const data = await this.otpService.sendSms(phone_number);
    return data;
  }
  async verifyOtp(phone_number: string, code: string) {
    await this.otpService.isBlockedUser(phone_number);
    await this.otpService.verifyOtpCode(phone_number, code);
    return {
      message: 'success',
    };
  }

  async login(loginAuthDto: LoginAuthDto) {
    const findEmail = await this.db.prisma.user.findUnique({
      where: {
        email: loginAuthDto.email,
      },
    });

    if (!findEmail) throw new NotFoundException('Email or password incorrect');

    const comparePassword = await bcrypt.compare(
      loginAuthDto.password,
      findEmail.password,
    );

    if (!comparePassword)
      throw new NotFoundException('Email or password incorrect');

    const token = await this.jwt.signAsync({ userId: findEmail.id });

    return token;
  }

  async register(userData: RegisterDto) {
    const findEmail = await this.db.prisma.user.findFirst({
      where: { email: userData.email },
    });
    if (findEmail) throw new ConflictException('this email already existed!');
    const hashedPassword = await bcrypt.hash(userData.password, 12);
    const { id, email } = await this.db.prisma.user.create({
      data: { ...userData, password: hashedPassword },
    });
    return { message: 'success', data: { id, email } };
  }
}
