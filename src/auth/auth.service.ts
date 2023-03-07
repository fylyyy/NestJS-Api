import {
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { PrismaService } from '../prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService,
  ) {}

  async signup(dto: AuthDto) {
    // generate password hash
    const hash = await argon.hash(dto.password);
    // save new user in db
    try {
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          hash,
        },
      });

      delete user.hash;

      // return user
      return user;
    } catch (error) {
      if (
        error instanceof
        Prisma.PrismaClientKnownRequestError
      ) {
        if (error.code === 'P2002') {
          throw new ForbiddenException(
            'User with this email already exists',
          );
        }
      }
      throw error;
    }
  }

  async signin(dto: AuthDto) {
    // find user by email
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });
    // if user does not exist throw exception
    if (!user)
      throw new ForbiddenException('Email incorrect');
    // compare passwords
    const pwMatches = await argon.verify(
      user.hash,
      dto.password,
    );
    // if password incorrect throw exception
    if (!pwMatches)
      throw new ForbiddenException('Password incorrect');
    //return token
    return this.signTokens(user.id, user.email);
  }

  async signTokens(
    userId: number,
    email: string,
  ): Promise<{
    access_token: string;
    refresh_token: string;
  }> {
    const payload = {
      sub: userId,
      email,
    };

    const access_token = await this.jwt.signAsync(payload, {
      expiresIn: '30m',
      secret: this.config.get('JWT_ACCESS_SECRET'),
    });

    const refresh_token = await this.jwt.signAsync(
      payload,
      {
        expiresIn: '5d',
        secret: this.config.get('JWT_REFRESH_SECRET'),
      },
    );

    const hash = await argon.hash(refresh_token);

    await this.prisma.user.update({
      where: {
        id: userId,
      },
      data: {
        refreshToken: hash,
      },
    });

    return { access_token, refresh_token };
  }

  async refreshTokens(
    userId: number,
    refreshToken: string,
  ): Promise<{
    access_token: string;
  }> {
    const user = await this.prisma.user.findUnique({
      where: {
        id: userId,
      },
    });

    if (!user || !user.refreshToken)
      throw new ForbiddenException('Access denied');

    const tokenMatches = await argon.verify(
      user.refreshToken,
      refreshToken,
    );

    if (!tokenMatches)
      throw new ForbiddenException('Access denied');

    return await this.signTokens(userId, user.email);
  }

  async logout(userId: number) {
    await this.prisma.user.update({
      where: {
        id: userId,
      },
      data: {
        refreshToken: null,
      },
    });
  }
}
