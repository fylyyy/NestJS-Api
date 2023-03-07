import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { GetUser } from './decorator';
import { AuthDto } from './dto';
import {
  AccessGuard,
  RefreshTokenGuard,
} from '../auth/guard/index';
import { User } from '@prisma/client';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('signup')
  signup(@Body() dto: AuthDto) {
    return this.authService.signup(dto);
  }

  @HttpCode(HttpStatus.OK)
  @Post('signin')
  signin(@Body() dto: AuthDto) {
    return this.authService.signin(dto);
  }

  @UseGuards(AccessGuard)
  @HttpCode(HttpStatus.OK)
  @Post('logout')
  logout(@GetUser('id') userId: number) {
    return this.authService.logout(userId);
  }

  @UseGuards(RefreshTokenGuard)
  @HttpCode(HttpStatus.OK)
  @Get('refresh')
  refresh(
    @GetUser('id') userId: number,
    @GetUser('refreshToken') refreshToken: string,
  ) {
    return this.authService.refreshTokens(
      userId,
      refreshToken,
    );
  }
}
