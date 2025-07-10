import { Injectable, CanActivate, ExecutionContext, HttpException, HttpStatus } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { firstValueFrom } from 'rxjs';

@Injectable()
export class TokenGuard implements CanActivate {
  constructor(private readonly httpService: HttpService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const access_token = request.headers['authorization']?.replace('Bearer ', '');
    if (!access_token) {
      throw new HttpException('No token provided', HttpStatus.UNAUTHORIZED);
    }

  const userServiceUrl = process.env.USER_SERVICE_URL || 'http://localhost:3030';


    try {
      const response = await firstValueFrom(
        this.httpService.post(`${userServiceUrl}/auth/verify`, { access_token }, {
          headers: { 'Content-Type': 'application/json' },
        }),
      );
      console.log('TokenGuard response:', response.data); // Debug
      request.user = response.data; // { userId, username }
      return true;
    } catch (error) {
      console.error('TokenGuard error:', error.message); // Debug
      throw new HttpException('Invalid token', HttpStatus.UNAUTHORIZED);
    }
  }
}
