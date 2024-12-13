// src/guards/auth.guard.ts
import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(private jwtService: JwtService) {}

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest(); // Get the request object
    const token = request.headers.authorization?.split(' ')[1]; // Extract Bearer token from the 'Authorization' header

    if (!token) {
      return false; // If no token is present, deny access
    }

    try {
      // Verify the token using JwtService
      const user = this.jwtService.verify(token); // Decode and verify the JWT
      request.user = user; // Attach the decoded user to the request object
      return true; // If token is valid, grant access
    } catch (e) {
      return false; // If token is invalid or expired, deny access
    }
  }
}
