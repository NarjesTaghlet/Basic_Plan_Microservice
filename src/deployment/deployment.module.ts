import { Module } from '@nestjs/common';
import { DeploymentService } from './deployment.service';
import { DeploymentController } from './deployment.controller';
import { HttpModule } from '@nestjs/axios';
import { Deployment } from './entities/deployment.entity';
import { TypeOrmModule } from '@nestjs/typeorm';
import * as dotenv from 'dotenv';
import { TokenGuard } from './Guards/token-guard';

dotenv.config();
@Module({
  imports: [
    TypeOrmModule.forFeature([Deployment ]), // Import the User entity for TypeORM
    HttpModule,
  ],
  controllers: [DeploymentController],
  providers: [DeploymentService,TokenGuard], // Provide UserService and JwtStrategy
  exports: [DeploymentService], // Export UserService and PassportModule if needed in other modules
})
export class DeploymentModule {}
