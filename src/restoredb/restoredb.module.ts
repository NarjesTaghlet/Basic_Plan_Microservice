import { Module } from '@nestjs/common';
import { RestoredbService } from './restoredb.service';
import { RestoredbController } from './restoredb.controller';
import { HttpModule } from '@nestjs/axios';
import { TokenGuard } from 'src/deployment/Guards/token-guard';
import { DeploymentModule } from 'src/deployment/deployment.module';
import { Deployment } from 'src/deployment/entities/deployment.entity';
import { TypeOrmModule } from '@nestjs/typeorm';

@Module({
  imports: [
        TypeOrmModule.forFeature([Deployment ]), // Import the User entity for TypeORM
    
      HttpModule,
    ],
  providers: [RestoredbService,TokenGuard],
  controllers: [RestoredbController],
  exports :[RestoredbService]
  
})
export class RestoredbModule {}
