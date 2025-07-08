

import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { DeploymentModule } from './deployment/deployment.module';
import * as dotenv from 'dotenv';
import { Deployment } from './deployment/entities/deployment.entity';
import { UpgradeService } from './upgrade/upgrade.service';
import { UpgradeModule } from './upgrade/upgrade.module';
import { RestoredbModule } from './restoredb/restoredb.module';
dotenv.config();

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: '.env', // Change à '.env' si à la racine, ou garde 'src/.env' si dans src/
    }),
    TypeOrmModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => {
        console.log('SECRET_KEY in TypeOrm config:', process.env.SECRET_KEY); // Debug
        return {
          type: 'mysql',
    //host: 'localhost',
    host : process.env.DB_HOST,
    port: 3307,
    username: 'root',
    password: '',
    database: 'deployment',
    entities: [Deployment],
    synchronize: true,
        };
      },
      inject: [ConfigService],
    }),
   DeploymentModule,
   UpgradeModule,
   RestoredbModule
  ],
  controllers: [AppController],
  providers: [AppService, UpgradeService], // Retire JwtStrategy d'ici
})
export class AppModule {
  constructor(configService: ConfigService) {
    console.log('SECRET_KEY in AppModule:', configService.get('SECRET_KEY')); // Debug
  }
}

