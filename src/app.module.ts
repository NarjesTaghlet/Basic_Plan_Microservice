

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
  host :configService.get<string>('DB_HOST'),
    port: configService.get<number>('DB_PORT'),
    username: configService.get<string>('DB_USERNAME'),
    password: configService.get<string>('DB_PASSWORD'),
    database: configService.get<string>('DB_NAME'),
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

