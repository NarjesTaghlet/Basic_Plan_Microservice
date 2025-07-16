import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';


async function bootstrap() {
  const app = await NestFactory.create(AppModule);
   //const app = await NestFactory.create(AppModule);
   app.enableCors({
     origin: 'http://localhost:4200', // ✅ Autoriser uniquement le frontend Angular
     methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
     allowedHeaders: 'Content-Type,Authorization',
     credentials: true, // ✅ Si besoin d'authentification (JWT, Cookies)
   });
 
  await app.listen(3032);
    //await app.listen(3003);

}
bootstrap();
