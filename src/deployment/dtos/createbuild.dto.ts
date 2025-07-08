import { IsNumber,IsString } from "class-validator";


export class CreateCodeBuildDto {
    @IsNumber()
    userId: number;
  
    @IsString()
    siteName: string;
  
    @IsString()
    userRepoUrl: string;
  
    @IsString()
    githubPat: string; // Add PAT to the DTO
  }