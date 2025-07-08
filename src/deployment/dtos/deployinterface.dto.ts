import { IsNotEmpty } from 'class-validator';


export class DeployInfrastructureDto {

    @IsNotEmpty()
    userId : number
    @IsNotEmpty()
    siteId : number

    @IsNotEmpty()
    siteName :string
  
}