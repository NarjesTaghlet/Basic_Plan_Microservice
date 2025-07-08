import { Controller, Post, Body, HttpException, HttpStatus,Delete,Get,Req,Query,Res } from '@nestjs/common';
import { DeploymentService } from './deployment.service';
import { DeployInfrastructureDto } from './dtos/deployinterface.dto';
import logger from '../utils/logger';
import { Headers } from '@nestjs/common'; // Pour le décorateur
import { Param } from '@nestjs/common';
import { Deployment } from './entities/deployment.entity';
//import { Request } from 'aws-sdk';
import { Request, UseGuards } from '@nestjs/common';
import { TokenGuard } from './Guards/token-guard';
import { Response } from 'express';
import { AxiosResponse , AxiosError} from 'axios';
import { AwsCredentialsResponse } from './interfaces/aws-credentials.interface';
import { HttpService } from '@nestjs/axios';
import { firstValueFrom } from 'rxjs';
import { CreateCodeBuildDto } from './dtos/createbuild.dto';
import { Token } from 'aws-sdk';

interface TestCodePipelineDto {
  userId: number;
  siteName: string;
  userRepoUrl: string;
  orgRepoUrl: string;
  githubPat: string;
}

interface DeployRequest {
  userId : number ;
  siteName: string;
  cloudflareDomain: string;
  selectedStack: string;
}

interface DeployResponse {
  instancePublicIp: string;
  userRepoUrl: string;
  deploymentId: number;
  secretsManagerArn: string;
}


 interface MetricDataPoint {
  timestamp: string;
  average: number;
}

interface SiteStats {
  cpuUsage: MetricDataPoint[];
  memoryUsage: MetricDataPoint[];
  networkIn: MetricDataPoint[];
  networkOut: MetricDataPoint[];
  uptimeSeconds: number;
}

@Controller('deployment')
export class DeploymentController {
  constructor(private readonly deploymentService: DeploymentService, private httpService: HttpService,) {}

 /* @Post()
  async deployInfrastructure(@Body() deployInfrastructureDto: DeployInfrastructureDto): Promise<{ s3BucketName: string }> {
    try {
      const { userId, siteId, siteName } = deployInfrastructureDto;
      logger.info(`Received request to deploy infrastructure: user_id=${userId}, site_id=${siteId}, site_name=${siteName}`);

      const result = await this.deploymentService.deployInfrastructure(userId, siteId, siteName);
      logger.info(`Successfully deployed infrastructure: s3BucketName=${result.s3BucketName}`);

      return result;
    } catch (error) {
      logger.error(`Failed to deploy infrastructure: ${error.message}`);
      throw new HttpException(
        `Failed to deploy infrastructure: ${error.message}`,
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }
    */

  /*@Post('final')
  async deploy(@Body() body: DeployRequest): Promise<DeployResponse> {
    try {
      const result = await this.deploymentService.deployInfrastructureAndSetupGitHub(body);
      return result;
    } catch (error) {
      throw new HttpException(
        `Deployment failed: ${error.message}`,
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }
    */


  // deployment.controller.ts
/*@Post('prepare-backend/:userId')
async prepareRemoteBackend(
  @Param('userId') userId: number
) {
  try {
    const result = await this.deploymentService.prepareremotebackend(
      userId,
    );

    return {
      statusCode: HttpStatus.CREATED,
      message: 'Infrastructure successfully provisioned',
      data: result
    };
  } catch (error) {
  }
}*/



  @UseGuards(TokenGuard)
  @Post('prepare-backend')
  async prepareRemoteBackend(@Req() req) {
    try {
      const userId = req.user.id; // Extrait de req.user (JWT)
      if (!userId) {
        throw new HttpException('User ID not found in token', HttpStatus.UNAUTHORIZED);
      }

      const result = await this.deploymentService.prepareremotebackend(userId);

      return {
        statusCode: HttpStatus.CREATED,
        message: 'Infrastructure successfully provisioned',
        data: result,
      };
    } catch (error) {
      throw new HttpException(
        `Failed to provision infrastructure: ${error.message}`,
        error.status || HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }


  /*@Post('final')
  async createDeployment(@Body() createDeploymentDto: DeployRequest) {
    const { userId, siteName, cloudflareDomain, selectedStack } = createDeploymentDto;

    return this.deploymentService.createDeployment(
      userId,
      siteName,
      cloudflareDomain,
      selectedStack,
    );
  }
   */

  @UseGuards(TokenGuard)
  @Post('final')
  async createDeployment(@Body() createDeploymentDto: DeployRequest, @Request() req) {
    const { siteName, cloudflareDomain, selectedStack } = createDeploymentDto;

    // Extract the authenticated user's ID from the token
    const userId = req.user.userId;

    return this.deploymentService.createDeployment(
      userId,
      siteName,
      cloudflareDomain,
      selectedStack,
    );
  }
  
/*  @UseGuards(TokenGuard)
  @Post('deploy')
  async deploySite(
    @Body() createDeploymentDto: DeployRequest, @Request() req , @Res() res: Response,
  ) {
    const { siteName, cloudflareDomain, selectedStack } = createDeploymentDto;

    // Extract the authenticated user's ID from the token
    const userId = req.user.userId;
    try {
      const deployment = await this.deploymentService.createDeployment(
        userId,
        siteName,
        cloudflareDomain,
        selectedStack,
      );

      //await this.deploymentService.deployInfrastructureAndSetupGitHub(deployment);
    } catch (error) {
      if (error instanceof HttpException && error.getStatus() === HttpStatus.TEMPORARY_REDIRECT) {
        const response = error.getResponse();
        res.status(HttpStatus.TEMPORARY_REDIRECT).json(response);
      } else {
        res.status(500).json({ error: `Failed to deploy site: ${error.message}` });
      }
    }
  }
   */
  
  
//get all deployment of the user 
    //@UseGuards(JwtAuthGuard)
    @Get('GetAll/:userId')
    async getUserDeployments(@Param('userId')  userId : number): Promise<Deployment[]> {
      const deployments = await this.deploymentService.findAllForUser(userId);
      return deployments;
    }

  @Get('sites')
  @UseGuards(TokenGuard)
  async getSites(@Req() request: any) :Promise<Deployment[]> {
    const userId = request.user.userId;
    console.log(userId)
    const deployments = await this.deploymentService.findAllForUser(userId);
    return deployments;
  }


  @Get(':id')
  async findOne(@Param('id') id: number): Promise<Deployment> {
    try {
      return await this.deploymentService.findOne(id);
    } catch (error) {
      throw new HttpException(
        `Failed to fetch deployment: ${error.message}`,
        HttpStatus.NOT_FOUND,
      );
    }
  }


  /*@Post()
  async deployInfrastructure(@Body() deployInfrastructureDto: DeployInfrastructureDto): Promise<{
    instancePublicIp: string;
    databaseEndpoint: string;
    databasePort: number;
    databaseName: string;
    databaseUsername: string;
    databasePassword: string;
    dnsRecord: string;
    wwwDnsRecord: string | null;
    instanceName: string;
  }> {
    try {
      const { userId, siteId, siteName } = deployInfrastructureDto;
      logger.info(`Deploying infrastructure: user_id=${userId}, site_id=${siteId}, site_name=${siteName}`);

      const result = await this.deploymentService.deployInfrastructure(userId, siteName);
      logger.info(`Deployed infrastructure: instance_public_ip=${result.instancePublicIp}`);

      return {
        instancePublicIp: result.instancePublicIp,
        databaseEndpoint: result.databaseEndpoint,
        databasePort: result.databasePort,
        databaseName: result.databaseName,
        databaseUsername: result.databaseUsername,
        databasePassword: result.databasePassword,
        dnsRecord: result.dnsRecord,
        wwwDnsRecord: result.wwwDnsRecord,
        instanceName: result.instanceName,
      };
    } catch (error) {
      logger.error(`Failed to deploy: ${error.message}`);
      throw new HttpException(`Failed to deploy infrastructure: ${error.message}`, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }
*/
@Delete('test-delete')
  async destroyInfrastructure(@Body() body : { userId : number , siteName : string , deploymentId : number ,terraformDir : string ,region : string,secretName : string ,key : string ,devregion : string }): Promise<void> {
    try {
      const {userId, siteName ,deploymentId,terraformDir,region,secretName,key,devregion} = body ;
      logger.info(`Destroying infrastructure: user_id=${userId},, site_name=${siteName}`);
      await this.deploymentService.destroyInfrastructure(userId, siteName ,deploymentId,terraformDir,region,secretName,key,devregion);
      logger.info(`Infrastructure destroyed successfully`);
    } catch (error) {
      logger.error(`Failed to destroy: ${error.message}`);
      throw new HttpException(`Failed to destroy infrastructure: ${error.message}`, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  @Delete(':id')
  async delete(@Param('id') id: string): Promise<void> {
    try {
      await this.deploymentService.deleteSite(parseInt(id));
    } catch (error) {
      throw new HttpException(
        `Failed to delete deployment: ${error.message}`,
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }


 /* @Post('create')
  // @UseGuards(JwtAuthGuard) // Décommente si tu veux sécuriser avec JWT
  async createDeployment(
    @Body() body: { userId: string; siteId: string; githubUsername?: string },
  ): Promise<{ repoUrl: string; cloneCommand: string }> {
    const { userId, siteId, githubUsername } = body;

    // Validation simple des paramètres
    if (!userId || !siteId) {
      throw new Error('userId and siteId are required');
    }

    // Appel au service
    return this.deploymentService.createUserDeployment(userId, siteId, githubUsername);
  }
    */

  /*@Post('trigger')
  async triggerDeployment() {
    await this.deploymentService.triggerDeployment();
    return { message: 'Deployment triggered successfully' };
  }
    */
  

   // Endpoint pour configurer les repos GitHub

  // Endpoint pour configurer les repos GitHub
  @Post('setup')
  async setupDeployment(
    @Body('userGithubToken') userGithubToken: string,
        @Body('userGithubUsername') userGithubUsername: string,
              @Body('orgTemplateRepo') orgTemplateRepo :string,

    @Body('userId') userId: number,
    @Body('siteName') siteName: string,
  ) {
    if (!userId || !siteName) {
      throw new HttpException('userId and siteId are required', HttpStatus.BAD_REQUEST);
    }
    const result = await this.deploymentService.generateUserRepoFromOrgTemplate( userGithubToken,
  userGithubUsername,
  orgTemplateRepo, // e.g., 'drupal-org-repo'
  siteName,
userId)
    return {
      message: 'GitHub repositories and webhook setup completed',
    };
  }

  // Endpoint pour gérer le webhook GitHub
 /* @Post('github')
  async handleGithubWebhook(
    @Headers('x-github-event') event: string,
    @Headers('x-hub-signature-256') signature: string,
    @Body() payload: any,
  ) {
    if (!this.deploymentService.verifySignature(signature, payload)) {
      throw new HttpException('Invalid signature', HttpStatus.UNAUTHORIZED);
    }
    if (event === 'push') {
      const userRepoUrl = payload.repository.ssh_url;
      const branch = payload.ref.replace('refs/heads/', '');
     // const orgRepoName = payload.repository.name;
      const orgRepoName ='drupal-19-test';
      console.log('helou',orgRepoName)
      await this.deploymentService.mirrorRepo(userRepoUrl, branch, orgRepoName);
      return { message: `Push from ${userRepoUrl} mirrored to ${orgRepoName} successfully` };
    }
    return { message: 'Event ignored' };
  }
    */

  @UseGuards(TokenGuard)
  @Post('upgrade')
  async upgradeInstance(@Body() body: {   siteName: string ,bundleId : string } , @Request() req) {
    const userId = req.user.userId;
    console.log(userId)
    const {siteName,bundleId } = body;
    if ( !userId || !siteName) {
      throw new HttpException('Missing required fields', HttpStatus.BAD_REQUEST);
    }
    try {
      console.log(bundleId)
    const result = await this.deploymentService.upgradeLightsailInstance({
        bundleId,
        userId,
        siteName,
      });
      
      return result;
    } catch (error) {
      throw new HttpException(error.message, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  ////////////////////////////GITHUB FUNCTIONS //////////////////


  @Post('github-pat/:userId')
  async fetchGitHubPat(@Param('userId') userId: string): Promise<{ pat: string }> {
    try {
      const numericUserId = parseInt(userId, 10);
      
      // Validation basique de l'userId
      if (isNaN(numericUserId)) {
        throw new HttpException('Invalid user ID format', HttpStatus.BAD_REQUEST);
      }

      // Logique de récupération du PAT
      const pat = await this.deploymentService.fetchGitHubPat(numericUserId);
      
      return { pat };
    } catch (error) {
      console.log(`Failed to fetch PAT for user ${userId}: ${error.message}`);

      // Gestion des erreurs spécifiques
      switch (error.name) {
        case 'ResourceNotFoundException':
          throw new HttpException('PAT not found', HttpStatus.NOT_FOUND);
        case 'InvalidSignatureException':
          throw new HttpException('Invalid AWS credentials', HttpStatus.UNAUTHORIZED);
        default:
          throw new HttpException(
            'Failed to retrieve GitHub PAT',
            HttpStatus.INTERNAL_SERVER_ERROR
          );
      }
    }
  }


  @UseGuards(TokenGuard)
  @Post('save-github-pat')
  async savePat(@Body() body: {  pat: string } , @Request() req) {
   
    const userId = req.user.userId;
    
    if (!userId || !body.pat.match(/^ghp_[a-zA-Z0-9]{36}$/)) {
      throw new HttpException('Invalid user ID or PAT format', HttpStatus.BAD_REQUEST);
    }
    try {
      await this.deploymentService.saveGitHubPat(userId, body.pat);
      return { message: 'PAT saved successfully' };
    } catch (error) {
      throw new HttpException(`Failed to save PAT: ${error.message}`, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }


  @UseGuards(TokenGuard)
  @Get('stats/:deploymentId')
  async getLightsailMetrics(
    @Param('deploymentId') deploymentId: string,
    @Request() req , 
  ) {
      const userId = req.user.userId ; 
     
      const instanceName = await  this.deploymentService.getInstanceName(parseInt(deploymentId, 10))
       console.log(instanceName)
     try {
      console.log(
        `Fetching metrics for deploymentId: ${deploymentId} , userId ${userId}, instanceName: ${instanceName}`,
      );
      const metrics = await this.deploymentService.getLightsailMetrics(
        parseInt(deploymentId, 10),
        parseInt(userId, 10),
        instanceName,
      );

      console.log(`Metrics retrieved successfully for deploymentId: ${deploymentId}`);
      return metrics;
    } catch (error) {
      console.error(`Error fetching metrics for deploymentId: ${deploymentId}: ${error.message}`);
      throw new HttpException(
        error.message || 'Failed to fetch metrics',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  @UseGuards(TokenGuard)
  @Post('pat-status')
  async getPatStatus(@Request() req) {
    const userId = req.user?.userId;
    console.log('userId (getPatStatus):', userId);


    if (!userId) {
      throw new HttpException('Invalid user ID', HttpStatus.BAD_REQUEST);
    }

    try {
      const status = await this.deploymentService.getPatStatus(userId);
      console.log('Returning PAT status:', status);
      return status;
    } catch (error) {
      throw new HttpException(`Failed to check PAT status: ${error.message}`, HttpStatus.NOT_FOUND);
    }
  }

  @UseGuards(TokenGuard)
  @Post('check-name-unique')
  async checkSiteNameUnique(
    @Body() siteName: string
  ) {
    return this.deploymentService.isSiteNameUnique(siteName);
  }








////////////////// for testing section 

@Post('create-codebuild')
async createCodeBuildProject(@Body() body: CreateCodeBuildDto) {
  const { userId, siteName, userRepoUrl, githubPat } = body;

  if (!userId || !siteName || !userRepoUrl || !githubPat) {
    throw new HttpException(
      'Missing required fields: userId, siteName, userRepoUrl, and githubPat are required',
      HttpStatus.BAD_REQUEST
    );
  }

  const urlRegex = /^https:\/\/github\.com\/[a-zA-Z0-9-]+\/[a-zA-Z0-9-]+$/;
  if (!urlRegex.test(userRepoUrl)) {
    throw new HttpException(
      'Invalid repository URL format. Expected format: https://github.com/username/repository',
      HttpStatus.BAD_REQUEST
    );
  }

  try {
    const response: AxiosResponse<AwsCredentialsResponse> = await firstValueFrom(
      this.deploymentService.httpService.post<AwsCredentialsResponse>(
        `http://localhost:3030/user/${userId}/connect-aws`,
        {}
      )
    );
    const { accessKeyId, secretAccessKey, sessionToken, accountId } = response.data;

    if (!accessKeyId || !secretAccessKey || !sessionToken || !accountId) {
      throw new HttpException(
        'Failed to retrieve valid AWS credentials or accountId',
        HttpStatus.INTERNAL_SERVER_ERROR
      );
    }

    await this.deploymentService.ensureArtifactBucket({ accessKeyId, secretAccessKey, sessionToken });

    const projectName = await this.deploymentService.createCodeBuildProject(
      userId,
      siteName,
      userRepoUrl,
      githubPat,
      { accessKeyId, secretAccessKey, sessionToken, accountId }
    );

    return {
      message: `CodeBuild project ${projectName} created successfully`,
      projectName,
      region: 'us-east-1',
    };
  } catch (error) {
    console.error('Error in createCodeBuildProject:', error);
    throw new HttpException(
      `Failed to create CodeBuild project: ${error.message}`,
      HttpStatus.INTERNAL_SERVER_ERROR
    );
  }
}
}
