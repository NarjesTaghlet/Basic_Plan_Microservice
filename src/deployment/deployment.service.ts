import { HttpService } from '@nestjs/axios';
import { spawn } from 'child_process';
import {  resolve } from 'path';
import { Repository } from 'typeorm';
import {HeadBucketCommand,S3Client,CreateBucketCommand } from '@aws-sdk/client-s3';
import { IAMClient ,PutRolePolicyCommand} from '@aws-sdk/client-iam';
import { CreateRoleCommand } from '@aws-sdk/client-iam';
import * as os from 'os';
import {
  CodePipelineClient,
} from '@aws-sdk/client-codepipeline';
import {
  CodeBuildClient,
  CreateProjectCommand,
  ImportSourceCredentialsCommand,
  CreateWebhookCommand
} from '@aws-sdk/client-codebuild';
import {
  LightsailClient,
  GetDiskCommand,
  GetStaticIpCommand,
  GetInstanceCommand,
  CreateInstanceSnapshotCommand,
  GetInstanceSnapshotCommand,
  CreateInstancesFromSnapshotCommand,
  AttachDiskCommand,
  GetInstanceMetricDataCommand,
  DetachDiskCommand,
  DeleteDiskCommand,
  GetDisksCommand,
  DetachStaticIpCommand,
  AttachStaticIpCommand,
  StopInstanceCommand,
  DeleteInstanceCommand,
  GetDiskSnapshotsCommand,
  DeleteDiskSnapshotCommand,
  GetInstanceSnapshotsCommand,
  DeleteInstanceSnapshotCommand,
  CreateDiskCommand
} from '@aws-sdk/client-lightsail';
  import { STSClient, AssumeRoleCommand } from '@aws-sdk/client-sts';
  import {  GetSecretValueCommand,PutSecretValueCommand , UpdateSecretCommand ,CreateSecretCommand } from '@aws-sdk/client-secrets-manager';
import { firstValueFrom } from 'rxjs';
import {InjectRepository} from "@nestjs/typeorm";
import { existsSync, writeFileSync } from 'fs';
import { Injectable, Logger } from '@nestjs/common';
import { Deployment } from './entities/deployment.entity'; // Adaptez le chemin

import { 

  readFileSync, 
} from 'fs';
import { join } from 'path';

import * as AWS from 'aws-sdk';
import * as path from 'path';
import logger from 'src/utils/logger';
import { execSync } from 'child_process';
import * as dotenv from 'dotenv' ;
import * as crypto from 'crypto';
import { promisify } from 'util';
import { exec } from 'child_process';
import * as fs from 'fs-extra';
import { NotFoundException } from '@nestjs/common';
import { SecretsManagerClient } from '@aws-sdk/client-secrets-manager';
import {
  CodeStarConnectionsClient,
  
} from '@aws-sdk/client-codestar-connections';
import { HttpException,HttpStatus } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';


dotenv.config();
const execAsync = promisify(exec);


export interface SiteStats {
  cpuUsage: MetricDataPoint[];
  memoryUsage: MetricDataPoint[];
  networkIn: MetricDataPoint[];
  networkOut: MetricDataPoint[];
  uptimeSeconds: number;
}

export interface MetricDataPoint {
  timestamp: string;
  average: number;
}

export enum InstanceMetricName {
  BurstCapacityPercentage = "BurstCapacityPercentage",
  BurstCapacityTime = "BurstCapacityTime",
  CPUUtilization = "CPUUtilization",
  NetworkIn = "NetworkIn",
  NetworkOut = "NetworkOut",
  StatusCheckFailed = "StatusCheckFailed",
  StatusCheckFailed_Instance = "StatusCheckFailed_Instance",
  StatusCheckFailed_System = "StatusCheckFailed_System"
}



@Injectable()
export class DeploymentService {
  private readonly payloadFile = 'github_payload.json';
  private artifactBucket: string = process.env.CODEPIPELINE_ARTIFACT_BUCKET || 'terraform-state-user';
  private pipelineRoleArn: string = `arn:aws:iam::${process.env.AWS_ACCOUNT_ID || '923159238841'}:role/CodePipelineServiceRole`;

  private secretsManagerClient: SecretsManagerClient;
  private codepipelineClient: CodePipelineClient;
  private readonly githubApiUrl = 'https://api.github.com';
  private readonly githubToken: string;
  private readonly orgName ='NarjesTg' ;
  private readonly templaterepo = 'Template-Basic'
  //return the real github token 
  //private readonly webhookSecret = process.env.WEBHOOK_SECRET; // Webhook secret
 // private readonly webhookUrl = ' https://ddf0-2c0f-f698-4097-5566-4560-c960-b6f0-e696.ngrok-free.app/api/webhooks/github'; // Replace with your ngrok URL
  private readonly webhookUrl = 'https://3e1d-2c0f-f698-4097-5566-4560-c960-b6f0-e696.ngrok-free.app/deployment/github'; // Replace with your ngrok URL
  private readonly cloudflareZoneId = process.env.cloudflare_zone_id;
  private readonly cloudflareApiToken = process.env.CLOUDFLARE_API_TOKEN;
  private codeStarConnectionsClient: CodeStarConnectionsClient; // Add client for CodeStar Connections

  constructor(
    @InjectRepository(Deployment)
    private deploymentRepository: Repository<Deployment>,
    //private userService: UserService,
    public httpService: HttpService,
    private configService : ConfigService
  ) {

   this.githubToken = process.env.GITHUB_PAT;
    this.codeStarConnectionsClient = new CodeStarConnectionsClient({ region: 'us-east-1' });

  }


      async fetchTempCredentials(userId: number) {
  try {
    // Utilise une variable d'environnement pour l'URL du user-service
    const userServiceUrl = this.configService.get<string>('USER_SERVICE_URL', 'http://localhost:3030');

    const { data } = await firstValueFrom(
      this.httpService.post(`${userServiceUrl}/user/${userId}/connect-aws`, {})
    );
    console.log(`Fetched AWS credentials for user ${userId}`);
    return data;
  } catch (error) {
    console.error(`Error fetching AWS credentials for user ${userId}: ${error.message}`);
    throw error;
  }
}



   //fonction get instance_name from DB ! 
   //get the name of prod instance
  async getInstanceName(deploymentId: number): Promise<string> {
    // ou bien fetch from secret manager cause we have an upgrade !! so instance name change ! 
    const instance = await this.deploymentRepository.findOne({
      where: { id:deploymentId },
    });


    if (!instance) {
      throw new NotFoundException(`Instance with ID ${deploymentId} not found`);
    }

    console.log(instance.instanceName)

    return instance.instanceName;
  }



  async findOne(id: number) {
    return await this.deploymentRepository.findOneBy({ id: id });
  }

  async findAllForUser(userId: number): Promise<Deployment[]> {
    return await this.deploymentRepository.find({ where: { userId } });
  }

  private async getUserById(userId: number) {
        const userServiceUrl = this.configService.get<string>('USER_SERVICE_URL', 'http://localhost:3030');


    try {
      const response = await firstValueFrom(
        this.httpService.get(`${userServiceUrl}/user/userid/${userId}`),
      );
      return response.data; // Suppose que la réponse contient { id, username, githubToken, ... }
    } catch (error) {
      console.error(`Failed to fetch user: ${error.message}`);
      throw new Error(`Could not fetch user with ID ${userId}`);
    }
  }

  private getAuthHeaders() {
    return {
      Authorization: `token ${this.githubToken}`,
      Accept: 'application/vnd.github.v3+json',
      'Content-Type': 'application/json'
    };
  }

  private getUserAuthHeaders(userGithubToken: string) {
    return {
      Authorization: `token ${userGithubToken}`,
      Accept: 'application/vnd.github.v3+json',
      'Content-Type': 'application/json',
    };
  }

 /*async createDeployment(userId: number, siteName: string, cloudflareDomain: string, selectedStack: string ): Promise<Deployment> {
    // Create the deployment record with initial status "Pending"
    const deployment = this.deploymentRepository.create({
      userId,
      siteName,
      cloudflareDomain,
      selectedStack,
      status: 'Pending',
      createdAt: new Date(),
      updatedAt: new Date(),
    });
    await this.deploymentRepository.save(deployment);

    try {
      // Perform the deployment (Terraform, GitHub setup, etc.)
      await this.deployInfrastructureAndSetupGitHub(deployment);
      //sleep(60s) 


      // Update status to "Active" on success
      deployment.status = 'Active';
      deployment.updatedAt = new Date();
    
      await this.deploymentRepository.save(deployment);
    } catch (error) {
      // Update status to "Failed" on error
      deployment.status = 'Failed';
      deployment.updatedAt = new Date();

      //deploy stack by triggering the pipeline !   => in the deploy    deployInfrastructureAndSetupGitHub function after
      //executing infra deploy !
       

      await this.deploymentRepository.save(deployment);


      throw new Error(`Deployment failed: ${error.message}`);
    }

    return deployment;
  }
    */
   async createDeployment(
  userId: number,
  siteName: string,
  cloudflareDomain: string,
  selectedStack: string
): Promise<{ deploymentId: number }> {
  // 🔤 Nettoyer le nom du site
  const SiteName = siteName.toLowerCase().replace(/[^a-z0-9-]/g, '-');

  // 🗂️ Créer le déploiement dans la BDD
  const deployment = this.deploymentRepository.create({
    userId,
    siteName: SiteName,
    cloudflareDomain,
    selectedStack,
    status: 'Pending',
    createdAt: new Date(),
    updatedAt: new Date(),
  });

  await this.deploymentRepository.save(deployment);

  // 🔁 Déclenche Terraform en arrière-plan (non bloquant)
  this.deployInfrastructureAndSetupGitHub(deployment)
    .then(async () => {
      deployment.status = 'Active';
      deployment.updatedAt = new Date();
      await this.deploymentRepository.save(deployment);
      console.log(`✅ Deployment ${deployment.id} completed`);
    })
    .catch(async (error) => {
      deployment.status = 'Failed';
      deployment.updatedAt = new Date();
      await this.deploymentRepository.save(deployment);
      console.error(`❌ Deployment ${deployment.id} failed:`, error.message);
    });

  // ✅ Réponse immédiate pour le frontend
  return { deploymentId: deployment.id };
}

      async getDeploymentStatus( id: number) {
        const deployment = await this.deploymentRepository.findOneBy({ id });
      
        if (!deployment) {
          throw new NotFoundException('Deployment not found');
        }
      
        return { status: deployment.status };
      }



 /* async deployInfrastructureAndSetupGitHub(deploymentData: { userId: number, siteName: string, cloudflareDomain: string , selectedStack: string }) {
    const { userId, siteName, cloudflareDomain, selectedStack } = deploymentData;

    // Step 1: Create a Deployment entity directly using the repository
    const deployment = this.deploymentRepository.create({
      userId,
      siteName,
      cloudflareDomain,
      selectedStack,
    });
    await this.deploymentRepository.save(deployment);
    console.log('Created deployment record:', deployment);

    // Step 2: Deploy Infrastructure
    const infraResult = await this.deployInfrastructure(userId, siteName);

    // Step 3: Update deployment with non-sensitive data
    deployment.instancePublicIp = infraResult.instancePublicIp;
    deployment.secretsManagerArn = infraResult.secretsManagerArn;
    await this.deploymentRepository.save(deployment);
    console.log('Updated deployment with infrastructure details:', { instancePublicIp: infraResult.instancePublicIp });

    // Step 4: Setup GitHub Repositories
    const githubResult = await this.setupUserDeployment(userId.toString(), siteName);

    // Step 5: Update deployment with GitHub repository URL
    deployment.userRepoUrl = githubResult.userRepoUrl;
    await this.deploymentRepository.save(deployment);
    console.log('Updated deployment with GitHub repository URL:', { userRepoUrl: githubResult.userRepoUrl });

    return {
      instancePublicIp: infraResult.instancePublicIp,
      userRepoUrl: githubResult.userRepoUrl,
      deploymentId: deployment.id,
      secretsManagerArn: infraResult.secretsManagerArn,
    };
  }
*/

async setupUserDeployment(
   userId: number,
  siteName: string,
  userGithubToken : string
): Promise<{ userRepoUrl: string }> {
  const repoName = `drupal-${userId}-${siteName}`;
  
  //const userGithubToken = process.env.userGithubToken

    console.log('token0',userGithubToken)

   const user = await this.getUserById(userId);
    console.log('helou',user)
    if (!user) {
      throw new Error('User not found');
    }
    // Récupérer githubUsername
    const githubUserResponse = await firstValueFrom(
      this.httpService.get('https://api.github.com/user', {
        headers: {
          Authorization: `token ${userGithubToken}`,
          Accept: 'application/vnd.github.v3+json',
        },
      })
    );
    const userGithubUsername = githubUserResponse.data.login;
        console.log(userGithubUsername)

 


  try {
    const response = await firstValueFrom(
      this.httpService.post(
        `https://api.github.com/repos/${this.orgName}/Basic_Template/generate`,
        {
          owner: userGithubUsername,
          name: repoName,
          private: true,
          include_all_branches: true,
          description: `Generated repo for user ${userId} / site ${siteName}`,
        },
        {
          headers: {
            Authorization: `token ${userGithubToken}`,
            Accept: 'application/vnd.github.baptiste-preview+json', // Required for /generate
          },
        }
      )
    );
    
    const userRepoUrl = response.data.html_url;

    console.log(userRepoUrl)
    return {
        userRepoUrl,
      };
    } catch (error) {
      console.error(`Deployment failed: ${error.message}`);
      throw new Error(`Could not complete deployment: ${error.message}`);
    }
  }


async deployInfrastructureAndSetupGitHub(deployment: Deployment) {
  try {
    
    const userGithubToken = await  this.fetchGitHubPat(deployment.userId)
    console.log(userGithubToken)

    
     // Step 4: Configuration GitHub
     const githubResult = await this.setupUserDeployment(deployment.userId, deployment.siteName ,userGithubToken);
     deployment.userRepoUrl = githubResult.userRepoUrl;
    
    // deployment.orgRepoUrl = githubResult.orgRepoUrl;
     await this.deploymentRepository.save(deployment);

   //change org to repo , now juste for test
    // Step 1: Deploy Infrastructure
    // Prod env
    // Step 1: Deploy Infrastructure
// Prod env
//do not forget to change orgrepourl by userrepourl
const prodTerraformDir = resolve('terraform', 'Basic_Plan', 'PROD');
const keyProd = `sites/${deployment.userId}/${deployment.siteName}/terraform.tfstate`
const prodregion = "us-east-1"
const infraResult = await this.deployInfrastructure(deployment.userId, deployment.siteName, githubResult.userRepoUrl, prodTerraformDir,keyProd,prodregion);

// Dev env
const keyDev = `sites/${deployment.userId}/dev/${deployment.siteName}/terraform.tfstate`
const devregion = "us-east-2"
const devTerraformDir = resolve('terraform', 'Basic_Plan', 'DEV');
const infraResult_dev = await this.deployInfrastructure(deployment.userId, deployment.siteName, githubResult.userRepoUrl, devTerraformDir,keyDev,prodregion);

 


    // Step 3: Mise à jour de la base de données
    deployment.instanceName = infraResult.instanceName;
    deployment.instanceName_dev = infraResult_dev.instanceName;
    deployment.instancePublicIp = infraResult.instancePublicIp;
    deployment.sshPrivateKey = infraResult.sshkey;
    deployment.instancePublicIp_dev=infraResult_dev.instancePublicIp;
    deployment.sshPrivateKey_dev=infraResult_dev.sshkey
    
    await this.deploymentRepository.save(deployment);

   

    /////////test
 //   await this.createCodePipeline(deployment.userId, deployment.siteName, githubResult.userRepoUrl, githubResult.orgRepoUrl);

 

    return {
      instancePublicIp: infraResult.instancePublicIp,
      userRepoUrl: githubResult.userRepoUrl,
     // orgRepoUrl: githubResult.orgRepoUrl,
      deploymentId: deployment.id
    };
  } catch (error) {
    console.error('Erreur détaillée:', error);
    throw new Error(`Échec du déploiement: ${error.message}`);


  }
}



/////////////////////////////////For Testing//////////////////////////


async ensureArtifactBucket(credentials: { accessKeyId: string; secretAccessKey: string; sessionToken: string }): Promise<void> {
  const s3Client = new S3Client({
    region: 'us-east-1', // Match the CodePipeline region
    credentials,
  });

  try {
    await s3Client.send(new HeadBucketCommand({ Bucket: this.artifactBucket }));
    logger.info(`Artifact bucket ${this.artifactBucket} already exists`);
  } catch (error) {
    if (error.name === 'NotFound') {
      await s3Client.send(
        new CreateBucketCommand({
          Bucket: this.artifactBucket,
          CreateBucketConfiguration: {
         //   LocationConstraint: 'us-east-2', // Must match the region
          },
        })
      );
      logger.info(`Created artifact bucket: ${this.artifactBucket}`);
    } else {
      throw error;
    }
  }
}


async createCodeBuildRole(credentials: { accessKeyId: string; secretAccessKey: string; sessionToken: string; accountId: string }): Promise<string> {
  const iamClient = new IAMClient({
    region: 'us-east-1',
    credentials,
  });

  const roleName = 'CodeBuildServiceRole';
  const roleArn = `arn:aws:iam::${credentials.accountId}:role/${roleName}`;

  // Step 1: Create the role with a trust policy for CodeBuild
  const trustPolicy = {
    Version: '2012-10-17',
    Statement: [
      {
        Effect: 'Allow',
        Principal: {
          Service: 'codebuild.amazonaws.com',
        },
        Action: 'sts:AssumeRole',
      },
    ],
  };

  try {
    await iamClient.send(
      new CreateRoleCommand({
        RoleName: roleName,
        AssumeRolePolicyDocument: JSON.stringify(trustPolicy),
        Description: 'Role for CodeBuild to access AWS resources',
      })
    );
    logger.info(`Created IAM role: ${roleName}`);
  } catch (error) {
    if (error.name === 'EntityAlreadyExistsException') {
      logger.info(`Role ${roleName} already exists, proceeding...`);
    } else {
      logger.error(`Failed to create IAM role: ${error.message}`);
      throw error;
    }
  }

  // Step 2: Attach the inline policy to the role
  const policyDocument = {
    Version: '2012-10-17',
    Statement: [
      {
        Effect: 'Allow',
        Action: ['ssm:GetParameter'],
        Resource: 'arn:aws:ssm:us-east-1:923159238841:parameter/codebuild/github-pat',
      },
      {
        Effect: 'Allow',
        Action: ['secretsmanager:GetSecretValue'],
        Resource: [
          'arn:aws:secretsmanager:us-east-1:923159238841:secret:sites/19/nchalahtemshiyarabi-*',
          'arn:aws:secretsmanager:us-east-1:923159238841:secret:ssh/19/nchalahtemshiyarabi-*',
        ],
      },
      {
        Effect: 'Allow',
        Action: ['s3:PutObject', 's3:GetObject', 's3:ListBucket'],
        Resource: [
          'arn:aws:s3:::codebuild-artifacts-us-east-1/*',
          'arn:aws:s3:::codebuild-artifacts-us-east-1',
        ],
      },
      {
        Effect: 'Allow',
        Action: [
          'logs:CreateLogGroup',
          'logs:CreateLogStream',
          'logs:PutLogEvents',
        ],
        Resource: '*',
      },

      {
        "Effect": "Allow",
        "Action": [
          "codecommit:GitPull",
          "codecommit:GetRepository",
          "codecommit:BatchGetRepositories"
        ],
        "Resource": "*"
      }
      
    ],
  };

  try {
    await iamClient.send(
      new PutRolePolicyCommand({
        RoleName: roleName,
        PolicyName: 'CodeBuildAccessPolicy',
        PolicyDocument: JSON.stringify(policyDocument),
      })
    );
    logger.info(`Attached policy to IAM role: ${roleName}`);
  } catch (error) {
    logger.error(`Failed to attach policy to IAM role: ${error.message}`);
    throw error;
  }

  return roleArn;
}


async createCodeBuildProject(
  userId: number,
  siteName: string,
  userRepoUrl: string,
  githubPat: string,
  credentials: {
    accessKeyId: string;
    secretAccessKey: string;
    sessionToken: string;
    accountId: string;
  }
): Promise<string> {
  const projectName = `drupal-build-${userId}-${siteName}`;

  try {
    const region = 'us-east-1';
    const codeBuildClient = new CodeBuildClient({
      region,
      credentials,
    });

    // ✅ Step 1: Import GitHub PAT securely
    console.log(`🔐 Importing GitHub PAT for user ${userId}`);
    await codeBuildClient.send(
      new ImportSourceCredentialsCommand({
        authType: 'PERSONAL_ACCESS_TOKEN',
        serverType: 'GITHUB',
        token: githubPat,
        shouldOverwrite: true,
      }),
    );
    console.log(` GitHub PAT imported successfully`);

    // ✅ Step 2: Define IAM Role (assumes you have this method ready)
    const roleArn = await this.createCodeBuildRole(credentials);
    console.log(`🔧 Using CodeBuild role: ${roleArn}`);

    // ✅ Step 3: Ensure artifact bucket exists (assumes method ready)
    await this.ensureArtifactBucket(credentials);
    console.log(`📦 Using artifact bucket: ${this.artifactBucket}`);

    const projectInput = {
      name: projectName,
      description: `Build project for user ${userId}, site ${siteName}`,
      source: {
        type: 'GITHUB',
        location: userRepoUrl,
        gitCloneDepth: 1,
        buildspec: 'buildspec.yml',
        gitSubmodulesConfig: {
          fetchSubmodules: false,
        },
      },
      sourceVersion: 'main',
      artifacts: {
        type: 'S3',
        location: this.artifactBucket,
        packaging: 'ZIP',
        path: projectName,
        namespaceType: 'BUILD_ID',
      },
      environment: {
        type: 'LINUX_CONTAINER',
        image: 'aws/codebuild/standard:5.0',
        computeType: 'BUILD_GENERAL1_SMALL',
        privilegedMode: true,
        environmentVariables: [
          {
            name: 'AWS_REGION',
            value: 'us-east-1',
            type: 'PLAINTEXT',
          },
        ],
      },
      serviceRole: roleArn,
      timeoutInMinutes: 60,
      queuedTimeoutInMinutes: 10,
    
      // ✅ Force-add webhook trigger here
      triggers: {
        webhook: true,
        filterGroups: [
          [
            {
              type: 'EVENT',
              pattern: '.*',
            },
            {
              type: 'HEAD_REF',
              pattern: 'main',
            },
          ],
        ],
      },
    } as any; // ✅ force cast to bypass missing type
    

    // ✅ Step 4: Explicitly create the webhook (guarantees proper GitHub hook creation)


console.log(`🔗 Webhook successfully created for ${projectName}`);
    const command = new CreateProjectCommand(projectInput);
    await codeBuildClient.send(command);
    
    console.log(`✅ CodeBuild project created: ${projectName}`);

    // ✅ Step 5: Now create the webhook
await codeBuildClient.send(
  new CreateWebhookCommand({
    projectName,
    filterGroups: [
      [
        {
          type: 'EVENT',
          pattern: 'PUSH',
        },
        {
          type: 'HEAD_REF',
          pattern: 'main',
        },
      ],
    ],
    buildType: 'BUILD',
  }),
);
console.log(`🔗 Webhook successfully created for ${projectName}`);
    return projectName;


  } catch (error) {
    logger.error(`❌ Failed to create CodeBuild project: ${error.message}`);
    throw new Error(`Failed to create CodeBuild project: ${error.message}`);
  }
}




/////////////////////////////////////////////////////////////////////////






  



  /*async deployInfrastructure(
    userId: number,
    siteName: string,
  ): Promise<{
    instancePublicIp: string;
    databaseEndpoint: string;
    databasePort: number;
    databaseName: string;
    databaseUsername: string;
    databasePassword: string;
    dnsRecord: string;
    wwwDnsRecord: string | null;
    instanceName: string;
    sshkey:string;
  }> {
    try {
      logger.info(`Starting infrastructure deployment for user_id ${userId}, site_name ${siteName}`);
      // Run terraform init with master account ! 
      

   
      const response: AxiosResponse<AwsCredentialsResponse> = await firstValueFrom(
        this.httpService.post<AwsCredentialsResponse>(`http://localhost:3030/user/${userId}/connect-aws`, {}),
      );
      const { accessKeyId, secretAccessKey, sessionToken } = response.data;


      logger.info(`Temporary Credentials: aws_access_key_id=${accessKeyId}, aws_secret_access_key=${secretAccessKey}, aws_session_token=${sessionToken}`);


      // Step 2: Use the temporary credentials to get the account ID
      const sts = new AWS.STS({
        accessKeyId: accessKeyId,
        secretAccessKey: secretAccessKey,
        sessionToken: sessionToken,
      });

      const identity = await sts.getCallerIdentity().promise();
      const awsRegion = "us-east-1";
      const accountId = identity.Account;
      logger.info(`Deploying to sub-account with Account ID: ${accountId}, Arn: ${identity.Arn}`);
  
      // Step 3: Create a temporary AWS CLI profile for the sub-account credentials
      const tempProfile = `temp-subaccount-${userId}-${siteName}`; // Unique profile name to avoid conflicts
      execSync(`aws configure set aws_access_key_id ${accessKeyId} --profile ${tempProfile}`, { stdio: 'inherit' });
      execSync(`aws configure set aws_secret_access_key ${secretAccessKey} --profile ${tempProfile}`, { stdio: 'inherit' });
      execSync(`aws configure set aws_session_token ${sessionToken} --profile ${tempProfile}`, { stdio: 'inherit' });
      logger.info(`Created temporary AWS CLI profile: ${tempProfile}`);
     
      // Step 4: Set up Terraform execution with absolute path
    const baseDir = path.resolve(__dirname, '..'); // Assumes script is in a subdirectory of the project root
      // Step 4: Run Terraform commands with the temporary profile
     // const terraformDir = path.join( 'terraform', 'Basic_Plan','DEV');
     const terraformDir = path.resolve('terraform', 'Basic_Plan', 'DEV');
      
     
     //process.chdir(terraformDir);
      logger.info(`Changed working directory to ${terraformDir}`);
      const env = { ...process.env, AWS_PROFILE: tempProfile, PATH: `${process.env.PATH};C:\\windows\\system32` };

      // Run terraform init with S3 backend configuration
   // const initCommand = `terraform init -backend-config="bucket=terraform-state-user-id" -backend-config="key=user-${userId}/workspace/site-${siteId}/terraform.tfstate" -backend-config="region=us-east-1" -backend-config="dynamodb_table=terraform-locks"`;
   // execSync(initCommand, { stdio: 'inherit', env: { ...process.env, AWS_PROFILE: tempProfile } });
      // Run terraform init
      //execSync(`terraform init `, { cwd: terraformDir,stdio: 'inherit', env: { ...process.env, AWS_PROFILE: tempProfile } });
      try {
        execSync(
          `terraform init -backend-config="bucket=terraform-state-user" -backend-config="key=sites/${userId}/${siteName}/terraform.tfstate" -backend-config="region=us-east-1" -backend-config="dynamodb_table=terraform-locks-user" -reconfigure`,
          { cwd: terraformDir, stdio: 'inherit', env }
        );
        logger.info('Terraform init completed successfully');
      } catch (error) {
        logger.error('Terraform init failed:', error.message);
        throw error;
      }

      // Step X: Create or select a unique Terraform workspace for this user + site
const workspaceName = `user-${userId}-${siteName}`;
logger.info(`🔧 Selecting or creating Terraform workspace: ${workspaceName}`);

try {
  execSync(`terraform workspace select ${workspaceName}`, {
    cwd: terraformDir,
    stdio: 'inherit',
    env,
  });
  logger.info(`✅ Workspace '${workspaceName}' selected`);
} catch (err) {
  logger.warn(`⚠️ Workspace '${workspaceName}' not found. Creating...`);
  execSync(`terraform workspace new ${workspaceName}`, {
    cwd: terraformDir,
    stdio: 'inherit',
    env,
  });
  logger.info(`✅ Workspace '${workspaceName}' created`);
}

        
      //const env = { ...process.env, AWS_PROFILE: tempProfile };
      // Run terraform plan
      const planCommand = `terraform plan -out=plan -var="user_id=${userId}"  -var="site_name=${siteName}" -var="account_id=${accountId}" -var="aws_access_key_id=${accessKeyId}" -var="aws_secret_access_key=${secretAccessKey}" -var="aws_session_token=${sessionToken}"`;
      execSync(planCommand, { cwd: terraformDir ,stdio: 'inherit', env: { ...process.env, AWS_PROFILE: tempProfile } });

      // Run terraform apply
      const applyCommand = `terraform apply -auto-approve -var="user_id=${userId}"  -var="site_name=${siteName}" -var="account_id=${accountId}" -var="account_id=${accountId}" -var="aws_access_key_id=${accessKeyId}" -var="aws_secret_access_key=${secretAccessKey}" -var="aws_session_token=${sessionToken}"`;
      execSync(applyCommand, { cwd: terraformDir ,stdio: 'inherit', env: { ...process.env, AWS_PROFILE: tempProfile } });


    
        
      

      // Step 5: Fetch Terraform outputs
      const outputJson = execSync(`terraform output -json`, { cwd: terraformDir, env }).toString();
      const outputs = JSON.parse(outputJson);

       // Step 5: Clean up the temporary profile
       const awsCredentialsPath = path.join(process.env.USERPROFILE, '.aws', 'credentials');
       if (fs.existsSync(awsCredentialsPath)) {
         let credentialsContent = fs.readFileSync(awsCredentialsPath, 'utf-8');
         credentialsContent = credentialsContent.replace(new RegExp(`\\[${tempProfile}\\][\\s\\S]*?(?=\\[|$)`, 'g'), '');
         fs.writeFileSync(awsCredentialsPath, credentialsContent.trim());
         logger.info(`Removed temporary AWS CLI profile: ${tempProfile}`);
       }

      // Step 6: Return the S3 bucket name
      return {
        instancePublicIp: outputs.instance_public_ip.value,
        databaseEndpoint: outputs.database_endpoint.value,
        databasePort: outputs.database_port.value,
        databaseName: outputs.database_name.value,
        databaseUsername: outputs.database_username.value,
        databasePassword: outputs.database_password.value,
        dnsRecord: outputs.dns_record.value,
        wwwDnsRecord: outputs.www_dns_record.value,
        instanceName: outputs.instance_name.value,
        sshkey: outputs.ssh.value,
      };
    } catch (error) {
      logger.error(`Failed to deploy infrastructure for user_id ${userId}, site_name ${siteName}: ${error.message}`);
      throw new Error(`Failed to deploy infrastructure: ${error.message}`);
    }
  }
*/
//////////////////////////////// test only /////////////////////////





  async deleteSite(deploymentId: number): Promise<void> {
    const deployment = await this.findOne(deploymentId);
    //siteName should be saved in the db (cas upgrade to be updated )
    //disk name also
    //il faut voir comment ca se passe ! 
    const { userId, siteName } = deployment;
    console.log ("ena deployment of deletesite function ",deployment)

    try {
      const terraformDirProd = path.join('terraform', 'Basic_Plan', 'PROD');
      const keyProd = `sites/${userId}/${siteName}/terraform.tfstate`
       const region = "us-east-1"

     
      await this.destroyInfrastructure(userId, siteName, deploymentId , terraformDirProd,region,`sites/${userId}/${siteName}`,keyProd,region);

      const keyDev = `sites/${userId}/dev/${siteName}/terraform.tfstate`
      const terraformDirDev = path.join('terraform', 'Basic_Plan', 'DEV');
      const regiondev = "us-east-2"
      await this.destroyInfrastructure(userId, siteName, deploymentId , terraformDirDev,region,`sites/dev/${userId}/${siteName}`,keyDev,regiondev);
      //we will check github token permissions to delete the github repo 
      //await this.cleanupScheduledSecrets(userId, siteName);
      await this.deploymentRepository.delete(deploymentId);
      console.log(`Successfully deleted deployment ${deploymentId} for user ${userId}, site ${siteName}`);
    } catch (error) {
      console.error(`Failed to delete deployment ${deploymentId}: ${error.message}`);
      throw new Error(`Failed to delete site: ${error.message}`);
    }
  }

  async cleanupScheduledSecrets(userId: number, siteName: string): Promise<void> {
    const secretsManager = new AWS.SecretsManager({
      region: 'us-east-1',
    });

    const secretNames = [
      `sites/${userId}/${siteName}`,
      `ssh/${userId}/${siteName}`,
    ];

    for (const secretName of secretNames) {
      try {
        const secret = await secretsManager.describeSecret({ SecretId: secretName }).promise();
        if (secret.DeletedDate) {
         console.log('Secret ${secretName} is scheduled for deletion. Forcing deletion...');
          await secretsManager.deleteSecret({
            SecretId: secretName,
            ForceDeleteWithoutRecovery: true,
          }).promise();
         console.log(`Secret ${secretName} has been permanently deleted.`);
        } else {
          console.log(`Deleting secret ${secretName}...`);
          await secretsManager.deleteSecret({
            SecretId: secretName,
            ForceDeleteWithoutRecovery: true,
          }).promise();
          console.log(`Secret ${secretName} has been permanently deleted.`);
        }
      } catch (error) {
        if (error.code === 'ResourceNotFoundException') {
          console.log(`Secret ${secretName} does not exist. Proceeding...`);
        } else {
          logger.error(`Error managing secret ${secretName}: ${error.message}`);
          throw error;
        }
      }
    }
  }
    

 /*async destroyInfrastructure(userId: number,  siteName: string,deploymentId:number): Promise<void> {
    let secretsManagerClient: SecretsManagerClient | undefined;
    const deployment = await this.findOne(deploymentId);
    //to change it now just for test
    const github_repo_url = deployment.orgRepoUrl
    const cloudflareDomain = deployment.cloudflareDomain;
    try {
      logger.info(`Starting destruction for user_id ${userId},  site_name ${siteName}`);
  
      // Step 1: Get temporary credentials
      const response: AxiosResponse<AwsCredentialsResponse> = await firstValueFrom(
        this.httpService.post<AwsCredentialsResponse>(`http://localhost:3030/user/${userId}/connect-aws`, {}),
      );
      const { accessKeyId, secretAccessKey, sessionToken } = response.data;
      logger.info(`Credentials: aws_access_key_id=${accessKeyId}`);
  
      // Step 2: Verify credentials
      const sts = new AWS.STS({ accessKeyId, secretAccessKey, sessionToken });
      const identity = await sts.getCallerIdentity().promise();
      const accountId = identity.Account;
      logger.info(`Destroying in sub-account: Account ID=${accountId}, Arn=${identity.Arn}`);

      secretsManagerClient = new SecretsManagerClient({
        region: 'us-east-1',
        credentials: {
          accessKeyId: response.data!.accessKeyId!,
          secretAccessKey:response.data!.secretAccessKey!,
          sessionToken: response.data!.sessionToken!,
        },
      });

       // Step 4: Fetch instance and disk names from Secrets Manager
    const secretName = `sites/${userId}/${siteName}`;
    logger.info(`Fetching details from Secrets Manager for ${secretName}...`);
    const secretResponse = await secretsManagerClient.send(
      new GetSecretValueCommand({
        SecretId: secretName,
      }),
    );
    const siteSecrets = JSON.parse(secretResponse.SecretString);
    let { instance_name, disk_name } = siteSecrets;

  
      // Step 3: Set temporary AWS CLI profile
      const tempProfile = `temp-subaccount-${userId}-${siteName}`;
      execSync(`aws configure set aws_access_key_id ${accessKeyId} --profile ${tempProfile}`, { stdio: 'inherit', shell: 'cmd.exe' });
      execSync(`aws configure set aws_secret_access_key ${secretAccessKey} --profile ${tempProfile}`, { stdio: 'inherit', shell: 'cmd.exe' });
      execSync(`aws configure set aws_session_token ${sessionToken} --profile ${tempProfile}`, { stdio: 'inherit', shell: 'cmd.exe' });
      execSync(`aws configure set region us-east-1 --profile ${tempProfile}`, { stdio: 'inherit', shell: 'cmd.exe' });
      logger.info(`Created profile: ${tempProfile}`);
  
      // Step 4: Run Terraform destroy
      const terraformDir = path.join('terraform', 'Basic_Plan', 'DEV');
      logger.info(`Terraform directory: ${terraformDir}`);
      const env = { ...process.env, AWS_PROFILE: tempProfile, PATH: `${process.env.PATH};C:\\windows\\system32` };
  
      try {
        execSync(`terraform init -reconfigure -backend-config="bucket=terraform-state-user" -backend-config="key=sites/${userId}/${siteName}/terraform.tfstate" -backend-config="region=us-east-1" -backend-config="dynamodb_table=terraform-locks-user"`, { cwd: terraformDir, env, stdio: 'inherit', shell: 'cmd.exe' });
        execSync(`terraform destroy -auto-approve -var="user_id=${userId}" -var="site_name=${siteName}" -var="account_id=${accountId}"  -var="aws_access_key_id=${accessKeyId}" -var="aws_secret_access_key=${secretAccessKey}" -var="aws_session_token=${sessionToken} -var="instance_name=${instance_name}" -var="disk_name=${disk_name}" `, { cwd: terraformDir, env, stdio: 'inherit', shell: 'cmd.exe' });
        logger.info(`Destroyed infrastructure`);
      } catch (terraformError) {
        logger.error(`Terraform error: ${terraformError.message}`);
        throw terraformError;
      }


      await this.cleanupScheduledSecrets(userId, siteName);
  
      // Step 5: Clean up profile
      const awsCredentialsPath = path.join(process.env.USERPROFILE, '.aws', 'credentials');
      if (fs.existsSync(awsCredentialsPath)) {
        let credentialsContent = fs.readFileSync(awsCredentialsPath, 'utf-8');
        credentialsContent = credentialsContent.replace(new RegExp(`\\[${tempProfile}\\][\\s\\S]*?(?=\\[|$)`, 'g'), '');
        fs.writeFileSync(awsCredentialsPath, credentialsContent.trim());
        logger.info(`Removed profile: ${tempProfile}`);
      }

      // Step 8: Delete GitHub repositories
      await this.deleteGitHubRepositories(userId, siteName);

      // Step 9: Delete Cloudflare DNS record
      if (cloudflareDomain) {
      //  await this.deleteCloudflareDNSRecord(cloudflareDomain);
      }

      //delete from database
    } catch (error) {
      logger.error(`Failed to destroy: ${error.message}`);
      throw new Error(`Failed to destroy infrastructure: ${error.message}`);
    }
  }
  */

  async  checkAndClearTerraformLock(terraformDir: string, env: NodeJS.ProcessEnv, statePath: string): Promise<void> {
    try {
      logger.info(`Checking for Terraform state locks at ${statePath}...`);
      const { stdout } = await execAsync(`terraform state list`, { cwd: terraformDir, env });
      if (stdout) {
        logger.info(`State exists. Attempting to clear any locks...`);
        const { stderr } = await execAsync(`terraform force-unlock -force`, { cwd: terraformDir, env });
        if (stderr) logger.warn(`Force-unlock stderr: ${stderr}`);
        logger.info(`Locks cleared.`);
      }
    } catch (error) {
      logger.warn(`No state or lock check failed: ${error.message}. Proceeding...`);
    }
  }
  
    async destroyInfrastructure(
    userId: number,
    siteName: string,
    deploymentId: number,
    terraformDir: string,
    region: string,
    secretName: string,
    key: string,
    devregion: string,
  ): Promise<void> {
    let secretsManagerClient: SecretsManagerClient | undefined;
    let lightsailClient: LightsailClient | undefined;
    const workspaceName = `user-${userId}-${siteName}`;
    const tempProfile = `temp-subaccount-${userId}-${siteName}`;
  //  const env = { ...process.env, AWS_PROFILE: tempProfile, PATH: `${process.env.PATH};C:\\windows\\system32` };

    try {
      logger.info(`Starting destruction for user_id ${userId}, site_name ${siteName}, deployment_id ${deploymentId}`);

      // Step 1: Get temporary credentials
    /*  const response: AxiosResponse<AwsCredentialsResponse> = await firstValueFrom(
        this.httpService.post<AwsCredentialsResponse>(`http://localhost:3030/user/${userId}/connect-aws`, {}),
      );
      const { accessKeyId, secretAccessKey, sessionToken } = response.data;*/
       // 1. Get temporary credentials from user service
        const data = await this.fetchTempCredentials(userId);

         const { accessKeyId, secretAccessKey, sessionToken } = data;

         const env = {
  ...process.env,
  AWS_ACCESS_KEY_ID: accessKeyId,
  AWS_SECRET_ACCESS_KEY:secretAccessKey,
  AWS_SESSION_TOKEN: sessionToken,
};
      logger.info(`Credentials: aws_access_key_id=${accessKeyId}`);

      // Step 2: Verify credentials
      const sts = new AWS.STS({ accessKeyId, secretAccessKey, sessionToken });
      const identity = await sts.getCallerIdentity().promise();
      const accountId = identity.Account;
      logger.info(`Destroying in sub-account: Account ID=${accountId}, Arn=${identity.Arn}`);

      // Step 3: Initialize SecretsManagerClient and LightsailClient
      secretsManagerClient = new SecretsManagerClient({
        region: devregion,
        credentials: { accessKeyId, secretAccessKey, sessionToken },
      });
      lightsailClient = new LightsailClient({
        region: devregion,
        credentials: { accessKeyId, secretAccessKey, sessionToken },
      });

      // Step 4: Fetch instance and disk names from Secrets Manager
      logger.info(`Fetching details from Secrets Manager for ${secretName}...`);
      const secretResponse = await secretsManagerClient.send(new GetSecretValueCommand({ SecretId: secretName }));
      const siteSecrets = JSON.parse(secretResponse.SecretString);
      let { instance_name, disk_name } = siteSecrets;

      if (!instance_name || !disk_name) {
        throw new Error(`Missing instance_name or disk_name in Secrets Manager for ${secretName}`);
      }
      logger.info(`Fetched from Secrets Manager: instance_name=${instance_name}, disk_name=${disk_name}`);

      // Step 5: Set temporary AWS CLI profile
      execSync(`aws configure set aws_access_key_id ${accessKeyId} --profile ${tempProfile}`, { stdio: 'inherit', shell: 'cmd.exe' });
      execSync(`aws configure set aws_secret_access_key ${secretAccessKey} --profile ${tempProfile}`, { stdio: 'inherit', shell: 'cmd.exe' });
      execSync(`aws configure set aws_session_token ${sessionToken} --profile ${tempProfile}`, { stdio: 'inherit', shell: 'cmd.exe' });
      execSync(`aws configure set region ${devregion} --profile ${tempProfile}`, { stdio: 'inherit', shell: 'cmd.exe' });
      logger.info(`Created profile: ${tempProfile}`);

      // Step 6: Stop the instance if running
      let instanceExists = false;
      try {
        const instanceResponse = await lightsailClient.send(new GetInstanceCommand({ instanceName: instance_name }));
        instanceExists = true;
        if (instanceResponse.instance?.state.name === 'running') {
          logger.info(`Instance ${instance_name} is running. Stopping...`);
          await lightsailClient.send(new StopInstanceCommand({ instanceName: instance_name }));
          let instanceStatus = instanceResponse.instance.state.name;
          const maxRetries = 24;
          let retries = 0;
          while (instanceStatus !== 'stopped' && retries < maxRetries) {
            const statusResponse = await lightsailClient.send(new GetInstanceCommand({ instanceName: instance_name }));
            instanceStatus = statusResponse.instance.state.name;
            if (statusResponse.instance.state.name !== 'stopped') {
              logger.info(`Instance ${instance_name} status: ${instanceStatus}. Waiting 5 seconds... (Attempt ${retries + 1}/${maxRetries})`);
              await new Promise((resolve) => setTimeout(resolve, 5000));
              retries++;
            }
          }
          if (instanceStatus !== 'stopped') {
            logger.warn(`Failed to stop instance ${instance_name}. Proceeding...`);
          } else {
            logger.info(`Instance ${instance_name} stopped.`);
          }
        } else {
          logger.info(`Instance ${instance_name} is already stopped (state: ${instanceResponse.instance.state.name}).`);
        }
      } catch (error) {
        if (error.name === 'NotFoundException') {
          logger.info(`Instance ${instance_name} does not exist.`);
          instanceExists = false;
        } else {
          throw new Error(`Failed to check instance ${instance_name}: ${error.message}`);
        }
      }

      // Step 7: Detach disk if attached
      let diskAttached = false;
      let diskExists = false;
      try {
        const diskResponse = await lightsailClient.send(new GetDiskCommand({ diskName: disk_name }));
        diskExists = true;
        if (diskResponse.disk?.attachedTo) {
          diskAttached = true;
          logger.info(`Disk ${disk_name} is attached to ${diskResponse.disk.attachedTo}. Detaching...`);
          await lightsailClient.send(new DetachDiskCommand({ diskName: disk_name }));
          let retries = 0;
          const maxRetries = 24;
          while (retries < maxRetries) {
            const checkDiskResponse = await lightsailClient.send(new GetDiskCommand({ diskName: disk_name }));
            if (!checkDiskResponse.disk?.attachedTo) {
              logger.info(`Disk ${disk_name} detached.`);
              diskAttached = false;
              break;
            }
            retries++;
            logger.info(`Disk ${disk_name} still attached. Retrying in 5 seconds... (Attempt ${retries + 1}/${maxRetries})`);
            await new Promise((resolve) => setTimeout(resolve, 5000));
          }
          if (diskAttached) {
            logger.warn(`Failed to detach disk ${disk_name}. Forcing...`);
            await lightsailClient.send(new DetachDiskCommand({ diskName: disk_name }));
            const finalCheck = await lightsailClient.send(new GetDiskCommand({ diskName: disk_name }));
            if (finalCheck.disk?.attachedTo) {
              throw new Error(`Failed to detach disk ${disk_name}.`);
            }
            logger.info(`Disk ${disk_name} force-detached.`);
          }
        } else {
          logger.info(`Disk ${disk_name} is not attached.`);
        }
      } catch (error) {
        if (error.name === 'NotFoundException') {
          logger.info(`Disk ${disk_name} does not exist.`);
          diskExists = false;
        } else {
          throw new Error(`Failed to check or detach disk ${disk_name}: ${error.message}`);
        }
      }

      // Step 8: Initialize Terraform
      logger.info(`Initializing Terraform in ${terraformDir}...`);
      await runTerraformCommand(
        [
          'init',
          '-reconfigure',
          '-backend-config=bucket=terraform-state-user',
          `-backend-config=key=${key}`,
          `-backend-config=region=${region}`,
          '-backend-config=dynamodb_table=terraform-locks-user',
        ],
        terraformDir,
        env,
      );

      // Step 9: Run Terraform destroy with dynamic lock handling
      const deployment = await this.findOne(deploymentId);
      const github_repo_url = deployment.orgRepoUrl;
      const destroyCommands = [
        'destroy',
        '-auto-approve',
        `-var=user_id=${userId}`,
        `-var=site_name=${siteName}`,
        `-var=account_id=${accountId}`,
        `-var=aws_access_key_id=${accessKeyId}`,
        `-var=aws_secret_access_key=${secretAccessKey}`,
        `-var=aws_session_token=${sessionToken}`,
        `-var=instance_name=${instance_name}`,
        `-var=disk_name=${disk_name}`,
        `-var=github_repo_url=${github_repo_url}`,
      ];
      logger.info('Running terraform destroy...');
      try {
        await runTerraformCommand(destroyCommands, terraformDir, env);
        logger.info('Terraform destroy successful');
      } catch (error) {
        const errorMessage = error.message || error.stderr || '';
        const lockIdMatch = errorMessage.match(/ID:\s*([a-f0-9-]+)\s/);
        if (lockIdMatch && lockIdMatch[1]) {
          const lockId = lockIdMatch[1];
          logger.info(`Detected lock ID: ${lockId}`);
          try {
            await runTerraformCommand(['force-unlock', '-force', lockId], terraformDir, env);
            logger.info('Terraform state unlocked');
            await runTerraformCommand(destroyCommands, terraformDir, env);
            logger.info('Terraform destroy successful after unlock');
          } catch (unlockError) {
            logger.error(`Force-unlock failed: ${unlockError.message}`);
            logger.info('Attempting to delete lock from DynamoDB...');
            const dynamodb = new AWS.DynamoDB({ region, credentials: { accessKeyId, secretAccessKey, sessionToken } });
            try {
              await dynamodb
                .deleteItem({
                  TableName: 'terraform-locks-user',
                  Key: { LockID: { S: lockId } },
                })
                .promise();
              logger.info('DynamoDB lock deleted');
              await runTerraformCommand(destroyCommands, terraformDir, env);
              logger.info('Terraform destroy successful after DynamoDB unlock');
            } catch (dynamoError) {
              logger.error(`DynamoDB unlock failed: ${dynamoError.message}`);
              logger.info('Falling back to -lock=false...');
              await runTerraformCommand([...destroyCommands, '-lock=false'], terraformDir, env);
              logger.info('Terraform destroy successful with -lock=false');
            }
          }
        } else {
          logger.info('No lock ID found, falling back to -lock=false...');
          await runTerraformCommand([...destroyCommands, '-lock=false'], terraformDir, env);
          logger.info('Terraform destroy successful with -lock=false');
        }
      }

      // Step 10: Clean up Lightsail snapshots
      logger.info(`Cleaning up Lightsail snapshots for userId: ${userId}...`);
      try {
        const snapshotResponse = await lightsailClient.send(new GetInstanceSnapshotsCommand({}));
        const snapshotPrefix = `lightsail-${userId}-${siteName}`;
        const snapshotsToDelete = snapshotResponse.instanceSnapshots?.filter((s) => s.name?.startsWith(snapshotPrefix)) || [];

        for (const snapshot of snapshotsToDelete) {
          logger.info(`Deleting snapshot ${snapshot.name}...`);
          await lightsailClient.send(new DeleteInstanceSnapshotCommand({ instanceSnapshotName: snapshot.name }));
          logger.info(`Deleted snapshot ${snapshot.name}`);
        }
        logger.info(snapshotsToDelete.length ? 'Snapshot cleanup completed' : 'No snapshots to delete');
      } catch (error) {
        logger.error(`Failed to clean up snapshots: ${error.message}`);
        throw new Error(`Snapshot cleanup failed: ${error.message}`);
      }

      // Step 11: Clean up Secrets Manager secrets
      await this.cleanupScheduledSecrets(userId, siteName);

      // Step 12: Clean up profile
  const awsCredentialsPath = path.join(os.homedir(), '.aws', 'credentials');

if (fs.existsSync(awsCredentialsPath)) {
  let credentialsContent = fs.readFileSync(awsCredentialsPath, 'utf-8');

  // Supprimer uniquement le bloc du profil temporaire
  const regex = new RegExp(`\\[${tempProfile}\\][\\s\\S]*?(?=\\[|$)`, 'g');
  const updatedContent = credentialsContent.replace(regex, '').trim();

  fs.writeFileSync(awsCredentialsPath, updatedContent);
  logger.info(`✅ Removed AWS CLI profile: ${tempProfile}`);
}
      
    

      // Step 13: Delete from database
      logger.info(`Deleted deployment ${deploymentId} from database`);
    } catch (error) {
      logger.error(`Failed to destroy: ${error.message}`);
      throw new Error(`Failed to destroy infrastructure: ${error.message}`);
    } finally {
      if (secretsManagerClient) secretsManagerClient.destroy();
      if (lightsailClient) lightsailClient.destroy();
    }
  }


  
  async deleteGitHubRepositories(userId: number, siteName: string): Promise<void> {
    const repoName = `drupal-${userId}-${siteName}`;
    logger.info(`Deleting GitHub repositories for ${repoName}`);

    try {
      const user = await this.getUserById(userId);

      if (!user || !user.githubToken) {
        throw new Error('User not found or GitHub token missing');
      }

      // Delete organization repository
      await firstValueFrom(
        this.httpService.delete(`${this.githubApiUrl}/repos/${this.orgName}/${repoName}`, {
          headers: this.getAuthHeaders(),
        })
      );
      logger.info(`Deleted organization repository: ${this.orgName}/${repoName}`);
    } catch (error) {
      if (error.response?.status === 404) {
        logger.warn(`Repository ${repoName} not found, skipping deletion`);
      } else {
        logger.error(`Failed to delete GitHub repositories: ${error.message}`);
        throw error;
      }
      


      

      // Get the GitHub username
    /*  const githubUserResponse = await firstValueFrom(
        this.httpService.get('https://api.github.com/user', {
          headers: {
            Authorization: `token ${user.githubToken}`,
            Accept: 'application/vnd.github.v3+json',
          },
        })
      );
      const githubUsername = githubUserResponse.data.login;

      // Delete user repository
      await firstValueFrom(
        this.httpService.delete(`${this.githubApiUrl}/repos/${githubUsername}/${repoName}`, {
          headers: this.getUserAuthHeaders(user.githubToken),
        })
      );
      logger.info(`Deleted user repository: ${githubUsername}/${repoName}`);
    } catch (error) {
      if (error.response?.status === 404) {
        logger.warn(`Repository ${repoName} not found, skipping deletion`);
      } else {
        logger.error(`Failed to delete GitHub repositories: ${error.message}`);
        throw error;
      }*/

    }
    
  }





  /*async deleteCloudflareDNSRecord(cloudflareDomain: string): Promise<void> {
    logger.info(`Deleting Cloudflare DNS record for ${cloudflareDomain}`);

    try {
      const cloudflareZoneId = process.env.CLOUDFLARE_ZONE_ID;
      const cloudflareApiToken = process.env.CLOUDFLARE_API_TOKEN;

      if (!cloudflareZoneId || !cloudflareApiToken) {
        throw new Error('Cloudflare credentials not configured');
      }

      // Step 1: Find the DNS record
      const dnsRecordsResponse = await firstValueFrom(
        this.httpService.get(`${this.cloudflareApiUrl}/zones/${cloudflareZoneId}/dns_records`, {
          headers: {
            Authorization: `Bearer ${cloudflareApiToken}`,
            'Content-Type': 'application/json',
          },
          params: {
            name: cloudflareDomain,
            type: 'A', // Assuming an A record; adjust if using CNAME or other types
          },
        })
      );

      const dnsRecords = dnsRecordsResponse.data.result;
      if (dnsRecords.length === 0) {
        logger.warn(`No DNS record found for ${cloudflareDomain}, skipping deletion`);
        return;
      }

      // Step 2: Delete the DNS record
      const dnsRecordId = dnsRecords[0].id;
      await firstValueFrom(
        this.httpService.delete(`${this.cloudflareApiUrl}/zones/${cloudflareZoneId}/dns_records/${dnsRecordId}`, {
          headers: {
            Authorization: `Bearer ${cloudflareApiToken}`,
            'Content-Type': 'application/json',
          },
        })
      );
      logger.info(`Deleted Cloudflare DNS record for ${cloudflareDomain}`);
    } catch (error) {
      logger.error(`Failed to delete Cloudflare DNS record for ${cloudflareDomain}: ${error.message}`);
      throw error;
    }
  }
  */



 /*async createUserDeployment(userId: string, siteId: string, githubUsername?: string): Promise<string> {
    const repoName = `drupal-${userId}-${siteId}`;

    // Créer le repo GitHub
    const createResponse = await this.httpService
      .post(
        `${this.githubApiUrl}/repos/${this.orgName}/drupal-template/generate`,
        {
          name: repoName,
          private: true,
          description: `Drupal site ${siteId} for user ${userId}`,
        },
        {
          headers: {
            Authorization: `token ${this.githubToken}`,
            Accept: 'application/vnd.github.v3+json',
          },
        },
      )
      .toPromise();

    if (createResponse.status !== 201) {
      throw new Error(`Failed to create GitHub repo: ${createResponse.data.message || 'Unknown error'}`);
    }

    const repoUrl = `https://github.com/${this.orgName}/${repoName}`;

    // Ajouter collaborateur si githubUsername est fourni
    if (githubUsername) {
      const inviteResponse = await this.httpService
        .put(
          `${this.githubApiUrl}/repos/${this.orgName}/${repoName}/collaborators/${githubUsername}`,
          { permission: 'write' },
          {
            headers: {
              Authorization: `token ${this.githubToken}`,
              Accept: 'application/vnd.github.v3+json',
            },
          },
        )
        .toPromise();

      if (inviteResponse.status !== 201) {
        console.warn(`Failed to add collaborator ${githubUsername}: ${inviteResponse.data.message}`);
      }
    }

    return repoUrl;
  }
 */
/*

  async createUserDeployment(
    userId: string, 
    siteId: string, 
    githubUsername?: string
  ): Promise<{ repoUrl: string; cloneCommand: string }> {
    const repoName = `drupal-${userId}-${siteId}`;
  
    try {
      // 1. Création du repository
      const createResponse = await firstValueFrom(
        this.httpService.post(
          `${this.githubApiUrl}/repos/${this.orgName}/drupal-template/generate`,
          {
            name: repoName,
            private: true,
            description: `Drupal site ${siteId} for user ${userId}`,
            owner: this.orgName
          },
          { headers: this.getAuthHeaders() }
        )
      );
  
      if (createResponse.status !== 201) {
        throw new Error(`Failed to create repository: ${createResponse.data.message}`);
      }
  
      const repoUrl = createResponse.data.html_url;
      const sshUrl = createResponse.data.ssh_url;
  
      // 2. Ajout du collaborateur (si fourni)
      if (githubUsername) {
        try {
          await firstValueFrom(
            this.httpService.put(
              `${this.githubApiUrl}/repos/${this.orgName}/${repoName}/collaborators/${githubUsername}`,
              { permission: 'push' },
              { headers: this.getAuthHeaders() }
            )
          );
        } catch (collabError) {
          console.error(`Collaborator addition warning: ${collabError.message}`);
          // Ne pas bloquer le processus pour cette erreur
        }
      }
  
      // 3. Configuration supplémentaire (optionnelle)
      await this.configureRepoDefaults(repoName);
  
      return {
        repoUrl,
        cloneCommand: `git clone ${sshUrl} ${repoName}`
      };
  
    } catch (error) {
      console.error(`Deployment failed: ${error.message}`);
      throw new Error(`Could not complete deployment: ${error.message}`);
    }
  }
  */
  
  



  


  
  
  /*async setupUserDeployment(userId: string, siteId: string): Promise<{ orgRepoUrl: string; userRepoUrl: string }> {
    const repoName = `drupal-${userId}-${siteId}`;
    const user = await this.getUserById(userId);
    console.log('helou',user)
    if (!user || !user.githubToken) {
      throw new Error('User not found or GitHub token missing');
    }
    const userGithubToken = user.githubToken;
    const githubUsername = user.username;
    console.log(userGithubToken)
    console.log(githubUsername)

    try {
      // 1. Crée le repo dans l’org
      const orgResponse = await firstValueFrom(
        this.httpService.post(
          `${this.githubApiUrl}/repos/${this.orgName}/drupal-template/generate`,
          {
            name: repoName,
            private: true,
            description: `Drupal site ${siteId} for user ${userId}`,
            owner: this.orgName,
          },
          { headers: this.getAuthHeaders() },
        ),
      );
      if (orgResponse.status !== 201) {
        throw new Error(`Failed to create org repository: ${orgResponse.data.message}`);
      }
      const orgRepoUrl = orgResponse.data.html_url;

      // 2. Crée le repo utilisateur
      const userResponse = await firstValueFrom(
        this.httpService.post(
          `${this.githubApiUrl}/user/repos`,
          {
            name: repoName,
            private: true,
            description: `User repo for ${siteId}`,
          },
          { headers: this.getUserAuthHeaders(userGithubToken) },
        ),
      );
      const userRepoUrl = userResponse.data.html_url;
      const userRepoFullName = `${githubUsername}/${repoName}`;

      // 3. Ajoute le collaborateur au repo org (optionnel)
      if (githubUsername) {
        try {
          await firstValueFrom(
            this.httpService.put(
              `${this.githubApiUrl}/repos/${this.orgName}/${repoName}/collaborators/${githubUsername}`,
              { permission: 'push' },
              { headers: this.getAuthHeaders() },
            ),
          );
        } catch (collabError) {
          console.error(`Collaborator addition warning: ${collabError.message}`);
        }
      }

      // 4. Configure le repo org
      await this.configureRepoDefaults(repoName);

      // 5. Ajoute le webhook au repo utilisateur
      await this.addWebhookToUserRepo(userGithubToken, userRepoFullName);

      return {
        orgRepoUrl,
        userRepoUrl,
      };
    } catch (error) {
      console.error(`Deployment failed: ${error.message}`);
      throw new Error(`Could not complete deployment: ${error.message}`);
    }
  }
    */

//github token tetaada variable ! when user click deploy naaytou l interface connect github => retrun token nasnoulou l url github baadika
//interface site_name , cloudflare domain , verif if c bn andou github ou nn then naytou fonction deploy infra baadhha trigger taa pipeline
 /* async setupUserDeployment(userId: number, siteName: string): Promise<{ orgRepoUrl: string; userRepoUrl: string }> {
    const repoName = `drupal-${userId}-${siteName}`;
    const user = await this.getUserById(userId);
    if (!user || !user.githubToken) {
      throw new Error('User not found or GitHub token missing');
    }
    const userGithubToken = user.githubToken;
  
    // Récupérer githubUsername
    const githubUserResponse = await firstValueFrom(
      this.httpService.get('https://api.github.com/user', {
        headers: {
          Authorization: `token ${userGithubToken}`,
          Accept: 'application/vnd.github.v3+json',
        },
      })
    );
    const githubUsername = githubUserResponse.data.login;
    console.log(`GitHub username: ${githubUsername}`);
  
    // 1. Créer dépôt org
    let orgResponse;
    try {
      orgResponse = await firstValueFrom(
        this.httpService.post(
          `${this.githubApiUrl}/repos/${this.orgName}/drupal-template/generate`,
          {
            name: repoName,
            private: true,
            description: `Drupal site ${siteName} for user ${userId}`,
            owner: this.orgName,
          },
          { headers: this.getAuthHeaders() }
        )
      );
    } catch (error) {
      console.error(`Org repo creation failed: ${error.response?.data?.message || error.message}`);
      throw new Error(`Failed to create org repository: ${error.message}`);
    }
    const orgRepoUrl = orgResponse.data.html_url;
  
    // 2. Créer dépôt utilisateur (vide)
    const userResponse = await firstValueFrom(
      this.httpService.post(
        `${this.githubApiUrl}/user/repos`,
        {
          name: repoName,
          private: true,
          description: `User repo for ${siteName}`,
        },
        { headers: this.getUserAuthHeaders(userGithubToken) }
      )
    );
    
    const userRepoUrl = userResponse.data.html_url;
    console.log("heelo from git setup")
    const userRepoFullName = `${githubUsername}/${repoName}`;
  
  /*  // 3. Ajouter collaborateur
    try {
      await firstValueFrom(
        this.httpService.put(
          `${this.githubApiUrl}/repos/${this.orgName}/${repoName}/collaborators/${githubUsername}`,
          { permission: 'push' },
          { headers: this.getAuthHeaders() }
        )
      );
    } catch (error) {
      console.error(`Collaborator addition warning: ${error.message}`);
    }
  */
    // 4. Configurer repo org
   // await this.configureRepoDefaults(repoName).catch(err => console.error(`Branch protection error: ${err.message}`));
  
    // 5. Ajouter webhook
    //await this.addWebhookToUserRepo(userGithubToken, userRepoFullName);
  
   // return {orgRepoUrl, userRepoUrl} ;
 // }


/////////////////// Original ///////////////////
  /*async setupUserDeployment(userId: number, siteName: string): Promise<{ userRepoUrl: string }> {
    const repoName = `drupal-${userId}-${siteName}`;
    const user = await this.getUserById(userId);

    if (!user || !user.githubToken) {
      throw new Error('User not found or GitHub token missing');
    }
   // const userGithubToken = user.githubToken;

   //retrieve token from the secrets manager or passed it into the front ! 


   const userGithubToken = process.env.userGithubToken
  
    // Récupérer githubUsername
    const githubUserResponse = await firstValueFrom(
      this.httpService.get('https://api.github.com/user', {
        headers: {
          Authorization: `token ${userGithubToken}`,
          Accept: 'application/vnd.github.v3+json',
        },
      })
    );
    const githubUsername = githubUserResponse.data.login;
  
  
   //rend templaterepo variable 
    // 1. Créer dépôt utilisateur
    let userResponse;
    try {
      userResponse = await firstValueFrom(
        this.httpService.post(
          `${this.githubApiUrl}/repos/${this.orgName}/Basic_Template/generate`,
          {
            name: repoName,
            private: true,
            description: `Drupal site ${siteName} for user ${userId}`,
           // owner: this.orgName,
            owner : githubUsername ,
            include_all_branches:true
          },
          { headers: this.getAuthHeaders() }
        )
      );
    } catch (error) {
      const errorMessage = error.response?.data?.errors?.[0]?.message || error.response?.data?.message;
      throw new Error(`Failed to create org repository: ${errorMessage || 'Unknown error'}`);
    }
    const userRepoUrl = userResponse.data.html_url;
    const userRepoFullName = `${this.orgName}/${repoName}`;
  
    // Vérifier si le dépôt utilisateur existe déjà
   /* try {
      const checkUserRepo = await firstValueFrom(
        this.httpService.get(`${this.githubApiUrl}/repos/${githubUsername}/${repoName}`, {
          headers: this.getUserAuthHeaders(userGithubToken)
        })
      );
      if (checkUserRepo.status === 200) {
        throw new Error(`User repository ${githubUsername}/${repoName} already exists`);
      }
    } catch (error) {
      if (error.response?.status !== 404) {
        throw new Error(`Error checking user repo: ${error.response?.data?.message || error.message}`);
      }
    }
  
    // 2. Créer dépôt utilisateur avec gestion d'erreur améliorée
    let userResponse;
    try {
      userResponse = await firstValueFrom(
        this.httpService.post(
          `${this.githubApiUrl}/user/repos`,
          {
            name: repoName,
            private: true,
            description: `User repo for ${siteName}`,
          },
          { headers: this.getUserAuthHeaders(userGithubToken) }
        )
      );
    } catch (error) {
      const errorMessage = error.response?.data?.errors?.[0]?.message || error.response?.data?.message;
      throw new Error(`Failed to create user repository: ${errorMessage || 'Unknown error'}`);
    }
  
    const userRepoUrl = userResponse.data.html_url;
    const userRepoFullName = `${githubUsername}/${repoName}`;

  // 3. Clone all branches and content from org repo to user repo
  try {
    // Fetch branches from org repo
    const orgBranchesResponse = await firstValueFrom(
      this.httpService.get(`${this.githubApiUrl}/repos/${orgRepoFullName}/branches`, {
        headers: this.getAuthHeaders(),
      })
    );
    const branches = orgBranchesResponse.data.map((branch: any) => ({
      name: branch.name,
      commitSha: branch.commit.sha,
    }));

    // For each branch, create it in the user repo and copy content
    for (const branch of branches) {
      try {
        // Create branch in user repo
        await firstValueFrom(
          this.httpService.post(
            `${this.githubApiUrl}/repos/${userRepoFullName}/git/refs`,
            {
              ref: `refs/heads/${branch.name}`,
              sha: branch.commitSha,
            },
            { headers: this.getUserAuthHeaders(userGithubToken) }
          )
        );

        // Verify content by fetching the commit tree (optional, for debugging)
        const commitResponse = await firstValueFrom(
          this.httpService.get(`${this.githubApiUrl}/repos/${orgRepoFullName}/git/commits/${branch.commitSha}`, {
            headers: this.getAuthHeaders(),
          })
        );
        const treeSha = commitResponse.data.tree.sha;

        // Fetch tree to ensure content is accessible
        await firstValueFrom(
          this.httpService.get(`${this.githubApiUrl}/repos/${orgRepoFullName}/git/trees/${treeSha}?recursive=1`, {
            headers: this.getAuthHeaders(),
          })
        );
      } catch (error) {
        console.error(`Failed to clone branch ${branch.name} to user repo: ${error.response?.data?.message || error.message}`);
        // Continue with other branches
      }
    }
  } catch (error) {
    console.error(`Failed to fetch branches from org repo: ${error.response?.data?.message || error.message}`);
    throw new Error('Failed to clone organization repository to user repository');
  }
  
 // 4. Configurer repo org
    await this.configureRepoDefaults(repoName).catch(err => console.error(`Branch protection error: ${err.message}`));


  
    // 5. Ajouter webhook
    await this.addWebhookToUserRepo(userGithubToken, userRepoFullName);  
    
    return {  userRepoUrl };
  }
    */

  

  async configureRepoDefaults(repoName: string): Promise<void> {
    const branches = ['main', 'dev'];
    for (const branch of branches) {
      try {
        await firstValueFrom(
          this.httpService.put(
            `${this.githubApiUrl}/repos/${this.orgName}/${repoName}/branches/${branch}/protection`,
            {
              required_status_checks: null,
              enforce_admins: true,
              required_pull_request_reviews: {
                required_approving_review_count: 1,
              },
              restrictions: null,
            },
            { headers: this.getAuthHeaders() }
          )
        );
      } catch (error) {
        console.error(`Failed to configure branch protection for ${branch}: ${error.response?.data?.message || error.message}`);
      }
    }
  }

  ///////////////////////Testing


async generateUserRepoFromOrgTemplate(
  userGithubToken: string,
  userGithubUsername: string,
  orgTemplateRepo: string, // e.g., 'drupal-org-repo'
  siteName: string,
  userId: number,
): Promise<string> {
  const repoName = `drupal-${userId}-${siteName}`;

  try {
    const response = await firstValueFrom(
      this.httpService.post(
        `https://api.github.com/repos/${this.orgName}/Basic_Template/generate`,
        {
          owner: userGithubUsername,
          name: repoName,
          private: true,
          include_all_branches: true,
          description: `Generated repo for user ${userId} / site ${siteName}`,
        },
        {
          headers: {
            Authorization: `token ${userGithubToken}`,
            Accept: 'application/vnd.github.baptiste-preview+json', // Required for /generate
          },
        }
      )
    );

    return response.data.html_url;
  } catch (error) {
    const message = error.response?.data?.message || error.message;
    throw new Error(`❌ Failed to generate user repo: ${message}`);
  }
}

///////////////////////////////////////////////

/*  async addWebhookToUserRepo(userGithubToken: string, userRepo: string) {
    try {
      const response = await firstValueFrom(
        this.httpService.post(
          `${this.githubApiUrl}/repos/${userRepo}/hooks`,
          {
            name: 'web',
            active: true,
            events: ['push'], // Trigger on push events
            config: {
              url: this.webhookUrl, // e.g., https://your-app/deployment/webhook
              content_type: 'json',
              secret: this.webhookSecret, // Secret to verify webhook payloads
            },
          },
          { headers: this.getUserAuthHeaders(userGithubToken) }
        )
      );
      logger.info(`Webhook added to ${userRepo} with ID ${response.data.id}`);
    } catch (error) {
      logger.error(`Failed to add webhook to ${userRepo}: ${error.response?.data?.message || error.message}`);
      throw new Error(`Webhook setup failed: ${error.message}`);
    }
  }
*/

 /* verifySignature(signature: string, payload: any): boolean {
    const hmac = crypto.createHmac('sha256', this.webhookSecret);
    const digest = `sha256=${hmac.update(JSON.stringify(payload)).digest('hex')}`;
    return signature === digest;
  }
*/

private async getUserRepoUrlFromDB(userId: number): Promise<string> {
  const result = await this.deploymentRepository.find({
    where: { userId },
    select: { userRepoUrl: true },
  });

  return result[0]?.userRepoUrl || '';
}


  private generateUniqueInstanceName(userId: string, siteName: string, bundleId: string): string {
    const sanitizedSiteName = siteName.toLowerCase().replace(/[^a-z0-9-]/g, '');
    const bundlePrefix = bundleId.split('_')[0];
    return `lightsail-${userId}-${sanitizedSiteName}-${bundlePrefix}`;
  }

  private async waitForInstanceState(userId: string,instanceName: string, targetState: string, maxRetries = 30, baseDelayMs = 4000): Promise<void> {

   // 1. Get temporary credentials from user service
        const data = await this.fetchTempCredentials(parseInt(userId,10));

         const { accessKeyId, secretAccessKey, sessionToken } = data;
    const sts = new AWS.STS({
      accessKeyId: accessKeyId,
      secretAccessKey: secretAccessKey,
      sessionToken: sessionToken,
    });
    const identity = await sts.getCallerIdentity().promise();
    const subAccountId = identity.Account;
    console.log(subAccountId)
  
    const stsClient = new STSClient({ region: 'us-east-1' });
    const { Credentials } = await stsClient.send(
      new AssumeRoleCommand({
        RoleArn: `arn:aws:iam::${subAccountId}:role/OrganizationAccountAccessRole`,
        RoleSessionName: `UpgradeInstanceSession-${Date.now()}`,
      }),
    );
  
    const lightsailClient = new LightsailClient({
      region: 'us-east-1',
      credentials: {
      accessKeyId: accessKeyId,
      secretAccessKey: secretAccessKey,
      sessionToken: sessionToken,
      },
    });

    const transitionalStates = ['pending', 'starting', 'stopping', 'rebooting', 'configuring', 'shutting-down'];
    let attempt = 1;

    while (attempt <= maxRetries) {
      try {
        const command = new GetInstanceCommand({ instanceName });
        const response = await lightsailClient.send(command);
        const state = response.instance?.state?.name;
        logger.info(`Instance ${instanceName} state: ${state}, attempt ${attempt}/${maxRetries}`);

        if (state === targetState) {
          logger.info(`Instance ${instanceName} is ${targetState}`);
          return;
        }

        if (transitionalStates.includes(state)) {
          const delay = baseDelayMs * Math.pow(1.5, attempt - 1); // Exponential backoff
          logger.info(`Instance in transition (${state}), waiting ${Math.round(delay)}ms...`);
          await new Promise(resolve => setTimeout(resolve, delay));
          attempt++;
          continue;
        }

        throw new HttpException(`Instance in unexpected state: ${state}`, HttpStatus.BAD_REQUEST);
      } catch (error) {
        logger.error(`Error checking instance state on attempt ${attempt}: ${error.message}`);
        if (error.name === 'ThrottlingException' && attempt < maxRetries) {
          const delay = baseDelayMs * Math.pow(2, attempt);
          logger.info(`Throttling detected, retrying after ${Math.round(delay)}ms...`);
          await new Promise(resolve => setTimeout(resolve, delay));
          attempt++;
          continue;
        }
        throw new HttpException(`Failed to check instance state: ${error.message || 'unknown error'}`, HttpStatus.INTERNAL_SERVER_ERROR);
      }
    }

    throw new HttpException(`Instance ${instanceName} not ${targetState} after ${maxRetries} attempts`, HttpStatus.SERVICE_UNAVAILABLE);
  }



  private allowedBundleIds: string[] = ['micro_3_0','small_3_0', 'medium_3_0'];
  
  async upgradeLightsailInstance({
    userId,
    siteName,
    bundleId,
  }: {
    userId: string;
    siteName: string;
    bundleId: string;
  }) {
    
    // Initialize variables


   // const bundleId = this.allowedBundleIds[1];
    
    console.log(`Fetching temporary credentials for user ${userId}...`);
 // 1. Get temporary credentials from user service
        const data = await this.fetchTempCredentials(parseInt(userId,10));

         const { accessKeyId, secretAccessKey, sessionToken } = data;
   if (!this.allowedBundleIds.includes(bundleId)) {
  throw new Error(`Bundle ID ${bundleId} non autorisé.`);
}
    const sts = new AWS.STS({
      accessKeyId: accessKeyId,
      secretAccessKey: secretAccessKey,
      sessionToken: sessionToken,
    });
    const identity = await sts.getCallerIdentity().promise();
    const subAccountId = identity.Account;
    console.log(subAccountId)
  
    const stsClient = new STSClient({ region: 'us-east-1' });
    const { Credentials } = await stsClient.send(
      new AssumeRoleCommand({
        RoleArn: `arn:aws:iam::${subAccountId}:role/OrganizationAccountAccessRole`,
        RoleSessionName: `UpgradeInstanceSession-${Date.now()}`,
      }),
    );
  
    const lightsailClient = new LightsailClient({
      region: 'us-east-1',
      credentials: {
      accessKeyId: accessKeyId,
      secretAccessKey: secretAccessKey,
      sessionToken: sessionToken,
      },
    });

  
    const secretsManagerClient = new SecretsManagerClient({
      region: 'us-east-1',
      credentials: {
        accessKeyId: accessKeyId,
      secretAccessKey: secretAccessKey,
      sessionToken: sessionToken,
      },
    });
  
    try {
      // Fetch secrets and derive variables
      const secretName = `sites/${userId}/${siteName}`;
      console.log(`Fetching details from Secrets Manager for ${secretName}...`);
      const secretResponse = await secretsManagerClient.send(
        new GetSecretValueCommand({
          SecretId: secretName,
        }),
      );
      const siteSecrets = JSON.parse(secretResponse.SecretString);
      const { instance_name, db_endpoint, db_username, db_password, db_name , disk_name } = siteSecrets;
  
      const oldInstanceName = instance_name; // Blue environment (e.g., lightsail_19_lastestupgradefeature)
    //  const newInstanceName = `${oldInstanceName}-upgraded`; // Green environment (e.g., lightsail_19_lastestupgradefeature-upgraded)
    const newInstanceName = this.generateUniqueInstanceName(userId,siteName,bundleId);  
    const oldDiskName =disk_name;
    const staticIpName = `static-ip-${userId}-${siteName}`; // Derive static IP name
  
      // Create a temporary AWS CLI profile for the sub-account credentials
      const tempProfile = `temp-subaccount-${userId}-${siteName}`; // Unique profile name to avoid conflicts
      execSync(`aws configure set aws_access_key_id ${accessKeyId} --profile ${tempProfile}`, { stdio: 'inherit' });
      execSync(`aws configure set aws_secret_access_key ${secretAccessKey} --profile ${tempProfile}`, { stdio: 'inherit' });
      execSync(`aws configure set aws_session_token ${sessionToken} --profile ${tempProfile}`, { stdio: 'inherit' });
      logger.info(`Created temporary AWS CLI profile: ${tempProfile}`);
  
      const env = { ...process.env, AWS_PROFILE: tempProfile, PATH: `${process.env.PATH};C:\\windows\\system32`, 
      TF_LOG: "DEBUG", // 🔍 Active les logs détaillés
  TF_LOG_PATH: "./terraform1.log", };
  
      // Preliminary Check: Verify Terraform state matches expected names
      console.log(`Verifying Terraform state matches expected resource names...`);
      const terraformDir = path.resolve('terraform', 'Basic_Plan', 'PROD');

  
      // Initialize Terraform with the remote backend
    const key=`sites/${userId}/${siteName}/terraform.tfstate`  
    try {
        await runTerraformCommand([
          'init',
          '-reconfigure',
          '-backend-config=bucket=terraform-state-user',
         `-backend-config=key=${key}`,
          `-backend-config=region=us-east-1`,
          '-backend-config=dynamodb_table=terraform-locks-user'
        ], terraformDir, env);
      } catch (error) {
        logger.error(`Terraform init failed: ${error.message}`);
        throw new Error(`Terraform init failed: ${error.message}`);
      }
       
      // Check if the state file exists and contains the expected resources
      let stateOutOfSync = false;
      try {
        const { stdout: stateList, stderr } = await execAsync(
          `terraform -chdir=${terraformDir} state list`,
          { env }
        );
        console.log(`Terraform state list stdout: ${stateList}`);
        if (stderr) console.warn(`Terraform state list stderr: ${stderr}`);
  
        const expectedResources = [
          'aws_lightsail_instance.instance',
          'aws_lightsail_disk.disk',
          'aws_lightsail_disk_attachment.disk_attachment',
        ];
        const missingResources = expectedResources.filter(resource => !stateList.includes(resource));
  
        if (missingResources.length > 0) {
          console.log(`Terraform state is missing resources: ${missingResources.join(', ')}. Will attempt to import the affected resources.`);
          stateOutOfSync = true;
        } else {
          const { stdout: instanceState, stderr: instanceStderr } = await execAsync(
            `terraform -chdir=${terraformDir} state show aws_lightsail_instance.instance`,
            { env }
          );
          console.log(`Terraform state show instance stdout: ${instanceState}`);
          if (instanceStderr) console.warn(`Terraform state show instance stderr: ${instanceStderr}`);
  
          const { stdout: diskState, stderr: diskStderr } = await execAsync(
            `terraform -chdir=${terraformDir} state show aws_lightsail_disk.disk`,
            { env }
          );
          console.log(`Terraform state show disk stdout: ${diskState}`);
          if (diskStderr) console.warn(`Terraform state show disk stderr: ${diskStderr}`);
  
          if (
            !instanceState.includes(`name = ${oldInstanceName}`) ||
            !diskState.includes(`name = ${oldDiskName}`)
          ) {
            console.log(`Terraform state is out of sync. Expected instance name: ${oldInstanceName}, disk name: ${oldDiskName}. Will attempt to import the affected resources.`);
            stateOutOfSync = true;
          }
        }
      } catch (error) {
        console.log(`Error checking Terraform state: ${error.message}. Assuming state is missing or out of sync, will attempt to import resources.`);
        stateOutOfSync = true;
      }
      const userRepoUrl = await this.getUserRepoUrlFromDB(+(userId as string)); // Converts string to number;
      console.log(userRepoUrl)
  
      // If the state is out of sync, import only the affected resources (instance, disk, disk attachment)
      if (stateOutOfSync) {
        console.log(`Importing affected resources into Terraform state...`);
        const importVars = [
          `-var=user_id=${userId}`,
          `-var=site_name="${siteName}"`,
          `-var=account_id="${subAccountId}"`,
          `-var=aws_access_key_id="${accessKeyId}"`,
          `-var=aws_secret_access_key="${secretAccessKey}"`,
          `-var=aws_session_token="${sessionToken}"`,
          `-var=instance_name="${oldInstanceName}"`,
          `-var=disk_name="${oldDiskName}"`,
          `-var="github_repo_url=${userRepoUrl}"`,

        ].join(' ');


     

             // Remove only the affected resources if they exist

        const instanceResponse = await lightsailClient.send(
         new GetInstanceCommand({ instanceName: oldInstanceName })
          );
console.log("Instance exists:", instanceResponse.instance?.name);

     
        try {
          await execAsync(`terraform -chdir=${terraformDir} state rm aws_lightsail_instance.instance`, { env });
          await execAsync(`terraform -chdir=${terraformDir} state rm aws_lightsail_disk.disk`, { env });
          await execAsync(`terraform -chdir=${terraformDir} state rm aws_lightsail_disk_attachment.disk_attachment`, { env });
          console.log(`Removed existing instance, disk, and disk attachment from Terraform state.`);
        } catch (error) {
          console.log(`No previous instance, disk, or disk attachment found in Terraform state. Proceeding with import...`);
        }
       

  
        // Import only the affected resources
        try {
          console.log('hrlo')
          await execAsync(
  `terraform -chdir=${terraformDir} import ${importVars} aws_lightsail_instance.instance ${oldInstanceName}`,
  { env, timeout: 200_000 } // 5 minutes
);
          console.log(`Imported aws_lightsail_instance.instance`);
        } catch (error) {
          console.error(`Failed to import instance ${oldInstanceName}: ${error.message}`);
          throw new Error(`Failed to import aws_lightsail_instance.instance: ${error.message}`);
        }
  
        try {
          await execAsync(
            `terraform -chdir=${terraformDir} import ${importVars} aws_lightsail_disk.disk ${oldDiskName}`,
            { env }
          );
          console.log(`Imported aws_lightsail_disk.disk`);
        } catch (error) {
          console.error(`Failed to import disk ${oldDiskName}: ${error.message}`);
          throw new Error(`Failed to import aws_lightsail_disk.disk: ${error.message}`);
        }
  
        // Import the disk attachment
        try {
          await execAsync(
            `terraform -chdir=${terraformDir} import ${importVars} aws_lightsail_disk_attachment.disk_attachment ${oldDiskName},${oldInstanceName}`,
            { env }
          );
          console.log(`Imported aws_lightsail_disk_attachment.disk_attachment`);
        } catch (error) {
          console.error(`Failed to import disk attachment for ${oldDiskName} and ${oldInstanceName}: ${error.message}`);
          throw new Error(`Failed to import aws_lightsail_disk_attachment.disk_attachment: ${error.message}`);
        }
  
        console.log(`Terraform state updated with correct instance (${oldInstanceName}), disk (${oldDiskName}), and disk attachment. Proceeding with deployment...`);
      } else {
        console.log(`Terraform state is consistent with expected names (${oldInstanceName}, ${oldDiskName}). Proceeding with deployment...`);
      }
  
      // Step 1: Create a Green Environment Using Only an Instance Snapshot
      console.log(`Step 1: Creating green environment for ${newInstanceName}...`);
      const instanceResponse = await lightsailClient.send(
        new GetInstanceCommand({
          instanceName: oldInstanceName,
        }),
      );
      const keyPairName = instanceResponse.instance?.sshKeyName;
      if (!keyPairName) {
        throw new Error(`Could not determine key pair name for instance ${oldInstanceName}.`);
      }
  
      const snapshotName = `${oldInstanceName}-snapshot-${Date.now()}`;
      await lightsailClient.send(
        new CreateInstanceSnapshotCommand({
          instanceName: oldInstanceName,
          instanceSnapshotName: snapshotName,
        }),
      );
      let snapshotStatus = '';
      while (snapshotStatus !== 'available') {
        const snapshotResponse = await lightsailClient.send(
          new GetInstanceSnapshotCommand({
            instanceSnapshotName: snapshotName,
          }),
        );
        snapshotStatus = snapshotResponse.instanceSnapshot.state;
        if (snapshotStatus !== 'available') {
          console.log(`Snapshot status: ${snapshotStatus}. Waiting 5 seconds...`);
          await new Promise((resolve) => setTimeout(resolve, 5000));
        }
      }
      console.log(`Instance snapshot ${snapshotName} created!`);
  
      // Step 2: Prepare Green Instance
      console.log(`Step 2: Preparing green instance ${newInstanceName}...`);
      const userDataScript = `#!/bin/bash
  # Set environment variables for database connection
  export DB_HOST="${db_endpoint}"
  export DB_PORT="3306"
  export DB_NAME="${db_name}"
  export DB_USER="${db_username}"
  export DB_PASS="${db_password}"
  # Persist environment variables
  echo "DB_HOST=${db_endpoint}" >> /etc/environment
  echo "DB_PORT=3306" >> /etc/environment
  echo "DB_NAME=${db_name}" >> /etc/environment
  echo "DB_USER=${db_username}" >> /etc/environment
  echo "DB_PASS=${db_password}" >> /etc/environment
  
  # Mount the block storage disk (attached at /dev/xvdf)
  if [ -b /dev/xvdf ]; then
    if ! mountpoint -q /mnt/drupal-data; then
      if ! blkid /dev/xvdf | grep -q 'TYPE='; then
        echo "Formatting /dev/xvdf as ext4..."
        mkfs.ext4 /dev/xvdf
      fi
      echo "Creating mount point /mnt/drupal-data..."
      mkdir -p /mnt/drupal-data
      echo "Mounting /dev/xvdf to /mnt/drupal-data..."
      mount /dev/xvdf /mnt/drupal-data
      echo "Adding /mnt/drupal-data to fstab..."
      echo "/dev/xvdf /mnt/drupal-data ext4 defaults,nofail 0 2" >> /etc/fstab
    else
      echo "/mnt/drupal-data is already mounted."
    fi
  else
    echo "Error: /dev/xvdf not found. Block storage disk may not be attached."
    exit 1
  fi
  echo "Creating directories /mnt/drupal-data/sites and /mnt/drupal-data/config..."
  mkdir -p /mnt/drupal-data/sites /mnt/drupal-data/config
  echo "Setting ownership to www-data (33:33)..."
  chown -R 33:33 /mnt/drupal-data/sites /mnt/drupal-data/config
  
  # Verify settings.php exists
  SETTINGS_FILE="/mnt/drupal-data/sites/default/settings.php"
  if [ ! -f "$SETTINGS_FILE" ]; then
    echo "Creating settings.php..."
    mkdir -p /mnt/drupal-data/sites/default
    cp /var/www/html/sites/default/default.settings.php "$SETTINGS_FILE"
    chown 33:33 "$SETTINGS_FILE"
    chmod 644 "$SETTINGS_FILE"
  fi
  
  # Append database settings to settings.php if not present
  if ! grep -q "\\\$databases\\['default'\\]\\['default'\\]" "$SETTINGS_FILE"; then
    echo "Adding database settings to settings.php..."
    cat <<EOL >> "$SETTINGS_FILE"
  \\\$databases['default']['default'] = [
    'driver' => 'mysql',
    'database' => '$DB_NAME',
    'username' => '$DB_USER',
    'password' => '$DB_PASS',
    'host' => '$DB_HOST',
    'port' => '$DB_PORT',
  ];
  EOL
  fi
  
  # Ensure Docker is running
  systemctl start docker
  systemctl enable docker
  
  # Start the Drupal container
  CONTAINER_NAME="drupal_${userId}_${siteName}"
  if docker ps -a --filter "name=$CONTAINER_NAME" --format '{{.Names}}' | grep -q "$CONTAINER_NAME"; then
    docker rm -f $CONTAINER_NAME
  fi
  docker run -d --name $CONTAINER_NAME \
    --restart always \
    -p 80:80 \
    -v /mnt/drupal-data/sites:/var/www/html/sites \
    -v /mnt/drupal-data/config:/var/www/html/config \
    -e DRUPAL_DB_HOST="$DB_HOST" \
    -e DRUPAL_DB_PORT="$DB_PORT" \
    -e DRUPAL_DB_NAME="$DB_NAME" \
    -e DRUPAL_DB_USER="$DB_USER" \
    -e DRUPAL_DB_PASS="$DB_PASS" \
    drupal:latest
  `;
  
      await lightsailClient.send(
        new CreateInstancesFromSnapshotCommand({
          instanceNames: [newInstanceName],
          availabilityZone: 'us-east-1a',
          instanceSnapshotName: snapshotName,
          bundleId: bundleId,
          keyPairName: keyPairName,
          userData: userDataScript,
        }),
      );
  
      let instanceStatus = '';
      while (instanceStatus !== 'running') {
        const instanceResponse = await lightsailClient.send(
          new GetInstanceCommand({
            instanceName: newInstanceName,
          }),
        );
        instanceStatus = instanceResponse.instance.state.name;
        if (instanceStatus !== 'running') {
          console.log(`Instance status: ${instanceStatus}. Waiting 5 seconds...`);
          await new Promise((resolve) => setTimeout(resolve, 5000));
        }
      }
  
      // Step 2.1: Wait for the disk to be attached
      console.log(`Waiting for block storage disk to be attached to ${newInstanceName}...`);
      let allAttachedDisks = [];
      let retries = 0;
      const maxRetries = 12; // Retry for up to 60 seconds
      while (retries < maxRetries) {
        const disksResponse = await lightsailClient.send(new GetDisksCommand({}));
        allAttachedDisks = disksResponse.disks?.filter(
          (disk) => disk.attachedTo === newInstanceName,
        ) || [];
  
        if (allAttachedDisks.length > 0) {
          console.log(`Found ${allAttachedDisks.length} disk(s) attached to ${newInstanceName}: ${JSON.stringify(allAttachedDisks.map(d => ({ name: d.name, attachedTo: d.attachedTo })))}`);
          break;
        }
  
        retries++;
        console.log(`No disks found attached to ${newInstanceName}. Retrying in 5 seconds... (Attempt ${retries}/${maxRetries})`);
        await new Promise((resolve) => setTimeout(resolve, 5000));
      }
  
      if (allAttachedDisks.length !== 1) {
        throw new Error(
          `Expected exactly 1 block storage disk attached to ${newInstanceName}, but found ${allAttachedDisks.length}: ${allAttachedDisks.map(d => d.name).join(', ')}. ` +
          `The snapshot may not have included a block storage disk, or there may be a configuration issue.`
        );
      }
  
      const finalDiskName = allAttachedDisks[0].name;
      console.log(`Green instance ${newInstanceName} is prepared and running with disk (${finalDiskName})!`);
  
      // Step 2.2: Detach Static IP from Old Instance and Attach to New Instance
      console.log(`Step 2.2: Detaching static IP ${staticIpName} from ${oldInstanceName} and attaching to ${newInstanceName}...`);
      try {
        await lightsailClient.send(
          new DetachStaticIpCommand({
            staticIpName: staticIpName,
          }),
        );
        console.log(`Detached static IP ${staticIpName} from ${oldInstanceName}.`);
      } catch (error) {
        if (error.name === 'NotFoundException') {
          console.warn(`Static IP ${staticIpName} not found or not attached to ${oldInstanceName}. Proceeding with attachment...`);
        } else {
          throw new Error(`Failed to detach static IP ${staticIpName}: ${error.message}`);
        }
      }
  
      await lightsailClient.send(
        new AttachStaticIpCommand({
          staticIpName: staticIpName,
          instanceName: newInstanceName,
        }),
      );
      console.log(`Attached static IP ${staticIpName} to ${newInstanceName}.`);
  
      // Step 3: Clean Up Blue Environment
      console.log(`Step 3: Cleaning up blue environment (${oldInstanceName})...`);
      await lightsailClient.send(
        new StopInstanceCommand({
          instanceName: oldInstanceName,
        }),
      );
      await this.waitForInstanceState(userId,oldInstanceName, 'stopped'); // Wait for stopped state

      let oldInstanceStatus = '';
      while (oldInstanceStatus !== 'stopped') {
        const oldInstanceResponse = await lightsailClient.send(
          new GetInstanceCommand({
            instanceName: oldInstanceName,
          }),
        );
        oldInstanceStatus = oldInstanceResponse.instance.state.name;
        if (oldInstanceStatus !== 'stopped') {
          console.log(`Blue instance status: ${oldInstanceStatus}. Waiting 5 seconds...`);
          await new Promise((resolve) => setTimeout(resolve, 5000));
        }
      }
  
      // Delete the old instance with forceDeleteAddOns
      await lightsailClient.send(
        new DeleteInstanceCommand({
          instanceName: oldInstanceName,
          forceDeleteAddOns: true,
        }),
      );
  
      await lightsailClient.send(
        new DeleteDiskCommand({
          diskName: oldDiskName,
        }),
      );
      console.log(`Blue environment cleaned up successfully!`);
  
      // Step 4: Update Secrets Manager with the new names
      const updatedSiteSecrets = {
        ...siteSecrets,
        instance_name: newInstanceName,
        disk_name: finalDiskName, // Use the actual disk name
      };
      await secretsManagerClient.send(
        new PutSecretValueCommand({
          SecretId: secretName,
          SecretString: JSON.stringify(updatedSiteSecrets),
        }),
      );
  
      // Step 5: Update Terraform State to Reflect New Names
      console.log(`Updating Terraform state with new instance, disk, and disk attachment names...`);
  
      // Initialize Terraform with the remote backend to ensure state is written to S3
      await execAsync(
        `terraform -chdir=${terraformDir} init -reconfigure -backend-config="bucket=terraform-state-user" -backend-config="key=sites/${userId}/${siteName}/terraform.tfstate" -backend-config="region=us-east-1" -backend-config="dynamodb_table=terraform-locks-user"`,
        { env }
      );
  
  
      // Remove old resources from state (instance, disk, and disk attachment)
      try {
        await execAsync(`terraform -chdir=${terraformDir} state rm aws_lightsail_instance.instance`, { env });
        await execAsync(`terraform -chdir=${terraformDir} state rm aws_lightsail_disk.disk`, { env });
        await execAsync(`terraform -chdir=${terraformDir} state rm aws_lightsail_disk_attachment.disk_attachment`, { env });
        console.log(`Removed old instance, disk, and disk attachment from Terraform state.`);
      } catch (error) {
        console.log(`No previous instance, disk, or disk attachment found in Terraform state. Proceeding with import...`);
      }
  
      // Import the new resources with variables
      const importVars = [
        `-var=user_id=${userId}`,
        `-var=site_name="${siteName}"`,
        `-var=account_id="${subAccountId}"`,
        `-var=aws_access_key_id="${accessKeyId}"`,
        `-var=aws_secret_access_key="${secretAccessKey}"`,
        `-var=aws_session_token="${sessionToken}"`,
        `-var=instance_name="${newInstanceName}"`,
        `-var=disk_name="${finalDiskName}"`,
        `-var="github_repo_url=${userRepoUrl}"`
      ].join(' ');
  
      // Import the new instance
      await execAsync(
        `terraform -chdir=${terraformDir} import ${importVars} aws_lightsail_instance.instance ${newInstanceName}`,
        { env }
      );
      console.log(`Imported new aws_lightsail_instance.instance`);
  
      // Import the new disk
      await execAsync(
        `terraform -chdir=${terraformDir} import ${importVars} aws_lightsail_disk.disk ${finalDiskName}`,
        { env }
      );
      console.log(`Imported new aws_lightsail_disk.disk`);
  
      // Import the new disk attachment
      await execAsync(
        `terraform -chdir=${terraformDir} import ${importVars} aws_lightsail_disk_attachment.disk_attachment ${finalDiskName},${newInstanceName}`,
        { env }
      );
      console.log(`Imported new aws_lightsail_disk_attachment.disk_attachment`);
  
      // Verify the state file in S3 contains all expected resources
      console.log(`Verifying Terraform state file in S3...`);
      try {
        const { stdout: s3LsStdout, stderr: s3LsStderr } = await execAsync(
          `aws s3 ls s3://terraform-state-user/sites/${userId}/${siteName}/terraform.tfstate --region us-east-1`,
          { env }
        );
        console.log(`AWS S3 ls stdout: ${s3LsStdout}`);
        if (s3LsStderr) console.warn(`AWS S3 ls stderr: ${s3LsStderr}`);
  
        // Check that the state file includes all expected resources
        const { stdout: stateList, stderr: stateListStderr } = await execAsync(
          `terraform -chdir=${terraformDir} state list`,
          { env }
        );
        console.log(`Terraform state list stdout: ${stateList}`);
        if (stateListStderr) console.warn(`Terraform state list stderr: ${stateListStderr}`);
  
        const expectedResources = [
          'aws_lightsail_instance.instance',
          'aws_lightsail_disk.disk',
          'aws_lightsail_disk_attachment.disk_attachment',
        ];
        const missingResources = expectedResources.filter(resource => !stateList.includes(resource));
        if (missingResources.length > 0) {
          throw new Error(`Terraform state is missing resources: ${missingResources.join(', ')}. Ensure all resources were imported correctly.`);
        }
      } catch (error) {
        throw new Error(`Failed to verify Terraform state file in S3: ${error.message}`);
      }
  
      console.log(`Terraform state updated with new instance (${newInstanceName}), disk (${finalDiskName}), and disk attachment.`);
  
      // Step 6: Clean Up Snapshots
      console.log(`Cleaning up snapshots created during deployment...`);
  
      // Clean up disk snapshots
      const diskSnapshotsResponse = await lightsailClient.send(new GetDiskSnapshotsCommand({}));
      const diskSnapshotsToDelete = diskSnapshotsResponse.diskSnapshots?.filter(
        (snapshot) => snapshot.name?.includes(siteName)
      ) || [];
  
      for (const snapshot of diskSnapshotsToDelete) {
        const snapshotName = snapshot.name;
        console.log(`Found disk snapshot ${snapshotName}. Deleting...`);
        await lightsailClient.send(
          new DeleteDiskSnapshotCommand({
            diskSnapshotName: snapshotName,
          }),
        );
        console.log(`Deleted disk snapshot ${snapshotName}.`);
      }
  
      // Clean up instance snapshots
      const instanceSnapshotsResponse = await lightsailClient.send(new GetInstanceSnapshotsCommand({}));
      const instanceSnapshotsToDelete = instanceSnapshotsResponse.instanceSnapshots?.filter(
        (snapshot) => snapshot.name?.includes(siteName)
      ) || [];
  
      for (const snapshot of instanceSnapshotsToDelete) {
        const snapshotName = snapshot.name;
        console.log(`Found instance snapshot ${snapshotName}. Deleting...`);
        await lightsailClient.send(
          new DeleteInstanceSnapshotCommand({
            instanceSnapshotName: snapshotName,
          }),
        );
        console.log(`Deleted instance snapshot ${snapshotName}.`);
      }


    const deployment = await this.deploymentRepository.findOne({ where: { siteName } });
    console.log('i am a deployment from upgrade function',deployment)
    // Save changes and verify
    
  try {
    // Use direct update instead of save()
    await this.deploymentRepository.update(
    { siteName }, 
   { 
      bundleId,        // Nouveau bundle ID
      instanceName: newInstanceName  // Nouveau nom d'instance
    } // Explicit update object
  );

  // Verify update
  const verifiedDeployment = await this.deploymentRepository.findOne({ where: { siteName } });
  console.log('Deployment from DB after update:', verifiedDeployment);
  
  if (verifiedDeployment.bundleId !== bundleId) {
    throw new Error(`Failed to save bundleId: expected ${bundleId}, got ${verifiedDeployment.bundleId}`);
  }
} catch (error) {
  // Error handling remains same
    console.error('Error saving deployment:', error);
      throw new HttpException(
        `Failed to save deployment: ${error.message}`,
        HttpStatus.INTERNAL_SERVER_ERROR
      );
}

   /* if (!deployment) {
      throw new HttpException(`Deployment with siteName ${siteName} not found`, HttpStatus.NOT_FOUND);
    }

      deployment.bundleId = bundleId
      
      deployment.updatedAt = new Date();
      await this.deploymentRepository.save(deployment);*/
      return {
        newInstance: newInstanceName,
        message: `✅ Instance upgraded successfully with blue-green deployment! Final instance: ${newInstanceName}, disk: ${finalDiskName}, static IP: ${staticIpName}.`,
      };
    } catch (error) {
      if (error.name === 'ResourceNotFoundException') {
        throw new Error(`Instance not found in sub-account for user ${userId}.`);
      }
      console.error('Error upgrading instance:', error);
      throw new Error(`Failed to upgrade instance: ${error.message}`);
    } finally {
      lightsailClient.destroy();
      secretsManagerClient.destroy();
    }
  }





  async deployInfrastructure(
    userId: number,
    siteName: string,
    githubRepoUrl: string,
    terraformDir: string ,// New input parameter,
    key : string ,
    region : string
  ): Promise<{
    instancePublicIp: string;
    databaseEndpoint: string;
    databasePort: number;
    databaseName: string;
    databaseUsername: string;
    databasePassword: string;
    dnsRecord: string;
    wwwDnsRecord: string | null;
    instanceName: string;
    sshkey: string;
    codebuildProjectArn: string;
    token : string 
  }> {
    const tempProfile = `temp-subaccount-${userId}-${siteName}`;
    const workspaceName = `user-${userId}-${siteName}`;
    const env = { ...process.env, AWS_PROFILE: tempProfile };
  
    try {
      logger.info(`🚀 Starting deployment for user ${userId}, site "${siteName}"`);
  
      // 1. Get temporary credentials from user service
     /* const { data } = await firstValueFrom(
        this.httpService.post<AwsCredentialsResponse>(
          `http://localhost:3030/user/${userId}/connect-aws`, {},
        ),
      );
  
      const { accessKeyId, secretAccessKey, sessionToken } = data;
      */
      // 1. Get temporary credentials from user service
        const data = await this.fetchTempCredentials(userId);

         const { accessKeyId, secretAccessKey, sessionToken } = data;

      logger.info(`🪪 AWS creds loaded for ${userId}`);

     const env = {
  ...process.env,
  AWS_ACCESS_KEY_ID: accessKeyId,
  AWS_SECRET_ACCESS_KEY: secretAccessKey,
  AWS_SESSION_TOKEN: sessionToken,
}; 
  
      // 2. Get AWS account ID
      const sts = new AWS.STS({ accessKeyId, secretAccessKey, sessionToken });
      const identity = await sts.getCallerIdentity().promise();
      const accountId = identity.Account;


      logger.info(`✅ Verified sub-account ID: ${accountId}`);
  
  
      // 3. Configure AWS CLI profile (sync OK here)
      execSync(`aws configure set aws_access_key_id ${accessKeyId} --profile ${tempProfile}`);
      execSync(`aws configure set aws_secret_access_key ${secretAccessKey} --profile ${tempProfile}`);
      execSync(`aws configure set aws_session_token ${sessionToken} --profile ${tempProfile}`);
  
      // 4. Run terraform init
      await runTerraformCommand([
        'init  -upgrade',
        `-backend-config=bucket=terraform-state-user`,
        `-backend-config=key=${key}`,
        `-backend-config=region=${region}`,
        `-backend-config=dynamodb_table=terraform-locks-user`,
        '-reconfigure'
      ], terraformDir, env);
  
      // 5. Create/select workspace
     /* try {
        await runTerraformCommand(['workspace', 'select', workspaceName], terraformDir, env);
      } catch {
        await runTerraformCommand(['workspace', 'new', workspaceName], terraformDir, env);
      }
*/
      console.log ("ena repo",githubRepoUrl)

  
      // 6. Terraform plan
      await runTerraformCommand([
        'plan',
        '-out=plan',
        `-var=user_id=${userId}`,
        `-var=site_name=${siteName}`,
        `-var=account_id=${accountId}`,
        `-var=aws_access_key_id=${accessKeyId}`,
        `-var=aws_secret_access_key=${secretAccessKey}`,
        `-var=aws_session_token=${sessionToken}`,
        `-var=github_repo_url=${githubRepoUrl}`,
       // `-var=docker_image=${dockerImage}`,
      ], terraformDir, env);

      // Avant l'apply, ajoutez :
await runTerraformCommand(['validate'], terraformDir, env);
  
      // 7. Terraform apply
     await runTerraformCommand([
        'apply',
        '-auto-approve',
        `-var=user_id=${userId}`,
        `-var=site_name=${siteName}`,
        `-var=account_id=${accountId}`,
        `-var=aws_access_key_id=${accessKeyId}`,
        `-var=aws_secret_access_key=${secretAccessKey}`,
        `-var=aws_session_token=${sessionToken}`,
        `-var=github_repo_url=${githubRepoUrl}`
      ], terraformDir, env);
      
  
      // 8. Terraform output (sync ok)
      const outputJson = execSync(`terraform output -json`, { cwd: terraformDir, env }).toString();
      const outputs = JSON.parse(outputJson);

      console.log('Terraform Outputs:', JSON.stringify(outputs, null, 2));
  
      // 9. Clean up AWS profile
      const awsCredentialsPath = path.join(os.homedir(), '.aws', 'credentials');

if (fs.existsSync(awsCredentialsPath)) {
  let credentialsContent = fs.readFileSync(awsCredentialsPath, 'utf-8');

  // Supprimer uniquement le bloc du profil temporaire
  const regex = new RegExp(`\\[${tempProfile}\\][\\s\\S]*?(?=\\[|$)`, 'g');
  const updatedContent = credentialsContent.replace(regex, '').trim();

  fs.writeFileSync(awsCredentialsPath, updatedContent);
  logger.info(`✅ Removed AWS CLI profile: ${tempProfile}`);
}
    
  
      logger.info(`✅ Deployment completed for user ${userId}, site "${siteName}"`);

    

  
      return {
        instancePublicIp: outputs.instance_public_ip.value,
        databaseEndpoint: outputs.database_endpoint.value,
        databasePort: outputs.database_port.value,
        databaseName: outputs.database_name.value,
        databaseUsername: outputs.database_username.value,
        databasePassword: outputs.database_password.value,
        dnsRecord: outputs.dns_record.value,
        wwwDnsRecord: outputs.www_dns_record.value,
        instanceName: outputs.instance_name.value,
        sshkey: outputs.ssh.value,
        codebuildProjectArn: outputs.codebuild_project_arn.value,
        token : outputs.token_github.value
      };
  
    } catch (err) {
      logger.error(`❌ Deployment failed for ${userId}/${siteName}: ${err.message}`);
      throw new Error(`Terraform failed: ${err.message}`);
    }
  }


  /////////////////////////////////GITHUB FUNCTIONS//////////////////


async saveGitHubPat(userId: number, pat: string): Promise<void> {



  const logger = new Logger('TokenService');
  console.log("hello from the function 0",userId,pat)
  const secretConfigs = [
    { id: `sites/${userId}/github-pat`, region: 'us-east-1' },
    { id: `sites/${userId}/PAT`, region: 'us-east-2' }
  ];

  try {
    // 1. Obtenir les credentials AWS
     // 1. Get temporary credentials from user service
        const data = await this.fetchTempCredentials(userId);

         const { accessKeyId, secretAccessKey, sessionToken } = data;
   
    // 2. Parcourir chaque configuration secrète
    for (const { id, region } of secretConfigs) {
      const client = new SecretsManagerClient({
        region,
        credentials: {
          accessKeyId: data.accessKeyId,
          secretAccessKey: data.secretAccessKey,
          sessionToken: data.sessionToken
        }
      });

      try {
        // 3. Essayer de mettre à jour le secret
        await client.send(new UpdateSecretCommand({
          SecretId: id,
          SecretString: pat // Stockage en texte brut
        }));
        logger.log(`[SUCCESS] Secret ${id} updated in ${region}`);
        
      } catch (updateError) {
        if (updateError.name === 'ResourceNotFoundException') {
          // 4. Créer le secret s'il n'existe pas
          await client.send(new CreateSecretCommand({
            Name: id,
            SecretString: pat,
            Description: `GitHub PAT for ${userId}`
          }));
          logger.log(`[SUCCESS] Secret ${id} created in ${region}`);
        } else {
          throw new Error(`[${region}] ${id}: ${updateError.message}`);
        }
      } finally {
        client.destroy();
      }
    }

  } catch (error) {
    logger.error(`[CRITICAL] Save failed: ${error.message}`);
    throw new Error(`Save failed: ${error.message}`);
  }
}



async fetchGitHubPat(userId: number): Promise<string> {
  const logger = new Logger('MediumService');
  console.log("helo from deployment")
  const secretId = `sites/${userId}/github-pat`;
  let client: SecretsManagerClient;

  try {
    // Get AWS credentials
  // 1. Get temporary credentials from user service
        const data = await this.fetchTempCredentials(userId);

         const { accessKeyId, secretAccessKey, sessionToken } = data;

    // Create Secrets Manager client
    client = new SecretsManagerClient({
      region: 'us-east-1',
      credentials: data
    });

    // Retrieve secret
    const { SecretString } = await client.send(
      new GetSecretValueCommand({ SecretId: secretId })
    );

    // Validate response
    if (!SecretString?.trim()) {
      throw new Error(`Empty PAT found at ${secretId}`);
    }

    // Validate PAT format directly
    if (!SecretString.match(/^ghp_[a-zA-Z0-9]{36}$/)) {
      throw new Error(`Invalid PAT format in secret ${secretId}`);
    }

    logger.log(`Successfully retrieved plaintext PAT from ${secretId}`);
    console.log(SecretString)
    return SecretString; // Direct return of plaintext

  } catch (error) {
    logger.error(`PAT retrieval failed: ${error.stack}`);
    throw new Error(`Failed to retrieve PAT: ${error.message}`);
  } finally {
    client?.destroy();
  }
}


//faut traiter le cas ou c la première fois on met un pat !

/*async getPatStatus(userId: number): Promise<{ 
  exists: boolean; 
  valid?: boolean;
  expiry?: string;
  isValid: boolean;
    isFirstTime?: boolean; // Nouveau flag

}> {
  const secretId = `sites/${userId}/github-pat`;
  let client: SecretsManagerClient;

  try {
    // 1. Get AWS credentials
    const { data } = await firstValueFrom(
      this.httpService.post<AwsCredentialsResponse>(`http://localhost:3030/user/${userId}/connect-aws`, {}),
    );

    // 2. Initialize Secrets Manager client
    client = new SecretsManagerClient({ 
      region: 'us-east-1',
      credentials: {
        accessKeyId: data.accessKeyId,
        secretAccessKey: data.secretAccessKey,
        sessionToken: data.sessionToken
      }
    });

    // 3. Check secret existence
    const secret = await client.send(new GetSecretValueCommand({ SecretId: secretId }));
    const pat = secret.SecretString;

    // 4. Validate with GitHub API
    const response = await firstValueFrom(
      this.httpService.get('https://api.github.com/user', {
        headers: { Authorization: `token ${pat}` },
      }),
    );

    // 5. Extract and verify expiration
    const expiryHeader = response.headers['github-authentication-token-expiration'];
    const expiryDate = new Date(expiryHeader.replace(' UTC', '') + 'Z');
    const currentDate = new Date();
    const isExpired = expiryDate <= currentDate;

    // 6. Final validity check
    const isValid = !isExpired && response.status === 200;

    return {
      exists: true,
      valid: true,
      expiry: expiryDate.toISOString(),
      isValid
    };

  } catch (error) {
    if (error.name === 'ResourceNotFoundException') {
      return { exists: false, isValid: false };
    }
    
    // Handle API validation failures
    if (error.response?.status === 401) {
      return {
        exists: true,
        valid: false,
        expiry: undefined,
        isValid: false
      };
    }

    return {
      exists: true,
      valid: false,
      expiry: undefined,
      isValid: false
    };
  } finally {
    client?.destroy();
  }
}*/

async getPatStatus(userId: number): Promise<{ 
  exists: boolean; 
  valid?: boolean;
  expiry?: string;
  isValid: boolean;
  isFirstTime?: boolean;
}> {
  const secretId = `sites/${userId}/github-pat`;
  let client: SecretsManagerClient;

  try {
    // 1. Get AWS credentials
  // 1. Get temporary credentials from user service
        const data = await this.fetchTempCredentials(userId);

         const { accessKeyId, secretAccessKey, sessionToken } = data;

    // 2. Initialize Secrets Manager client
    client = new SecretsManagerClient({ 
      region: 'us-east-1',
      credentials: {
        accessKeyId: data.accessKeyId,
        secretAccessKey: data.secretAccessKey,
        sessionToken: data.sessionToken
      }
    });

    try {
      // 3. Check secret existence
      const secret = await client.send(new GetSecretValueCommand({ SecretId: secretId }));
      const pat = secret.SecretString;

      console.log("pat",pat)

      // 4. Validate with GitHub API
      const response = await firstValueFrom(
        this.httpService.get('https://api.github.com/user', {
          headers: { Authorization: `token ${pat}` },
        }),
      );


      // 5. Extract and verify expiration
      const expiryHeader = response.headers['github-authentication-token-expiration'];
      const expiryDate = new Date(expiryHeader.replace(' UTC', '') + 'Z');
      const currentDate = new Date();
      const isExpired = expiryDate <= currentDate;

      // 6. Final validity check
      const isValid = !isExpired && response.status === 200;

      return {
        exists: true,
        valid: true,
        expiry: expiryDate.toISOString(),
        isValid,
        isFirstTime: false
      };

    } catch (awsError) {
      // Gestion spécifique de la première configuration
      if (awsError.name === 'ResourceNotFoundException') {
        return { 
          exists: false, 
          isValid: false,
          isFirstTime: true
        };
      }
      
      // Gestion des erreurs de validation GitHub
      if (awsError.response?.status === 401) {
        return {
          exists: true,
          valid: false,
          expiry: undefined,
          isValid: false,
          isFirstTime: false
        };
      }

      throw awsError;
    }

  } catch (error) {
    // Gestion générique des erreurs
    return {
      exists: false,
      isValid: false,
      isFirstTime: false
    };
  } finally {
    client?.destroy();
  }
}

async getPatStatuss(userId: number,pat:string): Promise<{ 
  exists: boolean; 
  valid?: boolean;
  expiry?: string;
  isValid: boolean;
}> {

  try {
    // 1. Get AWS credentials
   // 1. Get temporary credentials from user service
        const data = await this.fetchTempCredentials(userId);

         const { accessKeyId, secretAccessKey, sessionToken } = data;

  
    console.log("pat",pat)

    // 4. Validate with GitHub API
    const response = await firstValueFrom(
      this.httpService.get('https://api.github.com/user', {
        headers: { Authorization: `token ${pat}` },
      }),
    );

    // 5. Extract and verify expiration
    const expiryHeader = response.headers['github-authentication-token-expiration'];
    const expiryDate = new Date(expiryHeader.replace(' UTC', '') + 'Z');
    const currentDate = new Date();
    const isExpired = expiryDate <= currentDate;

    // 6. Final validity check
    const isValid = !isExpired && response.status === 200;

    return {
      exists: true,
      valid: true,
      expiry: expiryDate.toISOString(),
      isValid
    };

  } catch (error) {
    if (error.name === 'ResourceNotFoundException') {
      return { exists: false, isValid: false };
    }
    
    // Handle API validation failures
    if (error.response?.status === 401) {
      return {
        exists: true,
        valid: false,
        expiry: undefined,
        isValid: false
      };
    }

    return {
      exists: true,
      valid: false,
      expiry: undefined,
      isValid: false
    };
  } finally {
 
  }
}



async isSiteNameUnique(siteName: string): Promise<{ available: boolean }> {
     const normalized = String(siteName).toLowerCase()
    const exists = await this.deploymentRepository.exist({
      where: { siteName: normalized }
    });

    console.log("exists",exists)
    
    return { available: !exists };
  }



async getLightsailMetrics(
    deploymentId: number,
    userId: number,
    instanceName: string,

    period: '7d' | '30d' | '90d' = '30d',
  ): Promise<SiteStats> {
    console.log(`Fetching metrics for deploymentId: ${deploymentId}, userId: ${userId}, instanceName: ${instanceName}, period: ${period}`);

    try {
      // Validation initiale
      if (!instanceName) {
        console.error('Instance name is empty or undefined');
        throw new NotFoundException('Instance name is required');
      }

   // 1. Get temporary credentials from user service
        const data = await this.fetchTempCredentials(userId);

         const { accessKeyId, secretAccessKey, sessionToken } = data;
      const credentials = data;

      const region = "us-east-1";
      console.debug(`Using AWS region: ${region}`);

      // Initialize AWS clients
      const lightsailClient = new LightsailClient({
        region,
        credentials: {
          accessKeyId: credentials.accessKeyId,
          secretAccessKey: credentials.secretAccessKey,
          sessionToken: credentials.sessionToken,
        },
      });

      const endTime = new Date();
      let startTime: Date;
      switch (period) {
        case '7d':
          startTime = new Date(endTime.getTime() - 7 * 24 * 3600 * 1000);
          break;
        case '30d':
          startTime = new Date(endTime.getTime() - 30 * 24 * 3600 * 1000);
          break;
        case '90d':
          startTime = new Date(endTime.getTime() - 90 * 24 * 3600 * 1000);
          break;
        default:
          startTime = new Date(endTime.getTime() - 30 * 24 * 3600 * 1000);
      }

      // Fetch metrics
// Corriger la liste des métriques
const metrics = [
  InstanceMetricName.CPUUtilization, 
  InstanceMetricName.BurstCapacityPercentage,
  InstanceMetricName.NetworkIn,
  InstanceMetricName.NetworkOut
];      const metricDataPromises = metrics.map((metricName) =>
        lightsailClient.send(
          new GetInstanceMetricDataCommand({
            instanceName,
            metricName,
            period: 86400, // 1 jour
            startTime,
            endTime,
            unit: metricName.includes('Utilization') ? 'Percent' : 'Bytes',
            statistics: ['Average'],
          }),
        ),
      );

      const [cpuData, burstCapacityData, networkInData, networkOutData] = await Promise.all(metricDataPromises);

      const formatDataPoints = (data: any): MetricDataPoint[] =>
        data.metricData?.map((point: any) => ({
          timestamp: point.timestamp.toISOString(),
          average: point.average || 0,
        })) || [];

      // Fetch uptime
      const instanceCommand = new GetInstanceCommand({ instanceName });
      const instanceData = await lightsailClient.send(instanceCommand);
      if (!instanceData.instance) {
        console.error(`Instance ${instanceName} not found`);
        throw new NotFoundException(`Instance ${instanceName} not found`);
      }
      const createdOn = new Date(instanceData.instance.createdAt);
      const uptimeSeconds = Math.floor((endTime.getTime() - createdOn.getTime()) / 1000);

      console.log(`Metrics retrieved for ${instanceName}`);

      return {
        cpuUsage: formatDataPoints(cpuData),
        memoryUsage: formatDataPoints(burstCapacityData),
        networkIn: formatDataPoints(networkInData),
        networkOut: formatDataPoints(networkOutData),
        uptimeSeconds,
      };
    } catch (error) {
      console.error(`Error fetching metrics for deploymentId: ${deploymentId}: ${error.message}`);
      throw error instanceof NotFoundException
        ? error
        : new NotFoundException(`Failed to fetch metrics: ${error.message}`);
    }
  }





/////////////////////////////////////////////////////////////////////////////////////////////
  
























 async prepareremotebackend(userId: number ){
  //connect as the user sub account 
  //call the api connect aws
  //execute the backend ! 

  // Step 1: Get temporary credentials from user-service
 // 1. Get temporary credentials from user service
        const data = await this.fetchTempCredentials(userId);

         const { accessKeyId, secretAccessKey, sessionToken } = data;
  const env = {
  ...process.env,
  AWS_ACCESS_KEY_ID:accessKeyId,
  AWS_SECRET_ACCESS_KEY: secretAccessKey,
  AWS_SESSION_TOKEN: sessionToken,
};
  logger.info(`Temporary Credentials: aws_access_key_id=${accessKeyId}, aws_secret_access_key=${secretAccessKey}, aws_session_token=${sessionToken}`);


  // Step 2: Use the temporary credentials to get the account ID
  const sts = new AWS.STS({
    accessKeyId: accessKeyId,
    secretAccessKey: secretAccessKey,
    sessionToken: sessionToken,
  });

  const identity = await sts.getCallerIdentity().promise();
  const awsRegion = "us-east-1";
  const accountId = identity.Account;
  logger.info(`Deploying to sub-account with Account ID: ${accountId}, Arn: ${identity.Arn}`);

  // Step 3: Create a temporary AWS CLI profile for the sub-account credentials
  const tempProfile = `temp-subaccount-${userId}`; // Unique profile name to avoid conflicts
  execSync(`aws configure set aws_access_key_id ${accessKeyId} --profile ${tempProfile}`, { stdio: 'inherit' });
  execSync(`aws configure set aws_secret_access_key ${secretAccessKey} --profile ${tempProfile}`, { stdio: 'inherit' });
  execSync(`aws configure set aws_session_token ${sessionToken} --profile ${tempProfile}`, { stdio: 'inherit' });
  logger.info(`Created temporary AWS CLI profile: ${tempProfile}`);

 const terraformDir = path.resolve('terraform', 'backend');
  
 
 //process.chdir(terraformDir);
  logger.info(`Changed working directory to ${terraformDir}`);
  //const env = { ...process.env, AWS_PROFILE: tempProfile };




  // Run terraform init with S3 backend configuration
// const initCommand = `terraform init -backend-config="bucket=terraform-state-user-id" -backend-config="key=user-${userId}/workspace/site-${siteId}/terraform.tfstate" -backend-config="region=us-east-1" -backend-config="dynamodb_table=terraform-locks"`;
// execSync(initCommand, { stdio: 'inherit', env: { ...process.env, AWS_PROFILE: tempProfile } });
  // Run terraform init
  //execSync(`terraform init `, { cwd: terraformDir,stdio: 'inherit', env: { ...process.env, AWS_PROFILE: tempProfile } });
  try {
    execSync(
      `terraform init -reconfigure`,
      { cwd: terraformDir, stdio: 'inherit', env }
    );
    logger.info('Terraform init completed successfully');
  } catch (error) {
    logger.error('Terraform init failed:', error.message);
    throw error;
  }
    
  //const env = { ...process.env, AWS_PROFILE: tempProfile };
  // Run terraform plan
  const planCommand = `terraform plan -out=plan  -var="account_id=${accountId}" -var="aws_access_key_id=${accessKeyId}" -var="aws_secret_access_key=${secretAccessKey}" -var="aws_session_token=${sessionToken}" -var="user_id=${userId}"`;
  execSync(planCommand, { cwd: terraformDir ,stdio: 'inherit', env: { ...process.env, AWS_PROFILE: tempProfile } });

  // Run terraform apply
  const applyCommand = `terraform apply -auto-approve  -var="account_id=${accountId}" -var="account_id=${accountId}" -var="aws_access_key_id=${accessKeyId}" -var="aws_secret_access_key=${secretAccessKey}" -var="aws_session_token=${sessionToken}" -var="user_id=${userId}"`;
  execSync(applyCommand, { cwd: terraformDir ,stdio: 'inherit', env: { ...process.env, AWS_PROFILE: tempProfile } });



  // Step 5: Clean up the temporary profile

  const awsCredentialsPath = path.join(os.homedir(), '.aws', 'credentials');

if (fs.existsSync(awsCredentialsPath)) {
  let credentialsContent = fs.readFileSync(awsCredentialsPath, 'utf-8');

  // Supprimer uniquement le bloc du profil temporaire
  const regex = new RegExp(`\\[${tempProfile}\\][\\s\\S]*?(?=\\[|$)`, 'g');
  const updatedContent = credentialsContent.replace(regex, '').trim();

  fs.writeFileSync(awsCredentialsPath, updatedContent);
  logger.info(`✅ Removed AWS CLI profile: ${tempProfile}`);
}
      
  // Step 5: Fetch Terraform outputs
  const outputJson = execSync(`terraform output -json`, { cwd: terraformDir, env }).toString();
  const outputs = JSON.parse(outputJson);

  // Step 6: Return the S3 bucket name
  return {
   
  };
} catch (error) {
  logger.error(`Failed to deploy infrastructure for user_id , site_name : ${error.message}`);
  throw new Error(`Failed to deploy infrastructure: ${error.message}`);
}
}













/*private createPayload(deploymentId: number) {
  return {
    event_type: "deploy-stack",
    client_payload: {
      deployment_id: deploymentId,
      instance_ip: "44.198.78.218",
      db_host: "ls-989542c765b2e0d65112a0ba5f0cc4eb90cc6003.c43wcgu6gelw.us-east-1.rds.amazonaws.com",
      db_port: 3306,
      db_name: "db-19-my-drupal-site",
      db_user: "user",
      db_password: "s0a-QUifJ8JK6tux"
    }
  };
}

private buildCommand(token: string) {
  return [
    'curl.exe -X POST',
    '-H "Accept: application/vnd.github+json"',
    '-H "Content-Type: application/json"',
    `-H "Authorization: Bearer ${token}"`,
    '-H "X-GitHub-Api-Version: 2022-11-28"',
    'https://api.github.com/repos/NarjesTaghlet/drupal-site-Test/dispatches',
    `--data "@${this.payloadFile}"`
  ].join(' ');
}

async triggerDeployment(deploymentId = 10): Promise<void> {
  const token = process.env.testtoken;
  console.log(token)
  if (!token) {
    throw new Error('TEST_TOKEN not configured');
  }

  const payload = this.createPayload(deploymentId);

  try {
    writeFileSync(this.payloadFile, JSON.stringify(payload), { encoding: 'utf-8' });
    execSync(this.buildCommand(token), { 
      shell: 'cmd.exe',
      stdio: 'inherit',
      windowsHide: true
    });
  } finally {
    if (existsSync(this.payloadFile)) {
      unlinkSync(this.payloadFile);
    }
  }
}

*/





export function runTerraformCommand(args: string[], cwd: string, env: any): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn('terraform', args, { cwd, env, shell: true });

    child.stdout.on('data', (data) => process.stdout.write(`[TF] ${data}`));
    child.stderr.on('data', (data) => process.stderr.write(`[TF ERROR] ${data}`));

    child.on('exit', (code) => {
      if (code === 0) return resolve();
      reject(new Error(`Terraform exited with code ${code}`));
    });
  });
}

/*import { createWriteStream } from 'fs';
import chalk from 'chalk';
import { readFile } from 'fs/promises';

export function runTerraformCommand(args: string[], cwd: string, env: any): Promise<void> {
  return new Promise((resolve, reject) => {
    // Ensure Terraform logging is enabled
    env.TF_LOG = env.TF_LOG || 'DEBUG';
    env.TF_LOG_PATH = env.TF_LOG_PATH || join(cwd, 'terraform.log');

    console.log(`[TF] Running command: terraform ${args.join(' ')}`);

    const child = spawn('terraform', args, { cwd, env, shell: true });

    child.stdout.on('data', (data) => process.stdout.write(`[TF] ${data}`));
    child.stderr.on('data', (data) => process.stderr.write(`[TF ERROR] ${data}`));

    child.on('exit', async (code) => {
      let logContent = '';
      try {
        logContent = await readFile(env.TF_LOG_PATH, 'utf-8');
        console.log(`[TF] Log content:\n${logContent}`);
      } catch (logError) {
        console.error(`[TF] Failed to read log file: ${logError}`);
      }

      if (code === 0) {
        resolve();
      } else {
        reject(new Error(`Terraform exited with code ${code}\nLog:\n${logContent}`));
      }
    });
  });
}
  */