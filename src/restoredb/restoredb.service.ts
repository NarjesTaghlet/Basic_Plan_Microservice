import { Injectable } from '@nestjs/common';
import { RDSClient,CreateDBSnapshotCommand } from '@aws-sdk/client-rds';
import { GetRelationalDatabaseSnapshotsCommand } from '@aws-sdk/client-lightsail';
import { type UpdateRelationalDatabaseCommandInput } from "@aws-sdk/client-lightsail";
import { randomBytes } from 'crypto';
import {
  CodeBuildClient,
  StartBuildCommand,
} from "@aws-sdk/client-codebuild";

import {
  RDS,
  RestoreDBInstanceToPointInTimeCommand,
  RestoreDBInstanceFromDBSnapshotCommand,
  DescribeDBInstancesCommand,
  DescribeDBSnapshotsCommand,
  DeleteDBInstanceCommand,
  ModifyDBInstanceCommand
} from '@aws-sdk/client-rds';
import { HttpService } from '@nestjs/axios';
import { AxiosResponse , AxiosError} from 'axios';
import { AwsCredentialsResponse } from 'src/deployment/interfaces/aws-credentials.interface';
import { STSClient, AssumeRoleCommand } from '@aws-sdk/client-sts';
import {  PutSecretValueCommand,CreateSecretCommand} from '@aws-sdk/client-secrets-manager';
import { firstValueFrom } from 'rxjs';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Deployment } from 'src/deployment/entities/deployment.entity';
import {  Logger , BadRequestException } from '@nestjs/common';
import { LightsailClient, CreateRelationalDatabaseSnapshotCommand, GetRelationalDatabaseSnapshotCommand, CreateRelationalDatabaseFromSnapshotCommand,UpdateRelationalDatabaseCommand, DeleteRelationalDatabaseCommand, GetRelationalDatabaseCommand } from '@aws-sdk/client-lightsail';
import { SecretsManagerClient, GetSecretValueCommand, UpdateSecretCommand } from '@aws-sdk/client-secrets-manager';
import * as dotenv from 'dotenv' ;
dotenv.config();

interface RenameDatabaseParams {
  relationalDatabaseName: string;
  newRelationalDatabaseName: string;
}


@Injectable()
export class RestoredbService {
     constructor(
          @InjectRepository(Deployment)
           private deploymentRepository: Repository<Deployment>,
          
            private httpService: HttpService,
            
        ){
    
        }
    async fetchTempCredentials(userId: number) {
  try {
    // Utilise une variable d'environnement pour l'URL du user-service
    const userServiceUrl = process.env.USER_SERVICE_URL || 'http://localhost:3030';
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
/*async createManualSnapshotAndRestore(
  siteName: string,
  userId: number,
  dbInstanceIdentifier: string,
  targetDbInstanceIdentifier: string
): Promise<any> {
  let lightsail: LightsailClient;
  let secretsManager: SecretsManagerClient;

  try {
    // Get AWS credentials
    const { data } = await firstValueFrom(
      this.httpService.post<AwsCredentialsResponse>(
        `http://localhost:3030/user/${userId}/connect-aws`, 
        {}
      ),
    );

    // Initialize AWS clients
    const config = {
      region: 'us-east-1',
      credentials: {
        accessKeyId: data.accessKeyId,
        secretAccessKey: data.secretAccessKey,
        sessionToken: data.sessionToken,
      },
    };
    
    lightsail = new LightsailClient(config);
    secretsManager = new SecretsManagerClient(config);

    // 1. Create a manual snapshot
    const snapshotName = `manual-${dbInstanceIdentifier}-${Date.now()}`;
    const createSnapshotCommand = new CreateRelationalDatabaseSnapshotCommand({
      relationalDatabaseName: dbInstanceIdentifier,
      relationalDatabaseSnapshotName: snapshotName
    });
    
    await lightsail.send(createSnapshotCommand);
    console.log(`Manual snapshot created: ${snapshotName}`);
    
    // 2. Wait for snapshot to be available
    await this.waitForLightsailSnapshotAvailable(lightsail, snapshotName);

    // 3. Restore from snapshot
    return await this.restoreLightsailDbFromSnapshot(
      siteName,
      userId,
      dbInstanceIdentifier,
      snapshotName,
      targetDbInstanceIdentifier
    );
  } catch (error: any) {
    console.error(`Error creating manual snapshot and restoring:`, error);




    await this.triggerCodeBuildPipelineWithConnectAws(siteName,userId)
    
    // Handle specific Lightsail errors
    if (error.name === 'InvalidInputException') {
      throw new Error(`Invalid database name: ${dbInstanceIdentifier}. Check database exists in Lightsail.`);
    }
    if (error.name === 'NotFoundException') {
      throw new Error(`Database not found in Lightsail: ${dbInstanceIdentifier}`);
    }
    
    throw new Error(error.message || 'Failed to create manual snapshot and restore');
  } finally {
    lightsail?.destroy();
    secretsManager?.destroy();
  }
}
  */

async createManualSnapshotAndRestore(
  siteName: string,
  userId: number,
 // targetDbInstanceIdentifier: string
): Promise<any> {
  let lightsail: LightsailClient;
  let secretsManager: SecretsManagerClient;

  try {
    // 1. Get AWS credentials
    // 1. Get temporary credentials from user service
        const data = await this.fetchTempCredentials(userId);

         const { accessKeyId, secretAccessKey, sessionToken } = data;

    // 2. Initialize AWS clients
    const config = {
      region: 'us-east-1',
      credentials: {
        accessKeyId: data.accessKeyId,
        secretAccessKey: data.secretAccessKey,
        sessionToken: data.sessionToken,
      },
    };


    
    lightsail = new LightsailClient(config);
    secretsManager = new SecretsManagerClient(config);


    const secretName = `sites/${userId}/${siteName}`;
const secretResult = await secretsManager.send(
  new GetSecretValueCommand({ SecretId: secretName })
);

const secretJson = JSON.parse(secretResult.SecretString || '{}');

if (!secretJson.db_name) {
  throw new Error(`❌ 'db_name' not found in secret ${secretName}`);
}

const dbInstanceIdentifier = secretJson.db_name;
const targetDbInstanceIdentifier = `${dbInstanceIdentifier}restored`
console.log(`✅ Using DB Identifier from Secrets Manager: ${dbInstanceIdentifier}`);


    // 3. Créer un snapshot manuel
    const snapshotName = `manual-${dbInstanceIdentifier}-${Date.now()}`;
    const createSnapshotCommand = new CreateRelationalDatabaseSnapshotCommand({
      relationalDatabaseName: dbInstanceIdentifier,
      relationalDatabaseSnapshotName: snapshotName
    });
    await lightsail.send(createSnapshotCommand);
    console.log(`Manual snapshot created: ${snapshotName}`);

    // 4. Attendre que le snapshot soit disponible
    await this.waitForLightsailSnapshotAvailable(lightsail, snapshotName);

    // 5. Restaurer à partir du snapshot
    await this.restoreLightsailDbFromSnapshot(
      siteName,
      userId,
      dbInstanceIdentifier,
      snapshotName,
      targetDbInstanceIdentifier
    );

 
    return {
      message: `Manual snapshot, restore, and secret update completed.`,
      db: {
  
      }
    };
  } catch (error: any) {
    console.error(`Error creating manual snapshot and restoring:`, error);

    await this.triggerCodeBuildPipelineWithConnectAws(siteName, userId);
    
    // Handle specific Lightsail errors
    if (error.name === 'InvalidInputException') {
      throw new Error(`Invalid database name: . Check database exists in Lightsail.`);
    }
    if (error.name === 'NotFoundException') {
      throw new Error(`Database not found in Lightsail: `);
    }
    
    throw new Error(error.message || 'Failed to create manual snapshot and restore');
  } finally {
    lightsail?.destroy();
    secretsManager?.destroy();
  }
}


async triggerCodeBuildPipelineWithConnectAws( 
  siteName: string,
  userId: number,
  region = "us-east-1"
): Promise<void> {
  try {
    // 🔑 Obtenir les credentials temporaires
  // 1. Get temporary credentials from user service
        const data = await this.fetchTempCredentials(userId);

         const { accessKeyId, secretAccessKey, sessionToken } = data;

    const client = new CodeBuildClient({
      region,
      credentials: {
        accessKeyId: data.accessKeyId,
        secretAccessKey: data.secretAccessKey,
        sessionToken: data.sessionToken,
      },
    });

    const projectName = `drupal-deployment-${userId}-${siteName}`;

    const command = new StartBuildCommand({
      projectName,
      // 🔁 Optionnel : overrides si besoin
      // environmentVariablesOverride: [
      //   {
      //     name: 'TRIGGERED_BY_RESTORE',
      //     value: 'true',
      //     type: 'PLAINTEXT'
      //   }
      // ]
    });

    const result = await client.send(command);
    console.log(`🚀 CodeBuild triggered for ${projectName}: ${result.build?.id}`);
  } catch (error) {
    console.error("❌ Failed to trigger CodeBuild:", error);
    throw new Error("Pipeline trigger failed");
  }
}

private async restoreLightsailDbFromSnapshot(
  siteName: string,
  userId: number,
  dbInstanceIdentifier: string,
  snapshotIdentifier: string,
  targetDbInstanceIdentifier: string,
): Promise<any> {
  let lightsail: LightsailClient;
  let secretsManager: SecretsManagerClient;

  try {
  // 1. Get temporary credentials from user service
        const data = await this.fetchTempCredentials(userId);

         const { accessKeyId, secretAccessKey, sessionToken } = data;

    const config = {
      region: 'us-east-1',
      credentials: {
        accessKeyId: data.accessKeyId,
        secretAccessKey: data.secretAccessKey,
        sessionToken: data.sessionToken,
      },
    };

    lightsail = new LightsailClient(config);
    secretsManager = new SecretsManagerClient(config);

    const getDbCommand = new GetRelationalDatabaseCommand({
      relationalDatabaseName: dbInstanceIdentifier,
    });

    const sourceDb = await lightsail.send(getDbCommand);
    if (!sourceDb.relationalDatabase) {
      throw new Error(`Lightsail database not found: ${dbInstanceIdentifier}`);
    }

    console.log('Source DB details:', sourceDb.relationalDatabase);

    await this.waitForLightsailSnapshotAvailable(lightsail, snapshotIdentifier);

    const restoreCommand = new CreateRelationalDatabaseFromSnapshotCommand({
      relationalDatabaseSnapshotName: snapshotIdentifier,
      relationalDatabaseName: targetDbInstanceIdentifier,
      availabilityZone: sourceDb.relationalDatabase.location.availabilityZone,
      publiclyAccessible: sourceDb.relationalDatabase.publiclyAccessible,
      relationalDatabaseBundleId: sourceDb.relationalDatabase.relationalDatabaseBundleId,
      tags: [
        { key: 'UserId', value: userId.toString() },
        { key: 'Environment', value: 'Restored' },
        { key: 'OriginalName', value: dbInstanceIdentifier },
      ],
    });

    await lightsail.send(restoreCommand);
    console.log(`Lightsail DB restore from snapshot ${snapshotIdentifier} initiated`);

    await this.waitForLightsailDbAvailable(lightsail, targetDbInstanceIdentifier);

    // ✅ STEP: Generate secure password
    const newPassword = randomBytes(12).toString('base64').replace(/[^a-zA-Z0-9]/g, '').slice(0, 16);

    // ✅ STEP: Reset password on the restored DB
    await lightsail.send(
      new UpdateRelationalDatabaseCommand({
        relationalDatabaseName: targetDbInstanceIdentifier,
        masterUserPassword: newPassword,
      })
    );
    console.log(`✅ Master password reset for DB: ${targetDbInstanceIdentifier}`);

    // ✅ Wait for update to apply
    await this.waitForLightsailDbAvailable(lightsail, targetDbInstanceIdentifier);

    // ✅ Get new endpoint
    const getNewDbCommand = new GetRelationalDatabaseCommand({
      relationalDatabaseName: targetDbInstanceIdentifier,
    });

    const newDb = await lightsail.send(getNewDbCommand);
    const endpoint = newDb.relationalDatabase?.masterEndpoint?.address;
    const port = newDb.relationalDatabase?.masterEndpoint?.port;

    if (!endpoint || !port) {
      throw new Error('Failed to get endpoint for restored database');
    }

    console.log(`Restored instance endpoint: ${endpoint}:${port}`);

    // ✅ STEP: Update Secrets Manager with new credentials
    const secretName = `sites/${userId}/${siteName}`;

    console.log(newDb.relationalDatabase?.masterDatabaseName)

       await this.updateDbSecret(
            secretsManager,
            targetDbInstanceIdentifier,
            secretName,
            endpoint,
            port,
            newPassword
          );
    
    console.log(`🔐 Secrets Manager updated for ${secretName}`);

    // ✅ Trigger CodeBuild pipeline
     console.log(`Trigger pipeline`);
    await this.triggerCodeBuildPipelineWithConnectAws(siteName, userId);

    // ✅ Optional: delete old instance
    const deleteCommand = new DeleteRelationalDatabaseCommand({
      relationalDatabaseName: dbInstanceIdentifier,
      skipFinalSnapshot: true,
    });

    await lightsail.send(deleteCommand);
    console.log(`🗑️ Original instance ${dbInstanceIdentifier} deletion started`);

    return {
      message: `Database restored from snapshot ${snapshotIdentifier} to ${targetDbInstanceIdentifier}`,
      dbInstance: {
        identifier: targetDbInstanceIdentifier,
        endpoint,
        port,
      },
    };
  } catch (error: any) {
    console.error('❌ Error restoring from snapshot:', error);
    throw new Error(error.message || 'Failed to restore from snapshot');
  } finally {
    lightsail?.destroy();
    secretsManager?.destroy();
  }
}



// Lightsail-specific wait functions
private async waitForLightsailDbAvailable(
  client: LightsailClient,
  dbName: string,
  maxAttempts = 60,
  delay = 30000
): Promise<void> {
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    const command = new GetRelationalDatabaseCommand({ relationalDatabaseName: dbName });
    const response = await client.send(command);
    
    if (response.relationalDatabase?.state === 'available') {
      return;
    }
    
    console.log(`Waiting for DB ${dbName} to be available... (${response.relationalDatabase?.state})`);
    await new Promise(resolve => setTimeout(resolve, delay));
  }
  
  throw new Error(`Timed out waiting for DB ${dbName} to become available`);
}

private async waitForLightsailSnapshotAvailable(
  client: LightsailClient,
  snapshotName: string,
  maxAttempts = 30,
  delay = 30000
): Promise<void> {
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    const command = new GetRelationalDatabaseSnapshotCommand({ relationalDatabaseSnapshotName: snapshotName });
    const response = await client.send(command);
    
    if (response.relationalDatabaseSnapshot?.state === 'available') {
      return;
    }
    
    console.log(`Waiting for snapshot ${snapshotName} to be available... (${response.relationalDatabaseSnapshot?.state})`);
    await new Promise(resolve => setTimeout(resolve, delay));
  }
  
  throw new Error(`Timed out waiting for snapshot ${snapshotName} to become available`);
}



   async getAvailableSnapshots(userId: number, dbInstanceIdentifier: string) {
  let client: LightsailClient;
  try {
    // Get AWS credentials
    // 1. Get temporary credentials from user service
        const data = await this.fetchTempCredentials(userId);

         const { accessKeyId, secretAccessKey, sessionToken } = data;

    // Initialize Lightsail client
    client = new LightsailClient({
      region: 'us-east-1',
      credentials: {
        accessKeyId: data.accessKeyId,
        secretAccessKey: data.secretAccessKey,
        sessionToken: data.sessionToken,
      },
    });

    // Get all snapshots
    const response = await client.send(new GetRelationalDatabaseSnapshotsCommand({}));

    console.log("response l avaialable",response)
    
    // Filter snapshots for the specific database
    const databaseSnapshots = (response.relationalDatabaseSnapshots || []).filter(
      snapshot => snapshot.fromRelationalDatabaseName === dbInstanceIdentifier
    );

    // Map to consistent response format
    return {
      status: 'success',
      data: databaseSnapshots.map(snapshot => ({
        id: snapshot.name,
        date: snapshot.createdAt,
        size: snapshot.sizeInGb,
        status: this.mapSnapshotState(snapshot.state),
        instanceIdentifier: snapshot.fromRelationalDatabaseName,
        engine: snapshot.engine,
        engineVersion: snapshot.engineVersion,
      })),
      retentionPolicy: 'Manual snapshots are retained until deleted. Automated snapshots are retained for 35 days'
    };
  } catch (error) {
    return {
      status: 'error',
      message: `Failed to retrieve snapshots: ${error.message}`,
      errorCode: 'SNAPSHOT_FETCH_ERROR',
      details: error.name === 'NotFoundException' 
        ? `Database ${dbInstanceIdentifier} not found in Lightsail` 
        : undefined
    };
  } finally {
    client?.destroy();
  }
}

// Helper function to map Lightsail states to consistent status
private mapSnapshotState(state: string): string {
  const stateMap: Record<string, string> = {
    'available': 'available',
    'creating': 'creating',
    'failed': 'error',
    'unknown': 'unknown',
    'deleting': 'deleting',
    'pending': 'pending',
  };
  return stateMap[state.toLowerCase()] || state;
}

  


  
    
    private async restoreDbFromSnapshot(
        siteName: string,
        userId: number,
        dbInstanceIdentifier: string,
        snapshotIdentifier: string,
        targetDbInstanceIdentifier: string,
      ): Promise<any> {
        let client: RDSClient;
        let secretsManager: SecretsManagerClient;
    
        try {
          // Get AWS credentials
        // 1. Get temporary credentials from user service
        const data = await this.fetchTempCredentials(userId);

         const { accessKeyId, secretAccessKey, sessionToken } = data;
    
          // Initialize AWS clients
          const config = {
            region: 'us-east-1',
            credentials: {
              accessKeyId: data.accessKeyId,
              secretAccessKey: data.secretAccessKey,
              sessionToken: data.sessionToken,
            },
          };
          
          client = new RDSClient(config);
          secretsManager = new SecretsManagerClient(config);
    
          // 1. Get source DB details
          const describeCommand = new DescribeDBInstancesCommand({
            DBInstanceIdentifier: dbInstanceIdentifier
          });
           console.log("describecommand",describeCommand)
          const sourceDbResponse = await client.send(describeCommand);
          
          if (!sourceDbResponse.DBInstances || sourceDbResponse.DBInstances.length === 0) {
            throw new Error(`Source database not found: ${dbInstanceIdentifier}`);
          }
          
          const sourceDb = sourceDbResponse.DBInstances[0];
          console.log('Source DB details:', sourceDb);
    
          // 2. Vérifier que le snapshot est disponible
          await this.waitForSnapshotAvailable(client, snapshotIdentifier);
    
          // 3. Restaurer à partir du snapshot
          const restoreCommand = new RestoreDBInstanceFromDBSnapshotCommand({
            DBSnapshotIdentifier: snapshotIdentifier,
            DBInstanceIdentifier: targetDbInstanceIdentifier,
            PubliclyAccessible: sourceDb.PubliclyAccessible,
            DBSubnetGroupName: sourceDb.DBSubnetGroup?.DBSubnetGroupName,
            VpcSecurityGroupIds: sourceDb.VpcSecurityGroups?.map(sg => sg.VpcSecurityGroupId),
            DBParameterGroupName: sourceDb.DBParameterGroups?.[0]?.DBParameterGroupName,
            Tags: [
              { Key: 'UserId', Value: userId.toString() },
              { Key: 'Environment', Value: 'Restored' },
              { Key: 'OriginalName', Value: dbInstanceIdentifier },
            ],
            DeletionProtection: false,
          });
          
          await client.send(restoreCommand);
          console.log(`DB Restore from snapshot ${snapshotIdentifier} initiated`);
    
          // 4. Attendre que l'instance soit disponible
          await this.waitForDbInstanceAvailable(client, targetDbInstanceIdentifier);
          
          // 5. Récupérer les détails de l'instance restaurée
          const { endpoint: tempEndpoint, port: tempPort } = await this.getDbEndpoint(
            client,
            targetDbInstanceIdentifier
          );
          console.log(`Restored instance endpoint: ${tempEndpoint}:${tempPort}`);
          
          // 6. Mettre à jour Secrets Manager
          const secretName = `sites/${userId}/${siteName}`;
          const originalEndpoint = sourceDb.Endpoint?.Address;
          
          await this.updateDbSecret(
            secretsManager,
            targetDbInstanceIdentifier,
            secretName,
            tempEndpoint,
            tempPort
          );
    
          // 7. Supprimer l'instance originale
          const deleteCommand = new DeleteDBInstanceCommand({
            DBInstanceIdentifier: dbInstanceIdentifier,
            SkipFinalSnapshot: true,
            DeleteAutomatedBackups: true,
          });
          
          await client.send(deleteCommand);
          console.log(`Original instance ${dbInstanceIdentifier} deletion started`);
          await this.waitForDbInstanceDeleted(client, dbInstanceIdentifier);
    
          // 8. Renommer l'instance temporaire
          const renameCommand = new ModifyDBInstanceCommand({
            DBInstanceIdentifier: targetDbInstanceIdentifier,
            NewDBInstanceIdentifier: dbInstanceIdentifier,
            ApplyImmediately: true,
          });
          
          await client.send(renameCommand);
          await this.waitForDbInstanceAvailable(client, dbInstanceIdentifier);
    
          // 9. Récupérer le nouveau endpoint
          const { endpoint: newEndpoint, port: newPort } = await this.getDbEndpoint(
            client,
            dbInstanceIdentifier
          );
          
          // 10. Mettre à jour Secrets Manager avec le nom original
          await this.updateDbSecret(
            secretsManager,
            dbInstanceIdentifier,
            secretName,
            newEndpoint,
            newPort
          );
    
          // 11. Réinitialiser l'accès admin Drupal
    
          return {
            message: `Database restored from snapshot ${snapshotIdentifier} to ${dbInstanceIdentifier}`,
            dbInstance: {
              identifier: dbInstanceIdentifier,
              status: 'available',
              endpoint: newEndpoint,
              port: newPort
            },
          };
        } catch (error: any) {
          console.error('Error restoring from snapshot:', error);
          
          // Handle specific AWS errors
          if (error.name === 'DBSnapshotNotFoundFault') {
            throw new Error(`Snapshot not found: ${snapshotIdentifier}`);
          }
          if (error.name === 'DBInstanceNotFoundFault') {
            throw new Error(`Source database not found: ${dbInstanceIdentifier}`);
          }
          if (error.name === 'DBInstanceAlreadyExistsFault') {
            throw new Error('Database instance name already exists');
          }
          
          throw new Error(error.message || 'Failed to restore from snapshot');
        } finally {
          client?.destroy();
          secretsManager?.destroy();
        }
      }
    
      
    
     
    
      private async getDbEndpoint(
        client: RDSClient,
        instanceIdentifier: string
      ): Promise<{ endpoint: string; port: number }> {
        const response = await client.send(
          new DescribeDBInstancesCommand({
            DBInstanceIdentifier: instanceIdentifier
          })
        );
        
        const instance = response.DBInstances?.[0];
        if (!instance?.Endpoint?.Address) {
          throw new Error(`Endpoint not available for ${instanceIdentifier}`);
        }
        
        return {
          endpoint: instance.Endpoint.Address,
          port: instance.Endpoint.Port || 3306
        };
      }
    
      
    
     
    
    
    private async waitForSnapshotAvailable(
        client: RDSClient,
        snapshotId: string,
        timeoutMinutes: number = 30
      ): Promise<void> {
        const startTime = Date.now();
        const timeout = timeoutMinutes * 60 * 1000;
        
        console.log(`Waiting for snapshot ${snapshotId} to become available...`);
        
        while (Date.now() - startTime < timeout) {
          try {
            const response = await client.send(
              new DescribeDBSnapshotsCommand({
                DBSnapshotIdentifier: snapshotId
              })
            );
            
            const snapshot = response.DBSnapshots?.[0];
            if (snapshot?.Status === 'available') {
              console.log(`Snapshot ${snapshotId} is available`);
              return;
            }
            
            console.log(`Snapshot status: ${snapshot?.Status || 'pending'}... waiting`);
            await new Promise(resolve => setTimeout(resolve, 30000)); // 30s
          } catch (error) {
            if (error.name === 'DBSnapshotNotFoundFault') {
              throw new Error(`Snapshot not found: ${snapshotId}`);
            }
            throw error;
          }
        }
        
        throw new Error(`Snapshot ${snapshotId} not available after ${timeoutMinutes} minutes`);
      }
    
    
async restoreDbToPointInTimeWithZeroDowntime(
  siteName: string,
  userId: number,
  dbInstanceIdentifier: string,
  restoreTime: string
): Promise<any> {
  let lightsailClient: LightsailClient;
  let secretsManager: SecretsManagerClient;

  try {
    // 1. Load AWS credentials
     const data = await this.fetchTempCredentials(userId);

         const { accessKeyId, secretAccessKey, sessionToken } = data;

    const config = {
      region: 'us-east-1',
      credentials: {
        accessKeyId: data.accessKeyId,
        secretAccessKey: data.secretAccessKey,
        sessionToken: data.sessionToken,
      },
    };

    lightsailClient = new LightsailClient(config);
    secretsManager = new SecretsManagerClient(config);

    // 2. Get latest snapshot before restoreTime
    const snapshotRes = await lightsailClient.send(
      new GetRelationalDatabaseSnapshotsCommand({})
    );

         // Validate restore time
        const restoreDate = restoreTime ? new Date(restoreTime) : null;
        if (restoreDate && (isNaN(restoreDate.getTime()) || restoreDate > new Date())) {
          throw new Error('Invalid restore time');
        }

    const validSnapshots = snapshotRes.relationalDatabaseSnapshots
      ?.filter(s =>
        s.fromRelationalDatabaseName === dbInstanceIdentifier &&
        s.createdAt && new Date(s.createdAt) <= restoreDate
      )
      .sort((a, b) => new Date(b.createdAt!).getTime() - new Date(a.createdAt!).getTime());

    if (!validSnapshots?.length) {
      throw new Error(`No valid snapshots found before ${restoreTime}`);
    }

    const snapshotName = validSnapshots[0].name!;
    const tempDbName = `restored-${Date.now()}`.substring(0, 63);

    console.log(`Using snapshot ${snapshotName}`);

    // 3. Restore to new Lightsail DB (no impact yet)
    await lightsailClient.send(new CreateRelationalDatabaseFromSnapshotCommand({
      relationalDatabaseName: tempDbName,
      relationalDatabaseSnapshotName: snapshotName,
      availabilityZone: 'us-east-1a',
      publiclyAccessible: true,
    }));

    console.log(`Creating new restored DB ${tempDbName}`);

    // 4. Wait for DB to become available
    await this.waitForLightsailDbAvailable(lightsailClient, tempDbName);

    // 5. Fetch endpoint of new DB
    const dbRes = await lightsailClient.send(
      new GetRelationalDatabaseCommand({ relationalDatabaseName: tempDbName })
    );

    const newDb = dbRes.relationalDatabase;

    if (!newDb?.masterEndpoint) {
      throw new Error(`Restored DB ${tempDbName} missing endpoint`);
    }

    const newHost = newDb.masterEndpoint.address!;
    const newPort = newDb.masterEndpoint.port!;

    console.log(`New DB endpoint: ${newHost}:${newPort}`);

    // 6. Update Secrets Manager to point to new DB
    const secretName = `sites/${userId}/${siteName}`;

    const currentSecret = await secretsManager.send(new GetSecretValueCommand({
      SecretId: secretName,
    }));

    const parsedSecret = JSON.parse(currentSecret.SecretString!);

    parsedSecret.host = newHost;
    parsedSecret.port = newPort;

    await secretsManager.send(new PutSecretValueCommand({
      SecretId: secretName,
      SecretString: JSON.stringify(parsedSecret),
    }));

    console.log(`🔁 Secrets Manager updated — your app now connects to restored DB`);

    return {
      message: `✅ Restored DB and swapped Secrets Manager endpoint`,
      newDbName: tempDbName,
      newDbHost: newHost,
      newDbPort: newPort,
    };

  } catch (err: any) {
    console.error('Restore error:', err);
    throw new Error(`Restore failed: ${err.message}`);
  } finally {
    lightsailClient?.destroy();
    secretsManager?.destroy();
  }
}



  // ===== Méthodes utilitaires =====

  private async flushAndLockDatabase(client: LightsailClient, dbName: string): Promise<void> {
    try {
      console.log('Flushing and locking database to minimize data loss...');
      // Cette méthode dépend du moteur de base de données
      // Implémentation réelle nécessite l'exécution de commandes SQL spécifiques
      // Ex: FLUSH TABLES WITH READ LOCK (MySQL) ou pg_terminate_backend (PostgreSQL)
    } catch (error) {
      console.warn('Could not lock database, proceeding anyway:', error);
    }
  }

  // we should update db_password also ! 

  async restoreWithTempCredentials(
    siteName: string,
    userId: number,
    dbInstanceIdentifier: string,
    restoreTime: string,
  ): Promise<any> {


       const { data: tempCreds}= await this.fetchTempCredentials(userId);


    const awsConfig = {
      region: 'us-east-1',
      credentials: {
        accessKeyId: tempCreds.accessKeyId,
        secretAccessKey: tempCreds.secretAccessKey,
        sessionToken: tempCreds.sessionToken,
      },
    };

    const lightsailClient = new LightsailClient(awsConfig);
    const secretsClient = new SecretsManagerClient(awsConfig);

    // 2. Get snapshots for the DB
    const snapRes = await lightsailClient.send(
      new GetRelationalDatabaseSnapshotsCommand({})
    );


         // Validate restore time
        const restoreDate = restoreTime ? new Date(restoreTime) : null;
        if (restoreDate && (isNaN(restoreDate.getTime()) || restoreDate > new Date())) {
          throw new Error('Invalid restore time');
        }

    const snapshot = snapRes.relationalDatabaseSnapshots
      ?.filter(s =>
        s.fromRelationalDatabaseName === dbInstanceIdentifier &&
        s.createdAt && new Date(s.createdAt) <= restoreDate
      )
      .sort((a, b) => new Date(b.createdAt!).getTime() - new Date(a.createdAt!).getTime())[0];

    if (!snapshot?.name) {
      throw new Error(`No snapshot found before ${restoreTime}`);
    }

    const restoredDbName = `restored-${Date.now()}`.substring(0, 63);

    // 3. Restore to new DB
    await lightsailClient.send(
      new CreateRelationalDatabaseFromSnapshotCommand({
        relationalDatabaseName: restoredDbName,
        relationalDatabaseSnapshotName: snapshot.name,
        availabilityZone: 'us-east-1a',
        publiclyAccessible: true,
      })
    );

    console.log(`Restoring to DB: ${restoredDbName}`);
    await this.waitForLightsailDbAvailable(lightsailClient, restoredDbName);

    // 4. Get new DB endpoint
    const newDbRes = await lightsailClient.send(
      new GetRelationalDatabaseCommand({ relationalDatabaseName: restoredDbName })
    );
    const newDb = newDbRes.relationalDatabase;

    if (!newDb?.masterEndpoint) {
      throw new Error('Restored DB missing endpoint');
    }

    const newHost = newDb.masterEndpoint.address!;
    const newPort = newDb.masterEndpoint.port!;

    // 5. Update Secrets Manager
    const secretId = `sites/${userId}/${siteName}`;
    const secretRes = await secretsClient.send(
      new GetSecretValueCommand({ SecretId: secretId })
    );
    const parsedSecret = JSON.parse(secretRes.SecretString!);
    parsedSecret.host = newHost;
    parsedSecret.port = newPort;

    await secretsClient.send(
      new PutSecretValueCommand({
        SecretId: secretId,
        SecretString: JSON.stringify(parsedSecret),
      })
    );

    console.log(`✅ Secrets updated — app now points to restored DB`);

    return {
      message: 'Restored DB with temporary credentials and zero downtime.',
      newDb: {
        name: restoredDbName,
        endpoint: newHost,
        port: newPort,
      },
    };
  }
  



 private async waitForLightsailDbDeleted(client: LightsailClient, dbName: string): Promise<void> {
    const command = new GetRelationalDatabaseCommand({ relationalDatabaseName: dbName });
    let attempts = 0;
    const maxAttempts = 60; // 10 minutes
    
    while (attempts < maxAttempts) {
      attempts++;
      try {
        await client.send(command);
        console.log(`Database ${dbName} still deleting...`);
        await new Promise(resolve => setTimeout(resolve, 10000));
      } catch (error) {
        if (error.name === 'NotFoundException' || error.code === 'DoesNotExist') {
          console.log(`Database ${dbName} confirmed deleted`);
          return;
        }
        throw error;
      }
    }
    
    throw new Error(`Database ${dbName} did not delete within 10 minutes`);
  }



  private async waitForLightsailDbRenamed(
    client: LightsailClient, 
    oldName: string, 
    newName: string
  ): Promise<void> {
    const maxAttempts = 30; // 5 minutes
    let attempts = 0;
    
    while (attempts < maxAttempts) {
      attempts++;
      try {
        // Vérifier que le nouveau nom existe
        const response = await client.send(
          new GetRelationalDatabaseCommand({ relationalDatabaseName: newName })
        );
        
        if (response.relationalDatabase?.state === 'available') {
          // Vérifier que l'ancien nom n'existe plus
          try {
            await client.send(
              new GetRelationalDatabaseCommand({ relationalDatabaseName: oldName })
            );
          } catch (error) {
            if (error.name === 'NotFoundException') return;
          }
        }
      } catch (error) {
        // Ignorer les erreurs temporaires
      }
      await new Promise(r => setTimeout(r, 10000));
    }
    throw new Error(`Database rename from ${oldName} to ${newName} timed out`);
  }

  private async updateDbSecret(
      client: SecretsManagerClient,      
      targetDbInstanceIdentifier : string,
      secretName: string,
      host: string,
      port: number,
      db_password ?:string 
    ): Promise<void> {
      try {
        // Get existing secret
        const getSecretResponse = await client.send(
          new GetSecretValueCommand({ SecretId: secretName })
        );
        
        if (!getSecretResponse.SecretString) {
          throw new Error('Secret has no string value');
        }
        
        const secretValue = JSON.parse(getSecretResponse.SecretString);
        
        // Update connection details
        const updatedSecret = {
          ...secretValue,
          db_name : targetDbInstanceIdentifier,
          db_endpoint: host,
          db_port: port,
          db_password : db_password
        };
        
        // Update secret
        await client.send(
          new UpdateSecretCommand({
            SecretId: secretName,
            SecretString: JSON.stringify(updatedSecret),
          })
        );
        
        console.log(`Updated secret ${secretName} with new endpoint: ${host}:${port}`);
      } catch (error) {
        console.error('Failed to update DB secret:', error);
        throw new Error('Could not update database connection secret');
      }
    }


    
    private async waitForDbInstanceAvailable(
      client: RDSClient,
      instanceIdentifier: string,
      timeoutMinutes: number = 30
    ): Promise<void> {
    
      console.log("hellouu")
      const startTime = Date.now();
      const timeout = timeoutMinutes * 60 * 1000;
      
      while (Date.now() - startTime < timeout) {
        try {
          const response = await client.send(
            new DescribeDBInstancesCommand({
              DBInstanceIdentifier: instanceIdentifier
            })
          );
          
          const instance = response.DBInstances?.[0];
          if (instance?.DBInstanceStatus === 'available') {
            return;
          }
        } catch (error) {
          if (error.name === 'DBInstanceNotFoundFault') {
            // Continue waiting
          } else {
            throw error;
          }
        }
        
        await new Promise(resolve => setTimeout(resolve, 30000)); // Wait 30 seconds
      }
      
      throw new Error(`Timed out waiting for DB instance ${instanceIdentifier} to become available`);
    }
    
    private async waitForDbInstanceDeleted(
      client: RDSClient,
      instanceIdentifier: string,
      timeoutMinutes: number = 30
    ): Promise<void> {
      const startTime = Date.now();
      const timeout = timeoutMinutes * 60 * 1000;
      
      while (Date.now() - startTime < timeout) {
        try {
          await client.send(
            new DescribeDBInstancesCommand({
              DBInstanceIdentifier: instanceIdentifier
            })
          );
        } catch (error) {
          if (error.name === 'DBInstanceNotFoundFault') {
            return; // Deletion complete
          }
          throw error;
        }
        
        await new Promise(resolve => setTimeout(resolve, 30000)); // Wait 30 seconds
      }
      
      throw new Error(`Timed out waiting for DB instance ${instanceIdentifier} to be deleted`);
    }
    
   
    
}
