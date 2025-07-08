import { Injectable } from '@nestjs/common';
import { LightsailClient, CreateInstanceSnapshotCommand, GetInstanceSnapshotCommand, CreateInstancesFromSnapshotCommand, GetInstanceCommand, GetStaticIpsCommand, DetachStaticIpCommand, AttachStaticIpCommand, DeleteInstanceCommand } from '@aws-sdk/client-lightsail';
import { SecretsManagerClient, CreateSecretCommand, UpdateSecretCommand, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';
import {
    CreateInstancesCommand,
    DetachDiskCommand,
    AttachDiskCommand,
    GetStaticIpCommand,
  } from '@aws-sdk/client-lightsail';
  import { STSClient, AssumeRoleCommand } from '@aws-sdk/client-sts';

@Injectable()
export class UpgradeService {
 //// Step 1: Connect to the user's sub-account
 // return creds ta sub-account 
 // Step 3: Retrieve database credentials from Secrets Manager => to relink db ? 
 //snapchot of the old instance
 //// Step 6: Create a new instance from the snapshot with the new bundle_id
 // Step 7: Reassign the static IP
 //Delete the old one

 
 
}
