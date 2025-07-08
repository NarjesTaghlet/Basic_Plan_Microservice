export interface AwsCredentialsResponse {
    accessKeyId: string;
    secretAccessKey: string;
    sessionToken: string;
    accountId?:string;
  }