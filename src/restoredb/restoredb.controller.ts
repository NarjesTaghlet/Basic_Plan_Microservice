import { Controller } from '@nestjs/common';

import { Post,Get , Delete ,Body ,HttpException, HttpStatus , Request ,UseGuards } from '@nestjs/common';
import { RestoredbService } from './restoredb.service';
import { TokenGuard } from 'src/deployment/Guards/token-guard';
import { BadRequestException } from '@nestjs/common';




interface GetSnapshotsRequest {
  dbInstanceIdentifier: string;
  subAccountId: string;
}


interface RestoreDbRequest {
  siteName : string;
  userId: number;
  dbInstanceIdentifier: string;
  restoreTime: string | null; // ISO string or null for latest restorable time
  targetDbInstanceIdentifier: string;
}


@Controller('restoredb')
export class RestoredbController {

        constructor(private readonly rrestoredbservice : RestoredbService ){
    
        }


        @UseGuards(TokenGuard)
          @Post('snapshots')
          async getSnapshots(@Request() req, @Body() body: GetSnapshotsRequest) {
            const userId = req.user.userId; 
            const { dbInstanceIdentifier} = body;
        
        
            try {
              const snapshots = await this.rrestoredbservice.getAvailableSnapshots(userId, dbInstanceIdentifier);
              console.log("heelo",snapshots)
              return {
                message: `Successfully retrieved snapshots for ${dbInstanceIdentifier}`,
                snapshots,
              };
            } catch (error) {
              throw new BadRequestException(`Failed to retrieve snapshots: ${error.message}`);
            }
          }
        
        
          
        
        
          @UseGuards(TokenGuard)
          @Post('restore-db')
          async restoreDbToPointInTime(@Body() body: RestoreDbRequest , @Request() req) {
            try {
              // userId m token 
              // dbinstanceidentifier sitename & userId => ofnction twali tekhou userId & site Name 
              const {  restoreTime  , siteName} = body;
              const userId = req.user.userId
              const dbInstanceIdentifier = `db${userId}${siteName}`
              const targetDbInstanceIdentifier = `${dbInstanceIdentifier}-restored`

              console.log("helo from restorig db")
        
              // Validate input
              if (!userId || !dbInstanceIdentifier || !targetDbInstanceIdentifier) {
                throw new HttpException(
                  'Missing required fields: userId, dbInstanceIdentifier, or targetDbInstanceIdentifier',
                  HttpStatus.BAD_REQUEST,
                );
              }
        
              // Call service to restore DB
              const response = await this.rrestoredbservice.restoreWithTempCredentials(
                siteName,
                userId,
                dbInstanceIdentifier,
                restoreTime,
              );
        
              return {
                status: 'success',
                message: response.message,
                dbInstance: response.dbInstance,
              };
            } catch (error: any) {
              throw new HttpException(
                error.message || 'Failed to initiate DB restore',
                error.status || HttpStatus.INTERNAL_SERVER_ERROR,
              );
            }
          }



 @UseGuards(TokenGuard)
  @Post('available-snapshots')
  async getAvailableSnapshots(
    @Body() body : any,
    @Request() req
  ) {
    const userId = req.user.userId;
    const dbInstanceIdentifier = `db${userId}${body.siteName}`;
    console.log("hello")

    try {
      const response = await this.rrestoredbservice.getAvailableSnapshots(userId, dbInstanceIdentifier);
      
      if (response.status === 'error') {
        throw new HttpException(response.message, HttpStatus.INTERNAL_SERVER_ERROR);
      }

      // Formatage correct avec les propriétés AWS SDK v3
      const calendarData = response.data.map(snap => ({
        date: snap.date, // Utiliser directement la date formatée du service
        id: snap.id,
        size: snap.size,
        status: snap.status
      }));

      return {
        status: 'success',
        data: calendarData,
        retentionPeriod: response.retentionPolicy || '35 jours'
      };
    } catch (error) {
      throw new HttpException(
        error.message || 'Failed to fetch snapshots',
        HttpStatus.INTERNAL_SERVER_ERROR
      );
    }
  }


    
    
     @UseGuards(TokenGuard)
    @Post('create-snapshot-and-restore')
      async cc(@Body() body: any, @Request() req ) {
        try {
          const { siteName  } = body;
          const userId = req.user.userId;
  //  const dbInstanceIdentifier = `db${userId}${body.siteName}`;
 //   const targetDbInstanceIdentifier =  `db${userId}${body.siteName}restored`
 
    
          // Validation des paramètres
          if (!siteName || !userId ) {
            throw new HttpException('Missing required parameters', HttpStatus.BAD_REQUEST);
          }
    
          const result = await this.rrestoredbservice.createManualSnapshotAndRestore(
            siteName,
            userId,
         //   dbInstanceIdentifier,
         //   targetDbInstanceIdentifier
          );
    
          return {
            success: true,
            message: 'Manual snapshot created and restoration started',
            snapshotId: result.snapshotId,
            data: result
          };
        } catch (error) {
          throw new HttpException({
            status: HttpStatus.INTERNAL_SERVER_ERROR,
            error: error.message || 'Snapshot creation and restoration failed',
          }, HttpStatus.INTERNAL_SERVER_ERROR);
        }
      }
    

}
