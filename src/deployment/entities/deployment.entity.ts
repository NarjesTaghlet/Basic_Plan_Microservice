import { Entity, Column, PrimaryGeneratedColumn ,UpdateDateColumn, 
    CreateDateColumn, 
    Unique} from 'typeorm';

@Entity()
export class Deployment {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  userId: number;

  @Column(
    { unique: true }
  )
  siteName: string;

  @Column()
  cloudflareDomain: string;

  @Column()
  selectedStack: string;

  @Column()
  status: string;

  @Column({ nullable: true })
  instancePublicIp: string;

  @Column({ nullable: true })
  userRepoUrl: string;

  @Column({ nullable: true })
  orgRepoUrl: string;

  @Column({ nullable: true })
  secretsManagerArn: string;

@Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
createdAt: Date;


  @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
updatedAt: Date;


  @Column({ nullable: true, type: 'text' })
  sshPrivateKey: string; 

   //Dev environement

   @Column()
  cloudflareDomain_dev: string;


  @Column({ nullable: true })
  instancePublicIp_dev: string;


  @Column({ nullable: true })
  secretsManagerArn_test: string;

  @UpdateDateColumn({
    type: 'timestamp',
    default: () => 'CURRENT_TIMESTAMP',
    onUpdate: 'CURRENT_TIMESTAMP',
  })
  updatedAt_dev: Date;

  @Column({ nullable: true, type: 'text' })
  sshPrivateKey_dev: string;

  
  @Column({ nullable: true })
  instanceName: string;

   @Column({ nullable: true })
  instanceName_dev: string;


  @Column({ nullable: true })
  bundleId: string;

  //we should add the current bundle id & instance name for upgrading !



     
}