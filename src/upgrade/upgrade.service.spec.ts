import { Test, TestingModule } from '@nestjs/testing';
import { UpgradeService } from './upgrade.service';

describe('UpgradeService', () => {
  let service: UpgradeService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [UpgradeService],
    }).compile();

    service = module.get<UpgradeService>(UpgradeService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
