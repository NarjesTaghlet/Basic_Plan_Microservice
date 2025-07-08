import { Test, TestingModule } from '@nestjs/testing';
import { RestoredbService } from './restoredb.service';

describe('RestoredbService', () => {
  let service: RestoredbService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [RestoredbService],
    }).compile();

    service = module.get<RestoredbService>(RestoredbService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
