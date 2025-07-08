import { Test, TestingModule } from '@nestjs/testing';
import { RestoredbController } from './restoredb.controller';

describe('RestoredbController', () => {
  let controller: RestoredbController;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [RestoredbController],
    }).compile();

    controller = module.get<RestoredbController>(RestoredbController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
});
