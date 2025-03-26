import { Test, TestingModule } from '@nestjs/testing';
import { TokenCleanupService } from './token-cleanup.service';

describe('TokenCleanupService', () => {
  let service: TokenCleanupService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [TokenCleanupService],
    }).compile();

    service = module.get<TokenCleanupService>(TokenCleanupService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
