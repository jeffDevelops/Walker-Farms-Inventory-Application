import { TestBed, inject } from '@angular/core/testing';

import { UseCaseHttpService } from './use-case-http.service';

describe('UseCaseHttpService', () => {
  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [UseCaseHttpService]
    });
  });

  it('should be created', inject([UseCaseHttpService], (service: UseCaseHttpService) => {
    expect(service).toBeTruthy();
  }));
});
