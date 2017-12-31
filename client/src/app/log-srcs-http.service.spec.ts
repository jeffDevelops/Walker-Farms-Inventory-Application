import { TestBed, inject } from '@angular/core/testing';

import { LogSrcsHttpService } from './log-srcs-http.service';

describe('LogSrcsHttpService', () => {
  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [LogSrcsHttpService]
    });
  });

  it('should be created', inject([LogSrcsHttpService], (service: LogSrcsHttpService) => {
    expect(service).toBeTruthy();
  }));
});
