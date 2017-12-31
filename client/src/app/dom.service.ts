import { Inject, Injectable } from '@angular/core';
import { DOCUMENT } from '@angular/common';

@Injectable()
export class DomService {

  constructor(@Inject(DOCUMENT) private dom: any) { }


}
