import { Injectable } from '@angular/core';

@Injectable()
export class ModalService {

  constructor() { }

  create = {
    displayed: false
  };

  edit = {
    displayed: false
  };

  view = {
    displayed: false
  };

  toggleScrollUnderModal() {
    if (this.create.displayed || this.edit.displayed || this.view.displayed) {
      document.body.style.overflow = 'hidden';
    } else {
      document.body.style.overflow = 'auto';
    }
  }

}
