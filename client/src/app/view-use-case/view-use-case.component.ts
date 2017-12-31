import { Component, OnInit } from '@angular/core';

import { UseCaseHttpService } from '../use-case-http.service';
import { ModalService } from '../modal.service';
import { DomService } from '../dom.service';

@Component({
  selector: 'app-view-use-case',
  templateUrl: './view-use-case.component.html',
  styleUrls: ['./view-use-case.component.scss'],
})
export class ViewUseCaseComponent implements OnInit {

  constructor(private http: UseCaseHttpService,
              private modals: ModalService,
              private dom: DomService
  ) { }

  copied: boolean = false;

  splUseCase = {
    spl: ''
  }

  transitionOpacity() {
    let styles = {
      'background-color': this.modals.view.displayed ? 'rgba(0, 0, 0, 0.4)' : 'rgba(0, 0, 0, 0)',
      'transition' : 'background-color 3s'
    }
    return styles;
  }

copyToClipboard() {
      this.copied = true;
        let copyText = <HTMLInputElement>document.getElementById("spl");
        copyText.select()
        document.execCommand("Copy");
    }

  exitModal() {
    this.modals.view.displayed = false;
  }

  ngOnInit() {
    this.modals.view.displayed = true;
    this.splUseCase = Object.assign(this.splUseCase, this.http.specificUseCase);
    console.log(this.splUseCase);
  }

}
