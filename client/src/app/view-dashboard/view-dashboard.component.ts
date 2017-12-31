import { Component, OnInit } from '@angular/core';

import { DashboardHttpService } from '../dashboard-http.service';
import { ModalService } from '../modal.service';
import { DomService } from '../dom.service';

@Component({
  selector: 'app-view-dashboard',
  templateUrl: './view-dashboard.component.html',
  styleUrls: ['./view-dashboard.component.scss'],
})

export class ViewDashboardComponent implements OnInit {

  constructor(private http: DashboardHttpService,
              private modals: ModalService,
              private dom: DomService
  ) { }

  copyXML: boolean = false;

  dashboard = {
    dashboardXML: ''
  }

  transitionOpacity() {
    let styles = {
      'background-color': this.modals.view.displayed ? 'rgba(0, 0, 0, 0.4)' : 'rgba(0, 0, 0, 0)',
      'transition' : 'background-color 3s'
    }
    return styles;
  }

  copyToClipboard() {
    this.copyXML = true;
      let copyText = <HTMLInputElement>document.getElementById("xml");
      copyText.select()
      document.execCommand("Copy");
  }

  exitModal() {
    this.modals.view.displayed = false;
  }

  ngOnInit() {
    this.modals.view.displayed = true;
    this.dashboard = Object.assign(this.dashboard, this.http.specificDashboard);
    console.log(this.dashboard);
  }

}
