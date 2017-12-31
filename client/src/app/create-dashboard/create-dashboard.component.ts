import { Component, OnInit } from '@angular/core';

import { Observable } from 'rxjs/Observable';
import { Subscription } from 'rxjs/Subscription';

import { DashboardHttpService } from '../dashboard-http.service';
import { LogSrcsHttpService } from '../log-srcs-http.service';

import { ModalService } from '../modal.service';

@Component({
  selector: 'app-create-dashboard',
  templateUrl: './create-dashboard.component.html',
  styleUrls: ['../create-use-case/create-use-case.component.scss'],
})
export class CreateDashboardComponent implements OnInit {

  constructor(
    public http: DashboardHttpService,
    public logSrcsHttp: LogSrcsHttpService,
    public modals: ModalService
  ) { }

  subscription: Subscription;
  logSrcs: Array<any> = []; // all logSrcsHttp
  specificLogSrcs: Array<string> = [];
  tagToAdd: string = '';
  tagToDelete: string = '';

  // UX Enhancements
  savingTag: boolean = false;
  fetchingFromDB: boolean = false;
  deletingFromDB: boolean = false;

  dashboard = {
    dashboardName: '',
    domain: '',
    dashboardXML: '',
    requiredLogSrcs: [],
    comments: ''
  }

  domains: Array<string> = [
    'Access',
    'Audit',
    'Behavior Analytics',
    'Endpoint',
    'Threat',
    'Network',
    'Vulnerability',
    'Identity | Asset',
    'Machine Learning',
    'Infrastructure'
  ];

  dashboardNameValid: boolean = true;
  xmlValid: boolean = true;
  domainValid: boolean = false;

  addTag() {
    console.log(this.tagToAdd);
    let existingTags = this.logSrcsHttp.logSrcsArray.slice(0);
    let normalizedExistingTags = existingTags.map(tag => tag.toLowerCase());
    let normalizedNewTags = this.specificLogSrcs.map(tag => tag.toLowerCase());
    if (this.tagToAdd) {
      if (!normalizedExistingTags.includes(this.tagToAdd.toLowerCase())) {
        setTimeout( () => {
          this.logSrcsHttp.createLogSrc(this.tagToAdd)
            .then( () => {
              this.logSrcsHttp.getAllLogSrcs();
              existingTags.push(this.tagToAdd);
              this.dashboard.requiredLogSrcs.push({ logSrc: this.tagToAdd });
              this.specificLogSrcs.unshift(this.tagToAdd);
              this.tagToAdd = '';
            });
        }, 400);
    } else if (!normalizedNewTags.includes(this.tagToAdd.toLowerCase())) {
      this.specificLogSrcs.unshift(this.tagToAdd);
      this.tagToAdd = '';
    } else {
      alert('That tag already exists for this dashboard.');
      this.tagToAdd = '';
    }
  }
}

deleteTag(which) {
  let shouldDeleteFromDB = false;
  this.tagToDelete = this.specificLogSrcs[which];
  this.specificLogSrcs.splice(which, 1);

  let iterations = this.http.dashboardArray.length;
  let match = false;
  for (let i = 0; i < iterations; i++) {
    if (match) {
      break;
    }
    let currentDashboardLogSrcs = this.http.dashboardArray[i].requiredLogSrcs;
    console.log(currentDashboardLogSrcs);
    for (let j = 0; j < currentDashboardLogSrcs.length; j++) {
      if (match) {
        break;
      }
      let currentTagObject = currentDashboardLogSrcs[j];
      if (currentTagObject.locSrc === this.tagToDelete) {
        match = true;
      }
    }
    if (!match && i === iterations - 1) {
      shouldDeleteFromDB = true;
    }
  }
  if (shouldDeleteFromDB) {
    if (!window.confirm(`The tag you deleted doesn\'t exist anywhere else in our records and will be deleted permanently.\nClick "Cancel" to keep it as a suggestion.`)) {
      shouldDeleteFromDB = false;
    } else {
      this.logSrcsHttp.deleteLogSrc(this.tagToDelete)
        .then( () => {
          this.logSrcsHttp.getAllLogSrcs();
        });
      shouldDeleteFromDB = false;
    }
  }
}

validateDashboardName() {
  this.dashboardNameValid = true;
  this.http.dashboards.forEach(dashboardArray => {
    dashboardArray.forEach( dashboard => {
      if (this.dashboard.dashboardName.toLowerCase().trim() === dashboard.dashboardName.toLowerCase().trim()) {
        this.dashboardNameValid = false;
      }
    });
  });
}

validateDomain() {
  if (this.dashboard.domain) {
    this.domainValid = true;
  }
}

validateXML() {
  this.xmlValid = true;
  this.http.dashboards.forEach(dashboardArray => {
    dashboardArray.forEach( dashboard => {
      if (this.dashboard.dashboardXML.toLowerCase().trim() === dashboard.dashboardXML.toLowerCase().trim() && this.dashboard.dashboardXML !== '') {
        this.xmlValid = false;
      }
    });
  });
}

  postDashboard() {
    console.log(this.specificLogSrcs);
    this.specificLogSrcs.forEach(logsrc => {
      let logSrcObj = {
        logSrc: logsrc
      }
      this.dashboard.requiredLogSrcs.unshift(logSrcObj);
    });
    this.fetchingFromDB = true;
    // Call HTTP Service POST request method
    window.setTimeout( () => {
    this.http.createDashboard(this.dashboard)
            .then( () => {
              this.fetchingFromDB = false;
              this.http.getDashboards().then( response => {
                console.log('CREATE MODAL CALLING GET ALL DASHBOARDS: ', response);
                this.exitModal();
              });
            });
    }, 400);
  }

  transitionOpacity() {
    let styles = {
      'background-color': this.modals.create.displayed ? 'rgba(0, 0, 0, .4)' : 'rgba(0, 0, 0, 0)',
      'transition': 'background-color 3s'
    }
    return styles;
  }

  confirmModalExit() { // Checks if the object properties bound to the view are still empty
    function modalUntouched(boundObject) {
      let objProps = Object.getOwnPropertyNames(boundObject);
      for (let i = 0; i < objProps.length; i++) {
        let propName = objProps[i];
        if (boundObject[propName] && boundObject[propName][0]) {
          return false;
        }
      }
      return true;
    }
    console.log(this.dashboard);
    if (modalUntouched(this.dashboard)) {
      this.exitModal();
    } else {
      if (window.confirm('Your changes will not be saved. Exit anyway?')) {
        this.exitModal();
      }
    }
  }

  exitModal(): void {
    this.modals.create.displayed = false;
  }

  ngOnInit() {
    // INITIAL HTTP REQUEST
    this.logSrcsHttp.getAllLogSrcs().then( () => {
      this.logSrcs = this.logSrcsHttp.logSrcsArray;
    });
    // SUBSCRIBE COMPONENT TO CHANGES IN LOGSRCS ARRAY
    this.subscription = this.logSrcsHttp.cast.subscribe( logsrcs => {
      this.logSrcs = logsrcs;
    });
  }

  ngOnDestroy() {
    // Garbage collection, especially important in modal components!
    this.subscription ? this.subscription.unsubscribe() : null;
  }

}
