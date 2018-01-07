import { Component, OnInit, AfterViewInit, OnDestroy, HostListener, ViewChild, ElementRef } from '@angular/core';
import { trigger, state, style, animate, transition } from '@angular/animations';

import { Observable } from 'rxjs/Observable';
import { Subscription } from 'rxjs/Subscription';

import { DashboardHttpService } from '../dashboard-http.service';
import { LogSrcsHttpService } from '../log-srcs-http.service';
import { ModalService } from '../modal.service';

import { Angular2Csv } from 'angular2-csv/Angular2-csv';

@Component({
  selector: 'app-dashboard-index',
  templateUrl: './dashboard-index.component.html',
  styleUrls: ['./dashboard-index.component.scss'],
  animations: [
    trigger('navState', [
      state('fullHeight', style({
        transform: 'translateY(0)'
      })),
      state('collapsed', style({
        transform: 'translateY(-125px)'
      })),
      transition('collapsed <=> fullHeight', animate('500ms ease-out'))
    ])
  ],
})
export class DashboardIndexComponent implements OnInit {

  // Scroll detection for navbar
  @HostListener('window:scroll', [])
  onWindowScroll() {
    if (window.innerWidth > 863) {
      if (window.pageYOffset > 0) {
        this.navState = 'collapsed';
      } else {
        this.navState = 'fullHeight';
      }
    } else {
      this.navState = 'fullHeight';
    }
  }

  @HostListener('window:resize', [])
  onWindowResize() {
    if (window.innerWidth < 864) {
      this.menuExpanded = false;
      this.navState = 'fullHeight';
    } else {
      this.menuExpanded = true;
      if (window.pageYOffset > 0) {
        this.navState = 'collapsed';
      } else {
        this.navState = 'fullHeight';
      }
    }
  }

  @ViewChild('expandedFilter') expandedFilter: ElementRef;

  constructor(
    public http: DashboardHttpService,
    public logSrcHttp: LogSrcsHttpService,
    public modals: ModalService
  ) { }

  viewInitialized: boolean = false;

  navState = 'fullHeight'; // Navigation animation
  menuExpanded: boolean;

  // GET ALL DASHBOARDS
  subscription: Subscription;
  logSrcsSubscription: Subscription;
  logSrcObjects: Array<any> = []; // Populates the logSrcs filter, e.g. { logSrc: 'Wineventlog', selected: false }
  logSrcs: Array<any> = []; // Master copy (don't mutate)
  dashboards: Array<any> = []; // Master copy (Don't mutate this array)
  displayedDashboards: Array<any> = []; // Mutable copy
  displayedLogSrcs: Array<any> = []; // Mutable copy

  // FILTER (LOGSRCS)
  filterExpanded: boolean = false;
  closedFromBlur: boolean = false;
  logSrcSelected: boolean = false;
  selectedLogSrcs: Array<any> = [];
  logSrcFilterEngaged: boolean = false;
  logSrcFilterResults: Array<any> = [];

  // FILTER (SEARCH)
  term: string;
  searchFilterEngaged: boolean = false;
  searchFilterResults: Array<any> = [];

  // FILTER (DOMAIN)
  selected = null;
  domainFilterEngaged: boolean = false;
  domainFilterResults: Array<any> = [];
  domains: Array<string> = [
    'Lorem',
    'Ipsum',
    'Dolor',
    'Sit',
    'Amet',
    'Consectetur',
    'Adipicising',
    'Elit',
    'Nulla',
    'Sodales',
    'All'
  ];


  // LOGSRCS FILTER
  closeLogSrcFilter(event) {
    this.filterExpanded = false;
    console.log(this.filterExpanded);
  }

  toggleLogSrcFilter(event) {
    this.filterExpanded = true;
    if (this.filterExpanded && this.viewInitialized) {
      setTimeout( () => this.expandedFilter.nativeElement.focus(), 1);
    }
  }

  toggleLogSrcSelection(which) {
    this.logSrcObjects[which].selected = !this.logSrcObjects[which].selected;
    // If LogSrc is selected, pass it to selected array
    if (this.logSrcObjects[which].selected) {
      this.selectedLogSrcs.push(this.logSrcObjects[which].logSrc);
    // If not, remove it
    } else {
      let indexToRemove = this.selectedLogSrcs.indexOf(this.logSrcObjects[which].logSrc);
      this.selectedLogSrcs.splice(indexToRemove, 1);
    }
    if(this.selectedLogSrcs.length > 0) {
      this.logSrcFilterEngaged = true;
      this.filterByLogSrcs(this.selectedLogSrcs);
    } else {
      this.logSrcFilterEngaged = false;
      this.logSrcFilterResults = [];
      if (!this.domainFilterEngaged && !this.searchFilterEngaged) {
        this.displayedDashboards = this.dashboards;
      } else if (this.domainFilterEngaged && !this.searchFilterEngaged) {
        this.getDomainFilterResults(this.dashboards, this.selected);
      } else if (this.searchFilterEngaged && !this.domainFilterEngaged) {
        this.getSearchResults(this.dashboards);
      } else if (this.searchFilterEngaged && this.domainFilterEngaged) {
        let combinedFilterResults = [];
        this.domainFilterResults.forEach(domainFilterResult => {
          this.searchFilterResults.forEach(searchFilterResult => {
            if (searchFilterResult.dashboard === domainFilterResult.dashboard) {
              combinedFilterResults.push(domainFilterResult);
            }
          });
        });
        this.displayedDashboards = combinedFilterResults.slice(0);
      }
    }
  }

  filterByLogSrcs(selections) {
    this.logSrcFilterResults = [];
    if (!this.searchFilterEngaged && !this.domainFilterEngaged) {
      this.displayedDashboards = this.dashboards.slice(0);
      this.getLogSrcFilterResults(this.displayedDashboards, selections);
    } else if (this.searchFilterEngaged && !this.domainFilterEngaged) {
      this.getSearchResults(this.dashboards);
      this.getLogSrcFilterResults(this.searchFilterResults, selections);
    } else if (this.domainFilterEngaged && !this.searchFilterEngaged) {
      this.getDomainFilterResults(this.dashboards, this.selected);
      this.getLogSrcFilterResults(this.domainFilterResults, selections);
    } else if (this.domainFilterEngaged && this.searchFilterEngaged) {
      let combinedFilterResults = [];
      this.domainFilterResults.forEach(domainFilterResult => {
        this.searchFilterResults.forEach(searchFilterResult => {
          if (searchFilterResult.dashboard === domainFilterResult.dashboard) {
            combinedFilterResults.push(domainFilterResult);
          }
        });
      });
      this.getLogSrcFilterResults(combinedFilterResults, selections);
    }
  }

  getLogSrcFilterResults(pool, selections) {
    this.logSrcFilterResults = [];
    for (let i = 0; i < pool.length; i++) {
      logSrcs: for (let j = 0; j < pool[i].requiredLogSrcs.length; j++) {
        for (let k = 0; k < selections.length; k++) {
          if (selections[k] === pool[i].requiredLogSrcs[j].logSrc) {
            this.logSrcFilterResults.push(pool[i]);
            break logSrcs;
          }
        }
      }
    }
    this.displayedDashboards = this.logSrcFilterResults.slice(0);
  }

  // DOMAIN FILTER
  onSelect(selected) {
    this.domainFilterResults = [];
    if (selected === 'All' || selected === null) {
      this.domainFilterEngaged = false;
      if (!this.logSrcFilterEngaged && !this.searchFilterEngaged) {
        this.displayedDashboards = this.dashboards.slice(0);
      } else if (this.logSrcFilterEngaged && !this.searchFilterEngaged) {
        this.getLogSrcFilterResults(this.dashboards, this.selectedLogSrcs);
      } else if (this.searchFilterEngaged && !this.logSrcFilterEngaged) {
        this.getSearchResults(this.dashboards);
      } else if (this.searchFilterEngaged && this.logSrcFilterEngaged) {
        let combinedFilterResults = [];
        this.logSrcFilterResults.forEach(logSrcFilterResult => {
          this.searchFilterResults.forEach(searchFilterResult => {
            if (searchFilterResult.dashboard === logSrcFilterResult.dashboard) {
              combinedFilterResults.push(logSrcFilterResult);
            }
          });
        });
        this.displayedDashboards = combinedFilterResults.slice(0);
        combinedFilterResults = [];
      }
    } else {
      this.displayedDashboards = this.dashboards.slice(0);
      this.domainFilterEngaged = true;
      if (!this.searchFilterEngaged && !this.logSrcFilterEngaged) {
        this.getDomainFilterResults(this.displayedDashboards, selected);
      } else if (this.logSrcFilterEngaged && !this.searchFilterEngaged) {
        console.log(this.logSrcFilterResults);
        this.getLogSrcFilterResults(this.dashboards, this.selectedLogSrcs);
        this.getDomainFilterResults(this.logSrcFilterResults, selected);
      } else if (this.searchFilterEngaged && !this.logSrcFilterEngaged) {
        this.getSearchResults(this.dashboards);
        this.getDomainFilterResults(this.searchFilterResults, selected);
      } else if (this.searchFilterEngaged && this.logSrcFilterEngaged) {
        let combinedFilterResults = [];
        this.logSrcFilterResults.forEach(logSrcFilterResult => {
          this.searchFilterResults.forEach(searchFilterResult => {
            if (searchFilterResult.dashboard === logSrcFilterResult.dashboard) {
              combinedFilterResults.push(logSrcFilterResult);
            }
          });
        });
        this.getDomainFilterResults(combinedFilterResults, selected);
      }
    }
  }

  getDomainFilterResults(pool, selected) {
    this.domainFilterResults = [];
    pool.forEach(dashboard => {
      if (dashboard.domain === selected) {
        this.domainFilterResults.push(dashboard);
      }
    });
    this.displayedDashboards = this.domainFilterResults;
  }

  // Search FILTER
  onSearch() {
    if (!this.term) {
      this.searchFilterEngaged = false;
      this.searchFilterResults = [];
      if (!this.domainFilterEngaged && !this.logSrcFilterEngaged) {
        this.displayedDashboards = this.dashboards;
      } else if (this.domainFilterEngaged && !this.logSrcFilterEngaged) {
        this.getDomainFilterResults(this.dashboards, this.selected);
      } else if (this.logSrcFilterEngaged && !this.domainFilterEngaged) {
        this.getLogSrcFilterResults(this.dashboards, this.selectedLogSrcs);
      } else if (this.logSrcFilterEngaged && this.domainFilterEngaged) {
        this.getLogSrcFilterResults(this.dashboards, this.selectedLogSrcs);
        this.getDomainFilterResults(this.displayedDashboards, this.selected);
        // let combinedFilterResults = [];
        // this.domainFilterResults.forEach(domainFilterResult => {
        //   this.logSrcFilterResults.forEach(logSrcFilterResult => {
        //     if (logSrcFilterResult.dashboard === domainFilterResult.dashboard) {
        //       combinedFilterResults.push(domainFilterResult);
        //     }
        //   });
        // });
        // this.displayedDashboards = combinedFilterResults.slice(0);
      }
    } else {
      this.displayedDashboards = this.dashboards;
      this.searchFilterEngaged = true;
      // Determine the initial pool of resources to enact the filter on, but don't worry about it's empty
      if (!this.logSrcFilterEngaged && !this.domainFilterEngaged) {
        this.getSearchResults(this.displayedDashboards);
      } else if (this.logSrcFilterEngaged && !this.domainFilterEngaged) {
        this.getSearchResults(this.logSrcFilterResults);
      } else if (this.domainFilterEngaged && !this.logSrcFilterEngaged) {
        this.getSearchResults(this.domainFilterResults);
      } else if (this.domainFilterEngaged && this.logSrcFilterEngaged) {
        let combinedFilterResults = [];
        this.logSrcFilterResults.forEach(logSrcFilterResult => {
          this.domainFilterResults.forEach(domainFilterResult => {
            if (domainFilterResult.dashboard === logSrcFilterResult.dashboard) {
              combinedFilterResults.push(logSrcFilterResult);
            }
          });
        });
        this.getSearchResults(combinedFilterResults);
      }
    }
  }

  getSearchResults(pool) {
    console.log('SEARCHTERM: ', this.term);
    this.searchFilterResults = [];
    let isMatch = false;
    let normalizedTerm = this.term.toLowerCase();
    pool.forEach( dashboard => {
      // iterate through object properties
      let dashboardProps = Object.getOwnPropertyNames(dashboard);
      dashboardProps.forEach( property => {
        //don't search the MongoDB-added properties
        if (property !== '__v' && property !== '_id') {
        // if property is a string
          if (typeof(dashboard[property]) === 'string') {
            let normalizedProperty = dashboard[property].toLowerCase();
            // see if value of search box exists in that string
            if (normalizedProperty.includes(normalizedTerm)) {
              isMatch = true;
            }
          }
          // if property is an array
          if (Array.isArray(dashboard[property])) {
            let logSources = dashboard[property];
            logSources.forEach(logsrc => {
              let normalizedLogSrcName = logsrc.logSrc.toLowerCase();
              if (normalizedLogSrcName.includes(normalizedTerm)) {
                isMatch = true;
              }
            });
          }
        }
      });
      if (isMatch) {
        this.searchFilterResults.push(dashboard);
        isMatch = false;
      }
    });
    this.displayedDashboards = this.searchFilterResults.slice(0);
  }

  // Modals
  toggleCreate() {
    this.modals.create.displayed = !this.modals.create.displayed;
  }

  toggleEdit(whichDashboard) {
    // Populate data
    this.http.specificDashboard = this.displayedDashboards[whichDashboard];
    console.log(this.http.specificDashboard);
    // Call modal
    this.modals.edit.displayed = !this.modals.edit.displayed;
  }

  toggleXML(whichDashboard) {
    this.http.specificDashboard = this.displayedDashboards[whichDashboard];
    this.modals.view.displayed = !this.modals.view.displayed;
  }

  setStyles() {
    let styles = {
      'filter': this.modals.create.displayed || this.modals.edit.displayed || this.modals.view.displayed ? 'blur(2px)' : 'blur(0px)',
      'overflow': this.modals.create.displayed || this.modals.edit.displayed || this.modals.view.displayed ? 'hidden' : 'auto',
      'transition': 'filter 1s, overflow 1s'
    };
    this.modals.toggleScrollUnderModal();
    return styles;
  }

  // DOWNLOAD CSV
  download() {
    let csvDashboards = [];
    this.displayedDashboards.forEach(dashboard => {
      let stringAccumulator = '';
      console.log(dashboard.dashboardName);
      let logSrcArray = dashboard.requiredLogSrcs;
      for(let i = 0; i < logSrcArray.length; i++) {
        console.log(logSrcArray[i]);
        if (i === logSrcArray.length - 1) {``
          stringAccumulator += logSrcArray[i].logSrc;
        } else {
          stringAccumulator += logSrcArray[i].logSrc + ', ';
        }
      }
      let newObj = {};
      Object.defineProperty(newObj, 'dashboard', { value: dashboard.dashboardName, configurable: true, enumerable: true, writable: true });
      Object.defineProperty(newObj, 'domain', { value: dashboard.domain, configurable: true, enumerable: true, writable: true });
      Object.defineProperty(newObj, 'xml', { value: dashboard.dashboardXML, configurable: true, enumerable: true, writable: true });
      Object.defineProperty(newObj, 'requiredLogSrcs', { value: stringAccumulator, configurable: true, enumerable: true, writable: true });
      Object.defineProperty(newObj, 'comments', {  value: dashboard.comments, configurable: true, enumerable: true, writable: true });
      console.log(newObj);
      csvDashboards.push(newObj);
      console.log('\n \n');
    });
    console.log(csvDashboards);
    var options = {
      fieldSeparator: ',',
      quoteStrings: '"',
      decimalseparator: '.',
      showLabels: true,
      showTitle: false,
      headers: ['DASHBOARD NAME', 'DOMAIN', 'XML', 'REQD LOG SOURCES', 'COMMENTS'] //NEED TO ADD REQD LOG SOURCES
    };
      new Angular2Csv(csvDashboards, 'Dashboards', options);
  }

  toggleMenu() {
    this.menuExpanded = !this.menuExpanded;
  }

  setMenuStyles() {
    let menuStyle = { 'display': this.menuExpanded ? 'block' : 'none' };
    return menuStyle;
  }

  compensateForMenu() {
    let filterResultsStyle = { 'margin-top': this.menuExpanded && window.innerWidth < 864 ? '150px' : '0' };
    return filterResultsStyle;
  }

  // Lifecycle Hooks
  ngOnInit() {
    //Navbar STATE
    if (window.pageYOffset > 0) {
      this.navState = 'collapsed';
    } else {
      this.navState = 'fullHeight';
    }

     // MENU STATE
     if (window.innerWidth > 863) {
      this.menuExpanded = true;
    } else {
      this.menuExpanded = false;
    }

    // INITIAL HTTP GET REQUEST FOR DASHBOARDS
    this.http.getDashboards().then( response => {
      this.dashboards = this.http.dashboardArray;
      // Displayed dashboards stored in different place in memory
      this.displayedDashboards = this.dashboards.slice(0);
    });
    // SUBSCRIBE COMPONENT TO CHANGES IN DASHBOARDS ARRAY
    this.subscription = this.http.cast.subscribe( dashboards => {
      this.displayedDashboards = [];
      this.dashboards = dashboards;
      this.term ="";
      this.dashboards.forEach( dashboard => {
        // check filter selection before rendering anything
        if (dashboard.domain === this.selected) {
          this.displayedDashboards.push(dashboard);
        // if no filter selection, display all
        } else if (this.selected === 'All' || !this.selected) {
          this.displayedDashboards.push(dashboard);
        }
      });
    });
    // INITIAL HTTP GET REQUEST FOR LOG SRCS
    this.logSrcHttp.getAllLogSrcs().then( () => {
      this.logSrcs = this.logSrcHttp.logSrcsArray;
    });
    // SUBSCRIBE COMPONENT TO CHANGES IN LOGSRCS ARRAY
    this.logSrcsSubscription = this.logSrcHttp.cast.subscribe( logsrcs => {
      this.logSrcs = logsrcs;
      this.displayedLogSrcs = [];
      this.logSrcObjects = [];
      logsrcs.forEach(logsrc => {
        let object = {};
        Object.defineProperty(object, 'logSrc', { value: logsrc });
        Object.defineProperty(object, 'selected', { value: false, writable: true });
        this.logSrcObjects.unshift(object);
      });
    });
  }

  ngAfterViewInit() {
    this.viewInitialized = true;
  }

  ngOnDestroy() {
    // Garbage collection
    this.subscription ? this.subscription.unsubscribe() : null;
    this.logSrcsSubscription ? this.subscription.unsubscribe() : null;
  }

}
