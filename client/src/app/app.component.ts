import { Component, OnInit, HostListener } from '@angular/core';

import { trigger, state, style, animate, transition } from '@angular/animations';

import { DashboardIndexComponent } from './dashboard-index/dashboard-index.component';
import { UseCaseIndexComponent } from './use-case-index/use-case-index.component';

import { ModalService } from './modal.service';


@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.scss'],
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
  ]
})
export class AppComponent implements OnInit {

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
    console.log(this.checkIfActive('/'));
    console.log(this.checkIfActive('/dashboards'));
    if (window.innerWidth <= 863) {
      this.navState = 'fullHeight';
      this.active = {
        'background-color': '#bfbfbf',
        'border-top': 'none',
        'color': '#404040'
      };
      this.inactive = {
        'background-color': 'transparent',
        'border-top': 'none',
        'color': '#657883'
      }
    } else {
      if (window.pageYOffset > 0) {
        this.navState = 'collapsed';
      } else {
        this.navState = 'fullHeight';
      }
      this.active = {
        'background-color': 'transparent',
        'border-top': '3px solid #2C7A2E',
        'color': '#657883'
      };
      this.inactive = {
        'background-color': 'transparent',
        'border-top': '3px solid transparent',
        'color': '#657883'
      }
    }
  }

  constructor(private modals: ModalService) {}

  // Navigation Scroll state
  navState = 'fullHeight';

  // Navigation properties (determine whether link is active)
  active;
  inactive;
  pathname = window.location.pathname;

  toggleModalStyles() {
    let styles = {
      'filter': this.modals.edit.displayed || this.modals.create.displayed || this.modals.view.displayed ? 'blur(2px)' : 'blur(0px)',
      'overflow': this.modals.edit.displayed || this.modals.create.displayed || this.modals.view.displayed ? 'hidden' : 'auto',
      'transition': 'filter 1s, overflow 1s'
    };
    if (this.modals.create.displayed || this.modals.edit.displayed || this.modals.view.displayed) {
      document.body.style.overflow = 'hidden'; // I'm sure this is resolutely frowned-upon
    }
    return styles;
  }

  checkIfActive(path) {
    if (path == window.location.pathname) {
      return this.active;
    } else {
      return this.inactive;
    }
  }

  ngOnInit() {
    // Check window width and set active states accordingly
    if (window.innerWidth > 863) {
      this.active = { 
        'border-top':'2px solid #2C7A2E',
        'background-color': 'transparent',
        'color': '#2C7A2E'
      };
      this.inactive = { 
        'border-top': '2px solid transparent',
        'background-color': 'transparent',
        'color': '#2C7A2E'
      };
    } else {
      this.active = {
        'background-color': '#bfbfbf',
        'border-top': 'none',
        'color': '#333'
      };
      this.inactive = {
        'background-color': 'transparent',
        'border-top': 'none',
        'color': '#333'
      }
    }
  }

}


