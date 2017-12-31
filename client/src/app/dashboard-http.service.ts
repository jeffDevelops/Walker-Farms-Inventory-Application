import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';

import { BehaviorSubject } from 'rxjs/BehaviorSubject'
import { Observable } from 'rxjs/Observable'
import 'rxjs/add/operator/toPromise';

import { environment } from '../environments/environment';

import { CreateDashboardComponent } from './create-dashboard/create-dashboard.component';

@Injectable()
export class DashboardHttpService {

  // HTTP properties
  private dashboardUrl = `${environment.apiUrl}/api/dashboards`;
  private headers = new HttpHeaders({'Content-Type': 'application/json'})

  // Dashboard array
  dashboardArray = [];

  //In-memory dashboard to edit/deleteUseCase
  specificDashboard;

  public refreshDashboards(newDashboards) {
    this.dashboards.next(newDashboards.reverse());
  }

  constructor(private httpClient: HttpClient) {}

  public dashboards = new BehaviorSubject<any[]>([]);
  cast = this.dashboards.asObservable();

  public getDashboards(): Promise<any[]> {
    return this.httpClient
      .get<any[]>(this.dashboardUrl)
      .toPromise()
      .then( response => {
        this.dashboardArray = [];
        response.forEach( dashboard => {
          this.dashboardArray.unshift(dashboard);
        });
        this.refreshDashboards(response);
        return response;
      }).catch(this.handleError);
  }

  public createDashboard(dashboard): Promise<any> {
    console.log(dashboard);
    return this.httpClient
    .post(this.dashboardUrl, JSON.stringify(dashboard), { headers: this.headers })
    .toPromise()
    .then( response => console.log(response))
    .catch(this.handleError);
  }

  public updateDashboard(dashboard): Promise<any> {
    console.log(dashboard);
    let url = `${this.dashboardUrl}/${dashboard._id}`;
    return this.httpClient
      .put<any>(url, JSON.stringify(dashboard), { headers: this.headers })
      .toPromise()
      .then( () => console.log(dashboard))
      .catch(this.handleError);
  }

  public deleteDashboard(dashboard): Promise<any> {
    let url = `${this.dashboardUrl}/${dashboard._id}`;
    return this.httpClient
      .delete<any>(url, { headers: this.headers })
      .toPromise()
      .then( response => console.log(response))
      .catch(this.handleError);
  }

  private handleError(error: any): Promise<any> {
    console.error('An error occurred', error);
    return Promise.reject(error.message || error);
  }

}
