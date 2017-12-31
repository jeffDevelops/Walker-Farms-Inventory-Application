import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders, HttpResponse } from '@angular/common/http';

import { BehaviorSubject } from 'rxjs/BehaviorSubject';
import { Observable } from 'rxjs/Observable';
import 'rxjs/add/operator/toPromise';

import { environment } from '../environments/environment';
import { UseCaseHttpService } from './use-case-http.service';

@Injectable()
export class LogSrcsHttpService {

  constructor(private httpClient: HttpClient) {}

  // Http properties
  private logSrcUrl = `${environment.apiUrl}/api/log_sources`;
  private headers = new HttpHeaders({'Content-Type': 'application/json'});

  // Log Sources array
  logSrcsArray = [];

  // In-memory log sources to edit/deleteUseCase
  logSrcsToUpdate = [];

  // Define a Behavior Subject for components to receive updates, and set to []
  public logSrcs = new BehaviorSubject<any[]>([]);
  cast = this.logSrcs.asObservable();
  // Refresh Log Srcs in components subscribed to the logSrcs Behavior Subject
  public refreshLogSrcs(newLogSrcs) {
    console.log(newLogSrcs);
    this.logSrcs.next(newLogSrcs.reverse());
  }

  public getAllLogSrcs(): Promise<any[]> {
    this.logSrcsArray = [];
    return this.httpClient
      .get<any[]>(this.logSrcUrl, { headers: this.headers })
      .toPromise()
      .then( response => {
        console.log('GET ALL LOG SOURCES: ', response);
        response.forEach(logsrc => {
          // Push the actual value we need since every object in the response is a Mongoose doc with an id, etc.
          this.logSrcsArray.push(logsrc.logSrc);
        });
        this.refreshLogSrcs(this.logSrcsArray);
        return response;
      }).catch(this.handleError);
  }

  public createLogSrc(string): Promise<any> {
    // package the incoming string as an object to pass to the API with the key name from the schema
    console.log(string);
    let logSrc = {
      logSrc: string
    };
    return this.httpClient
      .post(this.logSrcUrl, JSON.stringify(logSrc), { headers: this.headers })
      .toPromise()
      .then( response => console.log(response))
      .catch(this.handleError);
  }

  public deleteLogSrc(string): Promise<any> {
    console.log('DELETE CALLED');
    console.log(string);
    let url = `${this.logSrcUrl}/${string}`;
    console.log(url);
    return this.httpClient
      .delete<any>(url, { headers: this.headers })
      .toPromise()
      .then( response => console.log(response))
      .catch(this.handleError);
  }

  private handleError(error: any): Promise<any> {
    console.log('An error occurred: ', error);
    return Promise.reject(error.message || error);
  }

}
