import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders, HttpResponse } from '@angular/common/http';

import { BehaviorSubject } from 'rxjs/BehaviorSubject';
import { Observable } from 'rxjs/Observable';
import 'rxjs/add/operator/toPromise';

import { environment } from '../environments/environment';

@Injectable()
export class UseCaseHttpService {

  constructor(private httpClient: HttpClient) {}

  // Http properties
  private useCaseUrl = `${environment.apiUrl}/api/use_cases`;
  private headers = new HttpHeaders({'Content-Type': 'application/json'});

  // Usecase array
  useCaseArray = [];

  // In-memory usecase to edit/delete
  specificUseCase;

  // Define a Behavior Subject for components to receive updates, and set to []
  public useCases = new BehaviorSubject<any[]>([]);
  cast = this.useCases.asObservable();

  // Refresh Use Cases in components subscribed to the useCases Behavior Subject
  public refreshUseCases(newUseCases) {
    this.useCases.next(newUseCases.reverse());
  }

  // HTTP Requests
  public getUseCases(): Promise<any[]> {
    return this.httpClient
      .get<any[]>(this.useCaseUrl, {headers: this.headers})
      .toPromise()
      .then( response => {
        this.useCaseArray = [];
        response.forEach( useCase => {
          this.useCaseArray.unshift(useCase);
        });
        this.refreshUseCases(response);
        return response;
      }).catch(this.handleError);
  }

  public createUseCase(usecase): Promise<any> {
    return this.httpClient
      .post(this.useCaseUrl, JSON.stringify(usecase), { headers: this.headers })
      .toPromise()
      .then( response => console.log(response))
      .catch(this.handleError);
  }

  public updateUseCase(usecase): Promise<any> {
    console.log('UPDATE CALLED: ', usecase);
    let url = `${this.useCaseUrl}/${usecase._id}`;
    return this.httpClient
      .put<any>(url, JSON.stringify(usecase), { headers: this.headers })
      .toPromise()
      .then( () => console.log(url))
      .catch(this.handleError);
  }

  public deleteUseCase(usecase): Promise<any> {
    let url = `${this.useCaseUrl}/${usecase._id}`;
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
