import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { EditUseCaseComponent } from './edit-use-case.component';

describe('EditUseCaseComponent', () => {
  let component: EditUseCaseComponent;
  let fixture: ComponentFixture<EditUseCaseComponent>;

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [ EditUseCaseComponent ]
    })
    .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(EditUseCaseComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
