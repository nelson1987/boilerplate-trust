import { NgModule } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';
import { AppComponent } from './app.component';
import { BrowserAnimationsModule } from '@angular/platform-browser/animations';

import { MatDialogModule} from '@angular/material/dialog';
@NgModule({

  imports: [
    BrowserModule,
    BrowserAnimationsModule,
    [MatDialogModule]
  ],
  providers:[],
  declarations: [ AppComponent ],
  bootstrap: [ AppComponent ]
})
export class AppModule { }