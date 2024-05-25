import { Component, OnInit } from '@angular/core';
import { RouterOutlet } from '@angular/router';
import { MatDialog } from '@angular/material/dialog';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [RouterOutlet ],
  templateUrl: './app.component.html',
  styleUrl: './app.component.css'
})
export class AppComponent {
  title = 'plateApp';
  constructor(public dialog: MatDialog){

  }
   openDialog(){
    console.log(this);
  // const dialogRef = this.dialog.(AppComponent,{innerHeight:'350px'

  // });
  // dialogRef.afterClosed().subscribe(result => {
  //   console.log('Dialog result: ${result}');
  // });
  }
}
