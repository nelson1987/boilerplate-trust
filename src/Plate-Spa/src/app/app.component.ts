import { Component } from '@angular/core';
import { RouterOutlet } from '@angular/router';
import { BookService } from './_services/book.service';
import { CategoryService } from './_services/category.service';
import { ConfirmationDialogService } from './_services/confirmation-dialog.service';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [RouterOutlet, BookService, CategoryService, ConfirmationDialogService],
  templateUrl: './app.component.html',
  styleUrl: './app.component.css'
})
export class AppComponent {
  title = 'Plate-Spa';
}
