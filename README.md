# Film Fanatic
## Introduction
The purpose of this website is for people to see other peoples reviews of films. But also for users to be able to add their own reviews to films. The site is aimed at people who often watch films and want to find films to watch and see what others have said about them. If there is a new film not on the website users will be able to add it. 


![Mock up image](documentation/mock-up.jpg)

## Features 
* Navigation bar
    * A simple navigation bar is at the top of the page for users to easily go through. 

![Navigation bar](documentation/)

* Home page
    * The home page is very simple if the user is not logged in it will show a login or register button.
    * If the user is logged in it will show a log out button. 

![Home page](documentation/home-page.jpg)

* Login page
    * The login page will have a panel for users to input their username and password and a login button.

![Login page](documentation/)

* Register page
    * The register page is similar to the login page but has register button instead. 

![Register page](documentation/)

* Films page
    * This is the main page of the website where all the films are displayed with a dropdown button for users to see the reviews of that film selected. 
    * There is also an option for the user to add a review or edit one of their previous reviews.
    * At the top of the page there is a search bar so users can find a film.
    
![Films page](documentation/)

* Add film 
    * This page users can add new films that are not already on the website. 

![Add film](documentation/)

* Edit film
    * A user can edit a film they previously added on this page. 

![Edit film](documentation/)

* Add review 
    * A form for users to add they're own review to a film.

![Add review](documentation/)

* Edit review
    * A user can change or edit they're review if they decide to. 

![Edit Review](documentation/)


## User Experience

### First time visitors
* As a first time visitor I want to see the films.
* I want to be able to see what people have said about certain films.
* I want to be able to create my own account so I can review films in the future.

### Second time visitors
* As a second time visitor I want to be able to log into my account.
* I want to be able to review a film I have watched.
* If the film I watched isn't on the website I want to be able to add it. 



### Design Choices
* Colour Scheme
    * The two main colours used on this website are #e98b72 which is an orange colour and #eed195 which is a yellow colour. These colours were chosen to add a fun and proffessional look on top of a dark background. 
    
* Typography
    * The font used was Roboto, with sans-serif set as a back up font. Roboto was used as it has an easy readibility and has a clean and modern design.
* Imagery
    * The background image used was taken from unsplash, linked below in the acknowledgements section. 



    
### Flow chart
* Here is my flowchart for adding films and reviews

![Flow chart](documentation/)

### Wireframes
* All wireframes were created using Balsamiq wireframes, all designs for desktop, tablet and mobile are linked [here]!(documentation/wireframes/)

### Testing
#### Functional Testing
* Creating a user
    * This works as it should. A user can be created if the username does not already exist. 
    * When created the user is shown a welcome message and directed to the films page.
* Logging in as user 
    * Similarly to register the user is shown a welcome message and directed to the films page.
    * If the username or password was wrong or does not exist the user is shown an incorrect password or username message. 
* Logging out
    * The log out button is clicked and the user is logged out and taken back to the login page. 
    * The user is also flashed a you have been logged out message. 
* Add review
    * The add review button is clicked and the user is taken to the add review page.
    * Username and film name is automatically rendered.
    * The user can leave a review and a rating score.
    * Once submitted the user is taken back to the films page and their review will appear on the corresponding film they added it to. 
* Edit review
    * If the user is the creater of the review they are given the option to edit it.
    * Click edit review takes them to the edit review page.
    * When submitted their review updates. 
    * Message shown saying their review is updated. 
* Delete review
    * When clicked the users review is deleted.
    * Also shown a message to say that their review has been deleted. 
* Add film 
    * Add film button takes user to add film page.
    * Form for adding films is displayed with the users name automatically rendering. 
    * User can fill out form, but can't submit it unless all fields are filled in. 
    * When submitted the film is then displayed on the films page. 
* Edit film 
    * Only displayed if user is the creator of the film. 
    * All inputs are automaically rendered in the form. 
    * When edited they are then displayed a your film has been edited message. 
* Delete film
    * Only displayed for the film creator
    * Once clicked the user is displayed a film deleted message. 
* Search bar
    * If a film exists it is shown by searching for it.
    * If it doesnt exist it will show no results found and will shows a button to add their film.
* Navbar testing
    * All navbar links take the user to the correct place, on both small and large screens. 

### Validator testing
* PEP 8 Online
    * This validator Service was used to validate the python file in the project to ensure there were no syntax errors in the project. The results were all clear as shown below. 
    <details>
        <summary>PEP 8</summary>
        ![PEP 8](documentation/readme/pep8-validation.jpg "PEP8")
    </details>

* The W3C CSS validator and the W3C Markup Validator were used to validate every page of the project to make sure there were no syntax errors.
* [W3C CSS Validator](https://jigsaw.w3.org/css-validator/#validate_by_input) [Result](documentation/readme/css-valid.jpg)
* [W3C Markup Validator](https://validator.w3.org/) - Results for each page are below
        * [Home page](documentation/readme/homepage-validation.jpg)
        * [Films page](documentation/readme/films-validation.jpg)
        * [Add film](documentation/readme/add-film-validation.jpg)
        * [Edit film]()
        * [Add review]()
        * [Edit review]()
        * [Login]()
        * [Register]()


### Testing User Stories

* First time visitor goals
    

* Second time visitor goals
    

* Future visitor goals
    
### Further testing 

### Manual Javascript testing

## Bugs Found
* A bug found whilst working on the website is that when trying to delete a review on a film it would delete the film as well. To overcome this I imported UUID to be able to generate unique id's for each review so they could be deleted that way. I used stack overflow to help me understand this.


## Deployment 
* This site was deployed to Heroku here are the steps:
   

## Credits
### Image Credits
* Background image https://unsplash.com/photos/a-black-background-with-a-white-border-m6OzmW0GrPk 

### Resources used
* I used this website https://devoriales.com/post/323/how-to-implement-pagination-in-your-flask-application to help me with the use of pagination.




### Acknowledgements
* I would like to thanks my mentor Okwudiri Okoro for their support.
* Also thank you to the slack community. 
* Icons were taken from <https://fontawesome.com/>
* Font was from <https://fonts.google.com/>
