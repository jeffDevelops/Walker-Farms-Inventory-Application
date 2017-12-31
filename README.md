# vSOC Content Library

This repository contains the directory for the vSOC Content Library application.

## About
### Client-Side: Angular
The Content Library frontend runs on Angular 5, and can found in the `client` directory. The application persists two types of resources--dashboards and use-cases (SPL queries). The dev code (i.e., before it is built) can be found in `client/src/app`, and you'll see that all services and components are organized by the resource they operate on. Further organization of this directory, and possibly organization into separate modules, could be a welcome change.

The `app` component serves as a container, but also features the nav that routes between the two index components that display the two resources. This nav checks the value of the url path to determine which component is active.

```
|-app
|-- <resource>-index.component
      |-- create-<resource>.component
      |-- edit-<resource>.component
```

Each resource has its own index component, which, on init, calls a GET method in that resource's HTTP service. This HTTP service for each resource serves as a singleton for the response data from the content-library's API, via an Rxjs BehaviorSubject. As a result, the array received from the API may be synced between any component that imports the service and subscribes to the BehaviorSubject.

See the Installations and Running Locally sections below to run the client-side on your machine.

### Server-Side: Node, Express, MongoDB
The Content Library backend uses the Node runtime, Express routing, and MongoDB to persist data. The Mongoose ORM allows Node to interface with the database. Model definitions can be found in the `models` directory; they are bundled as an exported object in that directory's index file. Much like on the front end, the routes (`api` directory) and controllers (`controllers`), are split by resource for organization's sake.

See the sections below for spinning up the dev server on your local machine.

## Installations
To run the app locally, run the following commands:

Check whether you have Node installed on your machine with `which node` or `node -v`

If not, you will need it to install dependencies. If so, skip to Angular installation below.

### Homebrew and Node
Install Homebrew:
```
/usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
```
Check for Homebrew updates:
```
brew update
```
It's not crucial, but the following command could reveal whether Homebrew has recommendations for your system configuration (for my machine, it revealed that the location of my Python installation could interfere with other Homebrew software installs in the future):
```
brew doctor
```
Add Homebrew's location to your $PATH in your Bash profile:
```
export PATH="/usr/local/bin:$PATH"
```
Install Node:
```
brew install node
```
Test that Node's installation worked by using the Node Package Manager (npm) to install Nodemon (hot reloading that listens for saved changes):
```
npm install -g nodemon
```
### Angular
Globally install the Angular CLI for hot-reloading and serving up the front-end:
```
npm install -g @angular/cli
```

Once Angular is installed, `cd` into the client-side directory (AWS-Test-App), and run:
```
npm install
```
`cd` into the server-side directory (server) and do the same for backend dependencies.

## Running Locally
The command `ng serve -open` from the client side directory serves and hot-reloads the frontend on `localhost:4200`, and the command `nodemon server.js` from the server directory serves and hot-reloads the backend/API from `localhost:3000`.

## Collaborators
Patrick Orzechowski, Rett Behrens, Jeremy Verdolino, Jeff Reynolds

hi mom
