import React from 'react';
import ReactDOM from 'react-dom';
import App from './components/App';
import SignIn from './components/SignIn';
import SignUp from './components/SignUp';
import {BrowserRouter, Route} from 'react-router-dom';
import {firebaseApp} from './firebase'

firebaseApp.auth().onAuthStateChanged(user => {
  if (user) {
    console.log('User has signed in or up', user);
  } else {
    console.log('user has signed out');
  }
})

ReactDOM.render(<BrowserRouter>
  <div>
    <Route exact={true} path='/' component={App}/>
    <Route path="/signin" component={SignIn}/>
    <Route path="/signup" component={SignUp}/>
  </div>
</BrowserRouter>, document.getElementById('root'))