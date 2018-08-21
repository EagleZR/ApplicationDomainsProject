import React, {Component} from 'react';
import {firebaseApp} from '../firebase'

class SignUp extends Component {
  constructor(props) {
    super(props);
    this.state = {
      email: '',
      password: ''
    }
  }

  signUp() {
    console.log('this.state', this.state);
    const {email, password} = this.state;
    firebaseApp.auth().createUserWithEmailAndPassword(email, password).catch(error => {
      console.log('error', error)
    })
  }

  render() {

    return (<div class="center_div">
      <div className="form-inline">
        <h2>Sign Up</h2>
        <div class="form-horizontal">
          <div class="form-group">
            <div class="col-md-6">
              <input className="form-control" type="text" placeholder="email" onChange={event => this.setState({email: event.target.value})}/>
              <input className="form-control" type="password" placeholder="password" onChange={event => this.setState({password: event.target.value})}/>
              <button className="button button_sign_up" type="button" onClick={() => this.signUp()}>Sign Up</button>
            </div>
          </div>
        </div>
      </div>
    </div>)
  }
}

export default SignUp;
