#!/usr/bin/env python3

from flask import Flask, request, session, jsonify
from flask_restful import Resource, Api
from sqlalchemy.exc import IntegrityError
from werkzeug.exceptions import Unauthorized, BadRequest
from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    def post(self):
        if not request.is_json:
            return {'error': 'Content-Type must be application/json'}, 415
            
        data = request.get_json()
        
        try:
            user = User(
                username=data['username'],
                image_url=data['image_url'],
                bio=data['bio']
            )
            user.password_hash = data['password']
            
            db.session.add(user)
            db.session.commit()
            
            session['user_id'] = user.id
            return user.to_dict(rules=('-recipes',)), 201
            
        except IntegrityError:
            return {'error': 'Username already exists'}, 422
        except ValueError as e:
            return {'error': str(e)}, 422
        except KeyError as e:
            return {'error': f'Missing required field: {str(e)}'}, 422

class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')
        if not user_id:
            raise Unauthorized('Unauthorized')
            
        user = db.session.get(User, user_id)
        if not user:
            raise Unauthorized('Unauthorized')
            
        return user.to_dict(rules=('-recipes',)), 200

class Login(Resource):
    def post(self):
        if not request.is_json:
            return {'error': 'Content-Type must be application/json'}, 415
            
        data = request.get_json()
        if not data or 'username' not in data or 'password' not in data:
            return {'error': 'Username and password required'}, 400
            
        user = User.query.filter_by(username=data['username']).first()
        
        if user and user.authenticate(data['password']):
            session['user_id'] = user.id
            return user.to_dict(rules=('-recipes',)), 200
            
        return {'error': 'Invalid username or password'}, 401

class Logout(Resource):
    def delete(self):
        if 'user_id' not in session or session['user_id'] is None:
            return {'error': 'Unauthorized'}, 401
            
        session.pop('user_id', None)
        return {}, 204

class RecipeIndex(Resource):
    def get(self):
        user_id = session.get('user_id')
        if not user_id:
            raise Unauthorized('Unauthorized')
            
        recipes = Recipe.query.filter_by(user_id=user_id).all()
        return [recipe.to_dict() for recipe in recipes], 200

    def post(self):
        if not request.is_json:
            return {'error': 'Content-Type must be application/json'}, 415
            
        user_id = session.get('user_id')
        if not user_id:
            raise Unauthorized('Unauthorized')
            
        data = request.get_json()
        try:
            recipe = Recipe(
                title=data['title'],
                instructions=data['instructions'],
                minutes_to_complete=data['minutes_to_complete'],
                user_id=user_id
            )
            
            db.session.add(recipe)
            db.session.commit()
            
            return recipe.to_dict(), 201
            
        except ValueError as e:
            return {'error': str(e)}, 422
        except KeyError as e:
            return {'error': f'Missing required field: {str(e)}'}, 422

# Register all resources
api.add_resource(Signup, '/signup')
api.add_resource(CheckSession, '/check_session')
api.add_resource(Login, '/login')
api.add_resource(Logout, '/logout')
api.add_resource(RecipeIndex, '/recipes')

# Add a root endpoint
@app.route('/')
def home():
    return {'message': 'Welcome to the Recipe API'}, 200

if __name__ == '__main__':
    # Ensure the app has a secret key for sessions
    app.secret_key = 'your_secret_key'  # Replace with a secure, random string
    app.run(debug=True)