import cors from 'cors';
import express, { NextFunction, Request, Response } from 'express';
import jwt from 'jsonwebtoken'
import decode from 'jwt-decode'
import { generateJwtAndRefreshToken } from './auth';
import { auth } from './config';

import { checkRefreshTokenIsValid, users, seedUserStore, invalidateRefreshToken } from './database';
import { CreateSessionDTO, DecodedToken, UserData } from './types';

const app = express();

app.use(express.json());
app.use(cors())

seedUserStore();

function checkAuthMiddleware(request: Request, response: Response, next: NextFunction) {
  const { authorization } = request.headers;

  if (!authorization) {
    return response
      .status(401)
      .json({ error: true, code: 'token.invalid', message: 'Token not present.' })
  }

  const [, token] = authorization?.split(' ');

  if (!token) {
    return response 
      .status(401)
      .json({ error: true, code: 'token.invalid', message: 'Token not present.' })
  }

  try {
    const decoded = jwt.verify(token as string, auth.secret) as DecodedToken;

    request.user = decoded.sub;

    return next();
  } catch (err) {

    return response 
      .status(401)
      .json({  error: true, code: 'token.expired', message: 'Token invalid.' })
  }
}

function addUserInformationToRequest(request: Request, response: Response, next: NextFunction) {
  const { authorization } = request.headers;

  if (!authorization) {
    return response
      .status(401)
      .json({ error: true, code: 'token.invalid', message: 'Token not present.' })
  }

  const [, token] = authorization?.split(' ');

  if (!token) {
    return response 
      .status(401)
      .json({ error: true, code: 'token.invalid', message: 'Token not present.' })
  }

  try {
    const decoded = decode(token as string) as DecodedToken;

    request.user = decoded.sub;

    return next();
  } catch (err) {
    return response 
      .status(401)
      .json({ error: true, code: 'token.invalid', message: 'Invalid token format.' })
  }
}

app.post('/sessions', (request, response) => {
  const { email, password } = request.body as CreateSessionDTO;

  const user = users.get(email);

  if (!user || password !== user.password) {
    return response
      .status(401)
      .json({ 
        error: true, 
        message: 'E-mail or password incorrect.'
      });
  }

  const { token, refreshToken } = generateJwtAndRefreshToken(email, {
    permissions: user.permissions,
    roles: user.roles,
  })

  return response.json({
    token,
    refreshToken,
    permissions: user.permissions,
    roles: user.roles,
    name: user.name,
    createdAt: user.createdAt
  });
});

app.post('/refresh', addUserInformationToRequest, (request, response) => {
  const email = request.user;
  const { refreshToken } = request.body;

  const user = users.get(email);

  if (!user) {
    return response
      .status(401)
      .json({ 
        error: true, 
        message: 'User not found.'
      });
  }

  if (!refreshToken) {
    return response
      .status(401)
      .json({ error: true, message: 'Refresh token is required.' });
  }

  const isValidRefreshToken = checkRefreshTokenIsValid(email, refreshToken)

  if (!isValidRefreshToken) {
    return response
      .status(401)
      .json({ error: true, message: 'Refresh token is invalid.' });
  }

  invalidateRefreshToken(email, refreshToken)

  const { token, refreshToken: newRefreshToken } = generateJwtAndRefreshToken(email, {
    permissions: user.permissions,
    roles: user.roles,
  })

  return response.json({
    token,
    refreshToken: newRefreshToken,
    permissions: user.permissions,
    roles: user.roles,
    name: user.name
  });
});

app.get('/me', checkAuthMiddleware, (request, response) => {
  const email = request.user;

  const user = users.get(email);

  if (!user) {
    return response
      .status(400)
      .json({ error: true, message: 'User not found.' });
  }

  return response.json({
    email,
    permissions: user.permissions,
    roles: user.roles,
    name: user.name,
    createdAt: user.createdAt
  })
});

//users pagination
interface User extends UserData {
  email: string;
}

function listUsers(): User[] {
  const usersList: User[] = [];

  users.forEach((user, key) => {
    usersList.push({
      email: key,
      name: user.name,
      permissions: user.permissions,
      roles: user.roles,
      createdAt: user.createdAt
    });
  })

  return usersList;
}

app.get('/users', checkAuthMiddleware, (request, response) => {
  const { pages = 1, per_page = 10 } = request.query;

  const totalUsers: User[] = listUsers();

  const pageStart = (Number(pages) - 1) * Number(per_page);
  const pageEnd = pageStart + Number(per_page);

  const usersList = totalUsers.slice(pageStart, pageEnd);

  response.header('x-total-count', String(totalUsers.length));

  return response
    .status(200)
    .json({ users: usersList, total: usersList.length })
});

//create user
app.post('/users', checkAuthMiddleware, (request, response) => {
  const userEmail = request.user;

  const user = users.get(userEmail);

  if (!user) {
    return response
      .status(400)
      .json({ error: true, message: 'User not found.' });
  };

  const userHasPermission = user.permissions.includes('users.create');

  if (!userHasPermission) {
    return response.status(401).json({
      error: true,
      message: `User does not have permission to create other users`,
    });
  }

  const { email, name, password } = request.body;

  if (!email || !name || !password) {
    return response.status(400).json({
      error: true,
      message: 'email, name and password required to create a new user'
    })
  }

  const userExists = users.get(email);

  if (userExists) {
    return response.status(400).json({
      error: true,
      message: 'User already exists'
    });
  }

  users.set(email, {
    name,
    password,
    createdAt: new Date(),
    permissions: ['users.list', 'metrics.list'],
    roles: ['editor']
  });

  const createdUser = users.get(email);

  return response.json({
    email,
    name: createdUser?.name,
    permissions: createdUser?.permissions,
    roles: createdUser?.roles,
    createdAt: createdUser?.createdAt
  })
});

app.listen(3333);