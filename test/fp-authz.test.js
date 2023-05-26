'use strict'

const { test } = require('tap')
const build = require('./build.js')
const authzPlugin = require('..')

test('Should reject for missing opts.secret', async (t) => {
  t.plan(1)

  const app = await build(t)

  t.rejects(
    app.register(authzPlugin, {
      roles: {
        admin: 'ROLE_ADMIN'
      }
    }),
    Error('provide a valid @fastify/jwt configuration for JWT token verification'))
})

test('Should authorize with one role', async (t) => {
  t.plan(2)

  const app = await build(t)

  await app.register(authzPlugin, {
    roles: {
      admin: 'ROLE_ADMIN'
    },
    secret: 'bazinga'
  })

  const { roles, authorize } = app

  const token = app.jwt.sign({
    id: 1,
    sub: 'frank.zappa',
    auth: 'ROLE_ADMIN'
  })

  app.get('/protected', {
    onRequest: authorize(roles.admin)
  }, async () => {
    return 'protected resource'
  })

  const response = await app.inject({
    method: 'GET',
    path: '/protected',
    headers: { authorization: `Bearer ${token}` }
  })
  t.equal(response.statusCode, 200)
  t.equal(response.body, 'protected resource')
})

test('Should authorize with multiple role', async (t) => {
  t.plan(4)

  const app = await build(t)

  await app.register(authzPlugin, {
    roles: {
      admin: 'ROLE_ADMIN',
      user: 'ROLE_USER'
    },
    secret: 'bazinga'
  })

  const { roles, authorize } = app

  const adminToken = app.jwt.sign({ id: 1, sub: 'frank.zappa', auth: 'ROLE_ADMIN' })
  const userToken = app.jwt.sign({ id: 2, sub: 'warren.cuccurullo', auth: 'ROLE_USER' })

  app.get('/protected', {
    onRequest: authorize([roles.admin, roles.user])
  }, async () => {
    return 'protected resource'
  })

  const responseForAdmin = await app.inject({
    method: 'GET',
    path: '/protected',
    headers: { authorization: `Bearer ${adminToken}` }
  })
  const responseForUser = await app.inject({
    method: 'GET',
    path: '/protected',
    headers: { authorization: `Bearer ${userToken}` }
  })

  t.equal(responseForAdmin.statusCode, 200)
  t.equal(responseForAdmin.body, 'protected resource')
  t.equal(responseForUser.statusCode, 200)
  t.equal(responseForUser.body, 'protected resource')
})

test('Should authorize with any role', async (t) => {
  t.plan(2)

  const app = await build(t)

  await app.register(authzPlugin, {
    roles: {
      admin: 'ROLE_ADMIN'
    },
    secret: 'bazinga'
  })

  const token = app.jwt.sign({ id: 1, sub: 'frank.zappa', auth: 'ROLE_ADMIN' })

  app.get('/protected', {
    onRequest: app.authorize()
  }, async () => {
    return 'protected resource'
  })

  const response = await app.inject({
    method: 'GET',
    path: '/protected',
    headers: { authorization: `Bearer ${token}` }
  })
  t.equal(response.statusCode, 200)
  t.equal(response.body, 'protected resource')
})

test('Should reject with "unauthorized" for bad role', async (t) => {
  t.plan(4)

  const app = await build(t)

  await app.register(authzPlugin, {
    roles: {
      admin: 'ROLE_ADMIN'
    },
    secret: 'bazinga'
  })

  const { roles, authorize } = app

  const token = app.jwt.sign({
    id: 1,
    sub: 'frank.zappa',
    auth: 'ROLE_USER'
  })

  app.get('/protected', {
    onRequest: authorize(roles.admin)
  }, async () => {
    return 'protected resource'
  })

  const response = await app.inject({
    method: 'GET',
    path: '/protected',
    headers: { authorization: `Bearer ${token}` }
  })

  const responseBody = response.json()
  t.equal(response.statusCode, 403)
  t.equal(responseBody.statusCode, 403)
  t.equal(responseBody.error, 'Forbidden')
  t.equal(responseBody.message, 'Unauthorized')
})

test('Should not register plugin for malformed roles in authorize()', async (t) => {
  t.plan(2)

  const app = await build(t)

  await app.register(authzPlugin, {
    roles: {
      admin: 'ROLE_ADMIN'
    },
    secret: 'bazinga'
  })

  let errMessage = ''
  try {
    app.authorize({ foo: 'bar' })
  } catch (err) {
    errMessage = err.message
  }
  t.equal(errMessage, 'authorize: role must be a string or an array of string')

  let errMessage2 = ''
  try {
    app.authorize([app.roles.admin, 1])
  } catch (err) {
    errMessage = err.message
    errMessage2 = err.message
  }
  t.equal(errMessage2, 'authorize: role must be a string or an array of string')
})
