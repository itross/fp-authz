'use strict'

const { test } = require('tap')
const build = require('./build.js')
const authzPlugin = require('..')

test('Should rejects for missing opts.roles object', async (t) => {
  t.plan(2)

  const app = await build(t)

  t.rejects(
    app.register(authzPlugin, {}),
    Error('specify a correct "roles" object.'))
  t.notOk(app.roles)
})

test('Should rejects for malformed opts.roles object', async (t) => {
  t.plan(2)

  const app = await build(t)

  t.rejects(
    app.register(authzPlugin, {
      roles: {}
    }),
    Error('specify a correct "roles" object.'))
  t.notOk(app.roles)
})

test('Should decorate roles enum and get role values', async (t) => {
  t.plan(5)

  const app = await build(t)

  await app.register(authzPlugin, {
    roles: {
      admin: 'ROLE_ADMIN',
      user: 'ROLE_USER'
    }
  })
  t.ok(app.roles)
  t.ok(app.roleNames)
  t.ok(app.roleName)
  t.equal(app.roles.admin, 'ROLE_ADMIN', 'role "admin" value is not "ROLE_ADMIN" as expected')
  t.equal(app.roles.user, 'ROLE_USER', 'role "user" value is not "ROLE_USER" as expected')
})

test('Should get role name from role value', async (t) => {
  t.plan(3)

  const app = await build(t)

  await app.register(authzPlugin, {
    roles: {
      admin: 'ROLE_ADMIN',
      user: 'ROLE_USER'
    }
  })
  t.ok(app.roles)
  t.equal(app.roleName('ROLE_ADMIN'), 'admin', 'role name for value "ROLE_ADMIN" should be "admin')
  t.equal(app.roleName('ROLE_USER'), 'user', 'role name for value "ROLE_USER" should be "user')
})

test('Should decorate is<role>() functions', async (t) => {
  t.plan(3)

  const app = await build(t)

  await app.register(authzPlugin, {
    roles: {
      admin: 'ROLE_ADMIN',
      user: 'ROLE_USER'
    }
  })
  t.ok(app.roles)
  t.ok(app.isAdmin)
  t.ok(app.isUser)
})

test('Should check if a role value is a role', async (t) => {
  t.plan(4)

  const app = await build(t)

  await app.register(authzPlugin, {
    roles: {
      admin: 'ROLE_ADMIN',
      user: 'ROLE_USER'
    }
  })
  t.ok(app.roles)
  t.equal(app.isAdmin('ROLE_ADMIN'), true)
  t.equal(app.isUser('ROLE_USER'), true)
  t.equal(app.isUser('ROLE_FAKE'), false)
})
