/**
 * Copyright (c) 2023 IT Resources S.r.l.
 * Code licensed under the MIT license.
 * See license in LICENSE file here in the project or at
 * https://github.com/itross/fp-authz/blob/main/LICENSE
 *
 * @author Luca Stasio <joshuagame@gmail.com>
 */

const fp = require('fastify-plugin')
const jwt = require('@fastify/jwt')
const createError = require('http-errors')

async function authzPlugin (fastify, opts) {
  if (!opts.roles || typeof opts.roles !== 'object' || Object.keys(opts.roles).length === 0) {
    throw new Error('provide a correct "roles" object.')
  }

  const { roles, ...jwtConfig } = opts

  if (!jwtConfig || Object.keys(jwtConfig).length === 0) {
    throw new Error('provide a valid @fastify/jwt configuration for JWT token verification.')
  }

  const _roles = Object.freeze({ ...roles })
  const roleNames = new Map(Object.entries(_roles).map(([k, v]) => [v, k]))
  const roleName = (roleValue) => roleNames.get(roleValue)

  fastify.decorate('roles', _roles)
  fastify.decorate('roleNames', roleNames)
  fastify.decorate('roleName', roleName)
  Object.entries(_roles).forEach(([k, v]) => {
    fastify.decorate(`is${k.charAt(0).toUpperCase() + k.slice(1)}`,
      (roleValue) => roleValue === v)
  })

  await fastify.register(jwt, jwtConfig)

  // authorize verifying Authorization request.headers and than roles
  // if no role is passsed, than authorize on all
  fastify.decorate('authorize', role => {
    const rolesToCheck = []
    if (role) {
      if (typeof role === 'string') {
        rolesToCheck.push(role)
      } else if (Array.isArray(role)) {
        role.forEach(r => {
          if (typeof r !== 'string') {
            throw new Error('authorize: role must be a string or an array of string')
          }
        })
        rolesToCheck.push(...role)
      } else {
        throw new Error('authorize: role must be a string or an array of string')
      }
    }

    // if no role is passed, user role from jwt claim must be one of the configured ones.
    role = role && role.length > 0 ? role : roles

    return async function (request) {
      try {
        await request.jwtVerify()
        if (rolesToCheck.length > 0 && !rolesToCheck.includes(request.user.auth)) {
          throw new createError.Forbidden('unauthorized')
        }
      } catch (err) {
        throw new createError.Forbidden('unauthorized')
      }
    }
  })
}

module.exports = fp(authzPlugin, {
  fastify: '>=4.0.0',
  name: '@itross/fp-authz'
})
