/**
 * Copyright (c) 2023 IT Resources S.r.l.
 * Code licensed under the MIT license.
 * See license in LICENSE file here in the project or at
 * https://github.com/itross/fp-authz/blob/main/LICENSE
 *
 * @author Luca Stasio <joshuagame@gmail.com>
 */

const fp = require('fastify-plugin')

async function authzPlugin (fastify, opts) {
  if (!opts.roles || typeof opts.roles !== 'object' || Object.keys(opts.roles).length === 0) {
    throw new Error('specify a correct "roles" object.')
  }

  const roles = Object.freeze({ ...opts.roles })

  const roleNames = new Map(Object.entries(roles).map(([k, v]) => [v, k]))

  fastify.decorate('roles', roles)
  fastify.decorate('roleNames', roleNames)
  fastify.decorate('roleName', (roleValue) => roleNames.get(roleValue))
}

module.exports = fp(authzPlugin, {
  fastify: '>=4.0.0',
  name: '@itross/fp-authz'
})
