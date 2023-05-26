function test (opts) {
  const { roles, ...jwt } = opts
  const _roles = Object.freeze({ ...roles })
  console.log(`roles: ${JSON.stringify(roles, null, 2)}`)
  console.log(`jwt: ${JSON.stringify(jwt, null, 2)}`)
  _roles.god = 'GOD_MOD'
  console.log(`_roles: ${JSON.stringify(_roles, null, 2)}`)
}

const opts = {
  roles: {
    admin: 'ROLE_ADMIN'
  },
  secret: 'supersecret',
  decode: {
    complete: true
  }
}

console.log(`opts before test: ${JSON.stringify(opts, null, 2)}`)

test(opts)

console.log(`opts after test: ${JSON.stringify(opts, null, 2)}`)
