/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import * as sqlAnalysis from '../../lib/sqlAnalysisLogger'
import { type AddressInfo } from 'node:net'
import http from 'node:http'
import chai from 'chai'
const expect = chai.expect

describe('SQL Analysis Logger', () => {
  afterEach(() => {
    delete process.env.SQL_ANALYSIS_API_URL
    delete process.env.SQL_ANALYSIS_AUTH_TOKEN
    sqlAnalysis.sqlAnalysisLogger.reinitialize()
  })

  describe('sqlAnalysisLogger', () => {
    it('ignores SQL logs when feature is disabled', async () => {
      let requestReceived = false

      const server = http.createServer((req, res) => {
        requestReceived = true
        res.statusCode = 200
        res.end('OK')
      })

      await new Promise<void>((resolve) => server.listen(0, resolve))

      try {
        sqlAnalysis.sqlAnalysisLogger.log('SELECT * FROM users', 50)
        await sqlAnalysis.sqlAnalysisLogger.flush()

        expect(requestReceived).to.be.false
      } finally {
        server.close()
      }
    })

    it('ignores SQL logs when API URL is not configured', async () => {
      let requestReceived = false

      const server = http.createServer((req, res) => {
        requestReceived = true
        res.statusCode = 200
        res.end('OK')
      })

      await new Promise<void>((resolve) => server.listen(0, resolve))

      try {
        // Enable feature but don't provide URL
        process.env.SQL_ANALYSIS_API_URL = ''
        sqlAnalysis.sqlAnalysisLogger.reinitialize()

        sqlAnalysis.sqlAnalysisLogger.log('SELECT * FROM users', 50)
        await sqlAnalysis.sqlAnalysisLogger.flush()

        expect(requestReceived).to.be.false
      } finally {
        server.close()
      }
    })

    it('sends SQL query to configured API endpoint', async () => {
      let receivedPayload: string = ''

      const server = http.createServer((req, res) => {
        let data = ''
        req.on('data', (chunk) => {
          data += chunk
        })
        req.on('end', () => {
          receivedPayload = data
          res.statusCode = 200
          res.end('OK')
        })
      })

      await new Promise<void>((resolve) => server.listen(0, resolve))
      const port = (server.address() as AddressInfo)?.port
      const url = `http://localhost:${port}`

      try {
        process.env.SQL_ANALYSIS_API_URL = url
        sqlAnalysis.sqlAnalysisLogger.reinitialize()

        sqlAnalysis.sqlAnalysisLogger.log('SELECT * FROM users WHERE id = 1', 123)
        await sqlAnalysis.sqlAnalysisLogger.flush()

        const payload = JSON.parse(receivedPayload)
        expect(payload).to.have.property('sqlText')
        expect(payload.sqlText).to.equal('SELECT * FROM users WHERE id = 1')
        expect(payload).to.have.property('duration')
        expect(payload.duration).to.equal(123)
        expect(payload).to.have.property('timestamp')
        expect(payload).to.have.property('dialect')
        expect(payload.dialect).to.equal('sqlite')
        expect(payload).to.have.property('environment')
      } finally {
        server.close()
      }
    })

    it('includes Authorization header when auth token is provided', async () => {
      let authHeader = ''

      const server = http.createServer((req, res) => {
        authHeader = req.headers.authorization || ''
        res.statusCode = 200
        res.end('OK')
      })

      await new Promise<void>((resolve) => server.listen(0, resolve))
      const port = (server.address() as AddressInfo)?.port
      const url = `http://localhost:${port}`

      try {
        process.env.SQL_ANALYSIS_API_URL = url
        process.env.SQL_ANALYSIS_AUTH_TOKEN = 'test-token-123'
        sqlAnalysis.sqlAnalysisLogger.reinitialize()

        sqlAnalysis.sqlAnalysisLogger.log('SELECT * FROM products', 50)
        await sqlAnalysis.sqlAnalysisLogger.flush()

        expect(authHeader).to.include('Bearer')
        expect(authHeader).to.include('test-token-123')
      } finally {
        server.close()
      }
    })

    it('handles API errors gracefully without throwing', async () => {
      const server = http.createServer((req, res) => {
        res.statusCode = 500
        res.end('Internal Server Error')
      })

      await new Promise<void>((resolve) => server.listen(0, resolve))
      const port = (server.address() as AddressInfo)?.port
      const url = `http://localhost:${port}`

      try {
        process.env.SQL_ANALYSIS_API_URL = url
        sqlAnalysis.sqlAnalysisLogger.reinitialize()

        sqlAnalysis.sqlAnalysisLogger.log('SELECT * FROM users', 50)
        await sqlAnalysis.sqlAnalysisLogger.flush()
        // Should not throw
      } finally {
        server.close()
      }
    })

    it('sends Content-Type header as application/json', async () => {
      let contentType = ''

      const server = http.createServer((req, res) => {
        contentType = req.headers['content-type'] || ''
        res.statusCode = 200
        res.end('OK')
      })

      await new Promise<void>((resolve) => server.listen(0, resolve))
      const port = (server.address() as AddressInfo)?.port
      const url = `http://localhost:${port}`

      try {
        process.env.SQL_ANALYSIS_API_URL = url
        sqlAnalysis.sqlAnalysisLogger.reinitialize()

        sqlAnalysis.sqlAnalysisLogger.log('SELECT 1', 1)
        await sqlAnalysis.sqlAnalysisLogger.flush()

        expect(contentType).to.equal('application/json')
      } finally {
        server.close()
      }
    })

    it('processes multiple queries in sequence', async () => {
      const receivedPayloads: string[] = []

      const server = http.createServer((req, res) => {
        let data = ''
        req.on('data', (chunk) => {
          data += chunk
        })
        req.on('end', () => {
          receivedPayloads.push(data)
          res.statusCode = 200
          res.end('OK')
        })
      })

      await new Promise<void>((resolve) => server.listen(0, resolve))
      const port = (server.address() as AddressInfo)?.port
      const url = `http://localhost:${port}`

      try {
        process.env.SQL_ANALYSIS_API_URL = url
        sqlAnalysis.sqlAnalysisLogger.reinitialize()

        sqlAnalysis.sqlAnalysisLogger.log('SELECT * FROM users', 10)
        sqlAnalysis.sqlAnalysisLogger.log('SELECT * FROM products', 20)
        sqlAnalysis.sqlAnalysisLogger.log('SELECT * FROM orders', 30)
        await sqlAnalysis.sqlAnalysisLogger.flush()

        expect(receivedPayloads.length).to.equal(3)
        const payloads = receivedPayloads.map(p => JSON.parse(p))
        expect(payloads[0].sqlText).to.equal('SELECT * FROM users')
        expect(payloads[1].sqlText).to.equal('SELECT * FROM products')
        expect(payloads[2].sqlText).to.equal('SELECT * FROM orders')
      } finally {
        server.close()
      }
    })
  })
})
