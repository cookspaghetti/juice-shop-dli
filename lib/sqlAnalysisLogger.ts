/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import config from 'config'
import logger from './logger'
import { type SqlAnalysisConfig } from './config.types'

interface SqlLogEvent {
  timestamp: string
  sqlText: string
  duration?: number
  dialect: string
  environment: string
}

class SqlAnalysisTransport {
  private queue: SqlLogEvent[] = []
  private isEnabled: boolean = false
  private apiUrl: string | null = null
  private maxQueueSize: number = 1000
  private logTimeoutMs: number = 3000
  private authToken: string | null = null
  private isSending: boolean = false

  constructor () {
    this.initialize()
  }

  private initialize (): void {
    try {
      const sqlConfig = config.get<SqlAnalysisConfig>('services.sqlAnalysis')
      this.isEnabled = sqlConfig.enabled
      this.maxQueueSize = sqlConfig.maxQueueSize || 1000
      this.logTimeoutMs = sqlConfig.logTimeoutMs || 3000

      // Allow override via environment variable for testing/deployment flexibility
      this.apiUrl = process.env.SQL_ANALYSIS_API_URL || (sqlConfig.apiUrl ?? null)

      if (this.isEnabled && !this.apiUrl) {
        logger.warn('SQL Analysis is enabled but SQL_ANALYSIS_API_URL is not configured. SQL logging will be disabled.')
        this.isEnabled = false
      }

      this.authToken = process.env.SQL_ANALYSIS_AUTH_TOKEN || null
      if (this.isEnabled && !this.authToken) {
        logger.warn('SQL Analysis is enabled but SQL_ANALYSIS_AUTH_TOKEN environment variable is not set. SQL logging will operate without authentication.')
      }
    } catch (err) {
      logger.warn(`Failed to initialize SQL Analysis: ${(err as Error).message}`)
      this.isEnabled = false
    }
  }

  public log (sqlText: string, duration?: number): void {
    if (!this.isEnabled || !this.apiUrl) {
      return
    }

    const event: SqlLogEvent = {
      timestamp: new Date().toISOString(),
      sqlText,
      duration,
      dialect: 'sqlite',
      environment: process.env.NODE_ENV || 'default'
    }

    if (this.queue.length >= this.maxQueueSize) {
      this.queue.shift()
    }
    this.queue.push(event)

    this.drainQueue()
  }

  private drainQueue (): void {
    if (this.isSending || this.queue.length === 0 || !this.apiUrl) {
      return
    }

    this.isSending = true
    const event = this.queue.shift()

    if (!event) {
      this.isSending = false
      return
    }

    fetch(this.apiUrl, {
      method: 'POST',
      headers: this.buildHeaders(),
      body: JSON.stringify(event),
      signal: AbortSignal.timeout(this.logTimeoutMs)
    }).then(response => {
      if (!response.ok) {
        logger.warn(`SQL Analysis API returned status ${response.status} when logging query`)
      }
    }).catch((err: Error) => {
      if (err.name === 'AbortError') {
        logger.warn(`SQL Analysis API request timed out after ${this.logTimeoutMs}ms`)
      } else {
        logger.warn(`Failed to send SQL log to analysis API: ${err.message}`)
      }
    }).finally(() => {
      this.isSending = false
      if (this.queue.length > 0) {
        this.drainQueue()
      }
    })
  }

  private buildHeaders (): Record<string, string> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json'
    }

    if (this.authToken) {
      headers.Authorization = `Bearer ${this.authToken}`
    }

    return headers
  }

  public isOperational (): boolean {
    return this.isEnabled && this.apiUrl !== null
  }

  // Reinitialize state - primarily for testing
  public reinitialize (): void {
    this.queue = []
    this.isSending = false
    this.initialize()
  }

  // Test-only helper to flush queue
  public async flush (): Promise<void> {
    while (this.queue.length > 0 || this.isSending) {
      await new Promise(resolve => setTimeout(resolve, 50))
    }
  }
}

export const sqlAnalysisLogger = new SqlAnalysisTransport()
